import asyncio
import hmac
import ipaddress
import secrets
import statistics
import time
from contextlib import suppress
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import Column, Float, Integer, MetaData, String, Table, delete, insert, select
from sqlalchemy.exc import SQLAlchemyError

from .peer import BLOCK, SERVICE, SIZE, signature

router = APIRouter(prefix="/speed")
metadata = MetaData()
results = Table(
    "speed_results",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("at", Float),
    Column("target", String),
    Column("scope", String),
    Column("latency_ms", Float),
    Column("download_mbps", Float),
    Column("upload_mbps", Float),
    Column("mode", String),
    Column("rounds", Integer),
    Column("download_cv_pct", Float),
    Column("upload_cv_pct", Float),
)


class Target(BaseModel):
    target: str = Field(min_length=1, max_length=256)
    token: SecretStr = Field(min_length=12, max_length=128)
    mode: Literal["quick", "repeated"] = "quick"


def endpoint(value):
    parsed = urlsplit(value if "://" in value else "http://" + value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("请填写受控端点的 HTTP(S) 地址与端口")
    host = parsed.hostname
    if host == "localhost":
        host = "127.0.0.1"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if parsed.scheme != "https":
            raise ValueError("主机名须使用 HTTPS，局域网 HTTP 请填写 IP 地址") from None
        ip = None
    if ip and (ip.is_unspecified or ip.is_multicast or str(ip) == "255.255.255.255"):
        raise ValueError("请选择单个受控测试端点")
    if ip and ip.is_global and parsed.scheme != "https":
        raise ValueError("公网端点须使用 HTTPS")
    port = parsed.port
    if port == 0:
        raise ValueError("端口无效")
    authority = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{authority}" + (f":{port}" if port else "")


class SpeedTest:
    def __init__(self, engine, log):
        self.engine = engine
        self.log = log
        self.task = None
        self.state = {"running": False, "phase": "idle", "progress": 0, "result": None, "error": None}
        metadata.create_all(engine)
        # Add optional measurement metadata without discarding an existing user's history.
        with engine.begin() as db:
            present = {row[1] for row in db.exec_driver_sql("PRAGMA table_info(speed_results)")}
            for name, kind in (
                ("mode", "TEXT"),
                ("rounds", "INTEGER"),
                ("download_cv_pct", "REAL"),
                ("upload_cv_pct", "REAL"),
            ):
                if name not in present:
                    db.exec_driver_sql(f"ALTER TABLE speed_results ADD COLUMN {name} {kind}")

    def start(self, target, key, mode="quick"):
        if self.task and not self.task.done():
            raise HTTPException(409, "已有测速任务正在执行")
        self.state = {"running": True, "phase": "latency", "progress": 0, "result": None, "error": None}
        self.task = asyncio.create_task(self.measure(target, key, mode))

    async def close(self):
        if self.task and not self.task.done():
            self.task.cancel()
            with suppress(asyncio.CancelledError):
                await self.task

    async def exchange(
        self, client, key, path, size, method="GET", progress_span=(20, 58)
    ):
        stamp, nonce = str(int(time.time())), secrets.token_hex(16)
        start_progress, end_progress = progress_span
        challenge = f"{method} {path} {stamp} {nonce}"
        headers = {
            "X-NetScope-Time": stamp,
            "X-NetScope-Nonce": nonce,
            "X-NetScope-Auth": signature(key, challenge),
        }

        async def upload():
            for i in range(SIZE // len(BLOCK)):
                yield BLOCK
                self.state["progress"] = start_progress + (
                    (i + 1) * (end_progress - start_progress) // (SIZE // len(BLOCK))
                )

        if method == "POST":
            headers["Content-Length"] = str(SIZE)
        start = time.perf_counter()
        async with client.stream(
            method, path, headers=headers, content=upload() if method == "POST" else None
        ) as response:
            if response.status_code == 401:
                raise ValueError("配对密钥不匹配或两端时钟偏差超过 60 秒")
            response.raise_for_status()
            stream = response.extensions["network_stream"]
            address = stream.get_extra_info("server_addr")
            if path == "/v1/ping" and not address:
                raise ValueError("无法确认测速对端地址")
            if int(response.headers.get("Content-Length", "-1")) != size:
                raise ValueError("测试端点返回了意外的数据长度")
            received = 0
            small = bytearray()
            async for chunk in response.aiter_raw():
                received += len(chunk)
                if received > size:
                    raise ValueError("测试端点返回的数据超过上限")
                if path == "/v1/download":
                    self.state["progress"] = start_progress + (
                        received * (end_progress - start_progress) // SIZE
                    )
                else:
                    small.extend(chunk)
            elapsed = time.perf_counter() - start
            if received != size:
                raise ValueError("传输未完成")
            if path == "/v1/ping":
                proof = response.headers.get("X-NetScope-Proof", "").encode()
                if small != SERVICE.encode() or not hmac.compare_digest(
                    proof, signature(key, f"reply {challenge}").encode()
                ):
                    raise ValueError("对端未通过 NetScope 配对验证")
                peer = ipaddress.ip_address(address[0])
                return elapsed, peer
            if method == "POST" and small != str(SIZE).encode():
                raise ValueError("对端未确认上传字节数")
            return elapsed, None

    async def measure(self, target, key, mode="quick"):
        rounds = 8 if mode == "repeated" else 1
        try:
            async with (
                asyncio.timeout(110 if rounds > 1 else 45),
                httpx.AsyncClient(
                    base_url=target,
                    timeout=30 if rounds > 1 else 12,
                    trust_env=False,
                    follow_redirects=False,
                    headers={"Accept-Encoding": "identity"},
                ) as client,
            ):
                samples = []
                for i in range(5):
                    seconds, peer = await self.exchange(client, key, "/v1/ping", size=len(SERVICE))
                    samples.append(seconds * 1000)
                    self.state["progress"] = (i + 1) * 4
                self.state["phase"] = "download"
                down_times = []
                for index in range(rounds):
                    start = 20 + index * 39 // rounds
                    end = 20 + (index + 1) * 39 // rounds
                    duration, _ = await self.exchange(
                        client, key, "/v1/download", size=SIZE, progress_span=(start, end)
                    )
                    down_times.append(duration)
                self.state.update(phase="upload", progress=60)
                up_times = []
                for index in range(rounds):
                    start = 60 + index * 39 // rounds
                    end = 60 + (index + 1) * 39 // rounds
                    duration, _ = await self.exchange(
                        client, key, "/v1/upload", method="POST", size=len(str(SIZE)),
                        progress_span=(start, end)
                    )
                    up_times.append(duration)

            def variation(durations):
                if len(durations) == 1:
                    return None
                rates = [SIZE * 8 / duration / 1e6 for duration in durations]
                return 100 * statistics.pstdev(rates) / statistics.mean(rates)

            row = {
                "at": time.time(),
                "target": target,
                "scope": "loopback" if peer.is_loopback else "internet" if peer.is_global else "lan",
                "latency_ms": statistics.median(samples),
                "download_mbps": SIZE * rounds * 8 / sum(down_times) / 1e6,
                "upload_mbps": SIZE * rounds * 8 / sum(up_times) / 1e6,
                "mode": mode,
                "rounds": rounds,
                "download_cv_pct": variation(down_times),
                "upload_cv_pct": variation(up_times),
            }
            with self.engine.begin() as db:
                db.execute(insert(results).values(**row))
                db.execute(
                    delete(results).where(
                        results.c.id.not_in(
                            select(results.c.id).order_by(results.c.id.desc()).limit(500)
                        )
                    )
                )
            self.state.update(phase="complete", progress=100, result=row)
            self.log("speed.complete", "已完成配对端点双向测速")
        except SQLAlchemyError:
            self.state.update(phase="error", error="写入测速记录失败，请检查数据库和可用磁盘空间")
        except (httpx.HTTPError, OSError, TimeoutError, ValueError) as exc:
            note = (
                str(exc)
                if isinstance(exc, ValueError)
                else "连接或传输失败，请检查端点、证书、端口和服务状态"
            )
            self.state.update(phase="error", error=note)
            with suppress(SQLAlchemyError):
                self.log("speed.error", note)
        finally:
            self.state["running"] = False


@router.post("", status_code=202)
async def start(request: Request, body: Target):
    try:
        target = endpoint(body.target.strip())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    test = request.app.state.speed
    test.start(target, body.token.get_secret_value(), body.mode)
    return test.state.copy()


@router.get("")
async def state(request: Request):
    return request.app.state.speed.state


@router.get("/history")
def history(
    request: Request,
    start: float | None = Query(None, ge=0, allow_inf_nan=False),
    end: float | None = Query(None, ge=0, allow_inf_nan=False),
):
    if start is not None and end is not None and start > end:
        raise HTTPException(422, "开始时间须早于结束时间")
    query = select(results)
    if start is not None:
        query = query.where(results.c.at >= start)
    if end is not None:
        query = query.where(results.c.at <= end)
    limit = 100 if start is None and end is None else 500
    with request.app.state.db.connect() as db:
        return [
            dict(row) for row in db.execute(query.order_by(results.c.id.desc()).limit(limit)).mappings()
        ]
