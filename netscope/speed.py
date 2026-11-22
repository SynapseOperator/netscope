import asyncio
import hmac
import ipaddress
import secrets
import statistics
import time
from contextlib import suppress
from itertools import pairwise
from typing import Literal
from urllib.parse import urlsplit

import httpx
import psutil
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    delete,
    insert,
    select,
)
from sqlalchemy.exc import SQLAlchemyError

from .peer import BLOCK, MAX_STREAM_BYTES, SERVICE, SIZE, signature

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
    Column("started_at", Float),
    Column("ended_at", Float),
    Column("interface", String),
    Column("duration_s", Integer),
    Column("download_bytes", Integer),
    Column("upload_bytes", Integer),
    Column("download_seconds", Float),
    Column("upload_seconds", Float),
    Column("loaded_latency_ms", Float),
    Column("latency_delta_ms", Float),
    Column("idle_jitter_ms", Float),
    Column("loaded_jitter_ms", Float),
    Column("loaded_samples", Integer),
    Column("segments", JSON),
    Column("limit_reached", Boolean),
)


class Target(BaseModel):
    target: str = Field(min_length=1, max_length=256)
    token: SecretStr = Field(min_length=12, max_length=128)
    mode: Literal["quick", "repeated", "sustained"] = "quick"
    duration_s: Literal[5, 10] = 5


def signed_headers(key, method, path):
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    challenge = f"{method} {path} {stamp} {nonce}"
    return challenge, {
        "X-NetScope-Time": stamp,
        "X-NetScope-Nonce": nonce,
        "X-NetScope-Auth": signature(key, challenge),
    }


def through_interface(local_addresses):
    if not local_addresses or None in local_addresses:
        return None
    try:
        interfaces = psutil.net_if_addrs()
    except (psutil.Error, OSError):
        return None
    # A transfer spanning multiple routes, or an address on several interfaces, is ambiguous.
    names = set()
    for address in local_addresses:
        matches = [
            name
            for name, addrs in interfaces.items()
            if any(a.address.split("%")[0] == address.split("%")[0] for a in addrs)
        ]
        if len(matches) != 1:
            return None
        names.add(matches[0])
    return next(iter(names)) if len(names) == 1 else None


def variation(rates):
    if len(rates) < 2 or not statistics.mean(rates):
        return None
    return 100 * statistics.pstdev(rates) / statistics.mean(rates)


def jitter(groups):
    differences = [abs(b - a) for group in groups for a, b in pairwise(group)]
    return statistics.mean(differences) if differences else None


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
        self.state = {
            "running": False,
            "phase": "idle",
            "progress": 0,
            "result": None,
            "error": None,
            "segments": [],
        }
        metadata.create_all(engine)
        # Add optional measurement metadata without discarding an existing user's history.
        with engine.begin() as db:
            present = {row[1] for row in db.exec_driver_sql("PRAGMA table_info(speed_results)")}
            for column in results.columns:
                if column.name not in present:
                    kind = column.type.compile(dialect=engine.dialect)
                    db.exec_driver_sql(f'ALTER TABLE speed_results ADD COLUMN "{column.name}" {kind}')

    def start(self, target, key, mode="quick", duration_s=5):
        if self.task and not self.task.done():
            raise HTTPException(409, "已有测速任务正在执行")
        self.state = {
            "running": True,
            "phase": "latency",
            "progress": 0,
            "result": None,
            "error": None,
            "segments": [],
        }
        self.task = asyncio.create_task(self.measure(target, key, mode, duration_s))

    async def close(self):
        if self.task and not self.task.done():
            self.task.cancel()
            with suppress(asyncio.CancelledError):
                await self.task
            if self.state["running"]:
                # A task cancelled before entering measure has no finally block yet.
                self.state.update(running=False, phase="cancelled")

    async def exchange(self, client, key, path, size, method="GET", progress_span=(20, 58)):
        start_progress, end_progress = progress_span
        challenge, headers = signed_headers(key, method, path)

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
            if path != "/v1/ping":
                local = stream.get_extra_info("client_addr")
                self.data_routes.add(local[0] if local else None)
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

    async def sustained(self, client, key, direction, duration_s):
        method = "GET" if direction == "download" else "POST"
        path = f"/v2/{direction}/{duration_s}"
        _, headers = signed_headers(key, method, path)
        start = time.perf_counter()
        previous = start
        total = previous_bytes = 0
        active = asyncio.Event()
        probes = []
        segments = []
        offset = 20 if direction == "download" else 60

        def sample(now):
            nonlocal previous, previous_bytes
            seconds = now - previous
            amount = total - previous_bytes
            segment = {
                "direction": direction,
                "elapsed_s": now - start,
                "seconds": seconds,
                "bytes": amount,
                "mbps": amount * 8 / seconds / 1e6,
            }
            segments.append(segment)
            self.state["segments"].append(segment)
            previous, previous_bytes = now, total

        def record(amount):
            nonlocal total
            total += amount
            if total > MAX_STREAM_BYTES:
                raise ValueError("持续测速对端返回的数据超过每方向 512 MiB 上限")
            active.set()
            now = time.perf_counter()
            if now - previous >= 1:
                sample(now)
            fraction = max((now - start) / duration_s, total / MAX_STREAM_BYTES)
            self.state["progress"] = offset + min(39, int(39 * fraction))

        async def under_load():
            await active.wait()
            while True:
                before = total
                try:
                    async with asyncio.timeout(2):
                        rtt, _ = await self.exchange(client, key, "/v1/ping", len(SERVICE))
                    # Only accept round trips during which payload made progress.
                    if total > before:
                        probes.append(rtt * 1000)
                except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                    pass  # Missing probes remain missing; throughput still has its own receipt.
                await asyncio.sleep(0.2)

        async def upload():
            deadline = time.perf_counter() + duration_s
            while total < MAX_STREAM_BYTES and time.perf_counter() < deadline:
                yield BLOCK
                record(len(BLOCK))

        listener = asyncio.create_task(under_load())
        try:
            async with client.stream(
                method, path, headers=headers, content=upload() if method == "POST" else None
            ) as response:
                if response.status_code == 404:
                    raise ValueError("对端版本不支持持续测速，请更新 peer.py 或选择快速、重复模式")
                if response.status_code == 401:
                    raise ValueError("对端拒绝配对签名，请检查密钥和两端时钟")
                response.raise_for_status()
                local = response.extensions["network_stream"].get_extra_info("client_addr")
                self.data_routes.add(local[0] if local else None)
                receipt = bytearray()
                async for block in response.aiter_raw():
                    if direction == "download":
                        record(len(block))
                    else:
                        if len(receipt) + len(block) > 16:
                            raise ValueError("对端的上传确认长度无效")
                        receipt.extend(block)
                if direction == "upload" and receipt != str(total).encode():
                    raise ValueError("对端未确认实际上传字节数")
        finally:
            listener.cancel()
            with suppress(asyncio.CancelledError):
                await listener
        end = time.perf_counter()
        if not total:
            raise ValueError("端点未传输测试数据")
        if total < MAX_STREAM_BYTES and end - start < duration_s * 0.95:
            raise ValueError("持续测速提前结束且未达到字节上限")
        sample(end)
        rates = [s["mbps"] for s in segments if s["seconds"] >= 0.25]
        return total, end - start, probes, variation(rates)

    async def measure(self, target, key, mode="quick", duration_s=5):
        rounds = 8 if mode == "repeated" else 1
        started_at = time.time()
        self.data_routes = set()
        self.state["segments"] = []
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
                measured = {}
                loaded_groups = []
                for direction, base in (("download", 20), ("upload", 60)):
                    self.state.update(phase=direction, progress=base)
                    if mode == "sustained":
                        amount, seconds, rtts, cv = await self.sustained(
                            client, key, direction, duration_s
                        )
                        loaded_groups.append(rtts)
                    else:
                        times = []
                        for i in range(rounds):
                            span = (base + i * 39 // rounds, base + (i + 1) * 39 // rounds)
                            duration, _ = await self.exchange(
                                client,
                                key,
                                f"/v1/{direction}",
                                size=SIZE if direction == "download" else len(str(SIZE)),
                                method="GET" if direction == "download" else "POST",
                                progress_span=span,
                            )
                            times.append(duration)
                        amount, seconds = SIZE * rounds, sum(times)
                        cv = variation([SIZE * 8 / d / 1e6 for d in times])
                    measured.update(
                        {
                            direction + "_bytes": amount,
                            direction + "_seconds": seconds,
                            direction + "_mbps": amount * 8 / seconds / 1e6,
                            direction + "_cv_pct": cv,
                        }
                    )
            ended_at = time.time()
            loaded = [r for group in loaded_groups for r in group]
            idle_ms = statistics.median(samples)
            loaded_ms = statistics.median(loaded) if loaded else None
            row = {
                "at": ended_at,
                "started_at": started_at,
                "ended_at": ended_at,
                "interface": through_interface(self.data_routes),
                "target": target,
                "scope": "loopback" if peer.is_loopback else "internet" if peer.is_global else "lan",
                "latency_ms": idle_ms,
                "mode": mode,
                "rounds": rounds,
                "duration_s": duration_s if mode == "sustained" else None,
                "idle_jitter_ms": jitter([samples]),
                "loaded_jitter_ms": jitter(loaded_groups),
                "loaded_latency_ms": loaded_ms,
                "latency_delta_ms": loaded_ms - idle_ms if loaded_ms is not None else None,
                "loaded_samples": len(loaded) if loaded_groups else None,
                "segments": self.state["segments"] if mode == "sustained" else None,
                "limit_reached": any(
                    measured[d + "_bytes"] == MAX_STREAM_BYTES for d in ("download", "upload")
                )
                if mode == "sustained"
                else None,
                **measured,
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
        except asyncio.CancelledError:
            self.state.update(phase="cancelled", result=None, error=None)
            with suppress(SQLAlchemyError):
                self.log("speed.cancel", "已取消主动测速")
            raise
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
    test.start(target, body.token.get_secret_value(), body.mode, body.duration_s)
    return test.state.copy()


@router.get("")
async def state(request: Request):
    return request.app.state.speed.state


@router.post("/cancel")
async def cancel(request: Request):
    test = request.app.state.speed
    if not test.task or test.task.done():
        raise HTTPException(409, "当前没有正在运行的测速")
    await test.close()
    return test.state


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
