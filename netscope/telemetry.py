"""Sample the OS once per second and retain minute totals without packet contents."""

import asyncio
import time
from collections import deque
from dataclasses import dataclass

import psutil
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from .devices import choose_interface, read_interfaces
from .telemetry_store import (
    alerts,
    close_alert,
    logs,
    metadata,
    prune,
    save_buckets,
    settings,
    write_setting,
)


class AlertRule(BaseModel):
    enabled: bool = True
    rx_mbps: float = Field(default=100, gt=0, le=10_000_000, allow_inf_nan=False)
    tx_mbps: float = Field(default=100, gt=0, le=10_000_000, allow_inf_nan=False)
    consecutive: int = Field(default=3, ge=1, le=120)
    recovery_ratio: float = Field(default=0.8, gt=0, lt=1)
    cooldown_s: int = Field(default=30, ge=0, le=3600)


@dataclass
class ThresholdState:
    streak: int = 0
    active: bool = False
    next_allowed: float = 0

    def observe(self, value, threshold, rule, now):
        if value is None:
            self.streak = 0
            return None
        if self.active:
            if value <= threshold * rule.recovery_ratio:
                self.active = False
                self.streak = 0
                self.next_allowed = now + rule.cooldown_s
                return "recover"
            return None
        self.streak = min(self.streak + 1, rule.consecutive) if value > threshold else 0
        if self.streak == rule.consecutive and now >= self.next_allowed:
            self.active = True
            return "trigger"
        return None


def counter_delta(previous, current, elapsed):
    """Skip initial, reset and interrupted intervals. psutil nowrap must be disabled."""
    if previous is None or current is None or not 0 < elapsed <= 3:
        return None
    delta = tuple(b - a for a, b in zip(previous, current, strict=True))
    if min(delta) < 0:
        return None
    return delta


class Monitor:
    def __init__(self, engine):
        self.engine = engine
        metadata.create_all(engine)
        with engine.connect() as db:
            config = dict(db.execute(select(settings)).all())
            active = db.execute(
                select(alerts.c.interface, alerts.c.kind).where(alerts.c.recovered_at.is_(None))
            ).all()
        self.selected = config.get("interface")
        self.rule = AlertRule.model_validate_json(config.get("rule", "{}"))
        self.open_alerts = set(active)
        self.thresholds = {
            key: ThresholdState(active=True) for key in active if key[1] in ("rx_rate", "tx_rate")
        }
        self.interfaces = []
        self.series = {}
        self.previous = {}
        self.previous_time = None
        self.previous_up = {}
        self.error = ""
        self.buckets = {}
        self.last_flush = 0
        self.last_prune = 0
        self.task = None
        self.stopping = asyncio.Event()

    async def start(self):
        self.stopping.clear()
        await self._sample()
        self.log("collector.start", "开始每秒读取系统网卡计数器。")
        self.task = asyncio.create_task(self._run())

    async def stop(self):
        self.stopping.set()
        if self.task:
            await self.task
        self.flush()
        self.log("collector.stop", "采集已停止，已提交末尾时间桶。")

    async def _run(self):
        while not self.stopping.is_set():
            try:
                await asyncio.wait_for(self.stopping.wait(), timeout=1)
            except TimeoutError:
                await self._sample()

    async def _sample(self):
        try:
            interfaces, counters = await asyncio.to_thread(read_interfaces)
        except (psutil.Error, OSError):
            self.error = "读取系统网卡计数器失败，请检查网卡和系统权限。"
            self.previous.clear()
            for state in self.thresholds.values():
                state.streak = 0
            self._incident("", "collector", time.time(), self.error, "检查系统网卡状态和本机服务权限。")
            return
        try:
            self.ingest(interfaces, counters, time.time(), time.monotonic())
        except SQLAlchemyError:
            self.error = "写入本地监测数据库失败，请检查数据目录和可用磁盘空间。"

    def log(self, action, message):
        with self.engine.begin() as db:
            db.execute(logs.insert().values(ts=time.time(), action=action, message=message))

    def _incident(self, name, kind, ts, message, advice):
        if (name, kind) in self.open_alerts:
            return
        with self.engine.begin() as db:
            db.execute(
                alerts.insert().values(
                    ts=ts,
                    interface=name,
                    kind=kind,
                    message=message,
                    advice=advice,
                )
            )
            db.execute(logs.insert().values(ts=ts, action="alert.open", message=message))
        self.open_alerts.add((name, kind))

    def _recover(self, name, kind, ts):
        if (name, kind) not in self.open_alerts:
            return
        with self.engine.begin() as db:
            close_alert(db, name, kind, ts, "recovered")
            db.execute(
                logs.insert().values(
                    ts=ts,
                    action="alert.recover",
                    message=f"{name or '系统采集'} · {kind} 已恢复。",
                )
            )
        self.open_alerts.remove((name, kind))

    def ingest(self, interfaces, counters, now, monotonic):
        elapsed = monotonic - self.previous_time if self.previous_time is not None else 0
        current = {}
        names = {i["name"] for i in interfaces}
        self._recover("", "collector", now)
        if elapsed > 3:
            self._incident(
                "",
                "sample_gap",
                now,
                f"两次采样相隔 {elapsed:.1f} 秒，速率曲线已留空。",
                "检查主机睡眠或本地服务是否繁忙。",
            )
        elif elapsed > 0:
            self._recover("", "sample_gap", now)
        self.error = ""
        if self.selected is None:
            self.selected = choose_interface(interfaces, counters)
        for name in self.previous_up.keys() - names:
            if self.previous_up[name]:
                self._incident(
                    name, "interface", now, f"{name} 已从系统移除。", "检查网线、驱动或 VPN 状态。"
                )
        for name in self.series.keys() - names:
            del self.series[name]
        for key, state in self.thresholds.items():
            if key[0] not in names:
                state.streak = 0

        for item in interfaces:
            name = item["name"]
            up = item["up"]
            if up:
                self._recover(name, "interface", now)
            elif self.previous_up.get(name):
                self._incident(
                    name, "interface", now, f"{name} 已断开。", "检查接口是否禁用、物理链路或无线连接。"
                )
            record = counters.get(name)
            counts = None
            if record is not None:
                counts = (
                    record.bytes_recv,
                    record.bytes_sent,
                    record.packets_recv,
                    record.packets_sent,
                )
            if counts is not None and up:
                current[name] = counts
            delta = counter_delta(self.previous.get(name), current.get(name), elapsed)
            if up and counts is None:
                self._incident(
                    name,
                    "counter",
                    now,
                    f"{name} 的系统计数器不可用。",
                    "检查网卡驱动和系统计数器读取权限。",
                )
            elif up and name in self.previous and 0 < elapsed <= 3 and delta is None:
                self._incident(
                    name,
                    "counter",
                    now,
                    f"{name} 的网卡计数器已重置。",
                    "核对网卡重连或驱动重启记录，等待新的连续读数。",
                )
            elif delta is not None:
                self._recover(name, "counter", now)
            point = dict(
                zip(
                    ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"),
                    counts or (None, None, None, None),
                    strict=True,
                )
            )
            rx = delta[0] * 8 / elapsed if delta is not None else None
            tx = delta[1] * 8 / elapsed if delta is not None else None
            point.update(ts=now, rx_bps=rx, tx_bps=tx)
            item.update(rx_bps=rx, tx_bps=tx)
            if name not in self.series:
                self.series[name] = deque(maxlen=300)
            self.series[name].append(point)
            if delta is not None:
                # Attribute an interval to the UTC minute in which its reading finishes.
                stamp = int(now // 60) * 60
                bucket = self.buckets.setdefault(
                    (stamp, name),
                    {
                        "ts": stamp,
                        "interface": name,
                        "seconds": 0,
                        "rx_bytes": 0,
                        "tx_bytes": 0,
                        "rx_packets": 0,
                        "tx_packets": 0,
                    },
                )
                bucket["seconds"] += elapsed
                for key, value in zip(
                    ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"), delta, strict=True
                ):
                    bucket[key] += value
            if self.rule.enabled:
                self._check_rates(name, now, monotonic, rx, tx)

        self.interfaces = interfaces
        self.previous = current
        self.previous_up = {i["name"]: i["up"] for i in interfaces}
        self.previous_time = monotonic
        if monotonic - self.last_flush >= 5:
            self.flush()
            self.last_flush = monotonic
        if now - self.last_prune >= 86400:
            prune(self.engine, now)
            self.last_prune = now

    def _check_rates(self, name, now, monotonic, rx, tx):
        for kind, value, limit, label in (
            ("rx_rate", rx, self.rule.rx_mbps, "下载"),
            ("tx_rate", tx, self.rule.tx_mbps, "上传"),
        ):
            key = (name, kind)
            state = self.thresholds.setdefault(key, ThresholdState())
            event = state.observe(value, limit * 1_000_000, self.rule, monotonic)
            if event == "trigger":
                self._incident(
                    name,
                    kind,
                    now,
                    f"{name} {label}连续 {self.rule.consecutive} 次超过 {limit:g} Mbps，"
                    f"当前 {value / 1_000_000:.2f} Mbps。",
                    "查看同一时段的通信端点、测速记录或已授权的抓包统计，确认流量来源。",
                )
            elif event == "recover":
                self._recover(name, kind, now)

    def flush(self):
        save_buckets(self.engine, self.buckets)
        self.buckets.clear()

    def select_interface(self, name):
        with self.engine.begin() as db:
            write_setting(db, "interface", name)
        self.selected = name
        self.log("interface.select", f"选择监测网卡 {name}。")

    def configure(self, rule):
        if rule == self.rule:
            return
        with self.engine.begin() as db:
            write_setting(db, "rule", rule.model_dump_json())
            db.execute(
                update(alerts)
                .where(
                    alerts.c.recovered_at.is_(None),
                    alerts.c.kind.in_(("rx_rate", "tx_rate")),
                )
                .values(recovered_at=time.time(), end_reason="rule_changed")
            )
        self.open_alerts = {key for key in self.open_alerts if key[1] not in ("rx_rate", "tx_rate")}
        self.thresholds.clear()
        self.rule = rule
        self.log("rule.update", "更新上传和下载速率告警规则。")

    def snapshot(self):
        series = list(self.series.get(self.selected, ()))
        latest = series[-1] if series else None
        interface = next((i for i in self.interfaces if i["name"] == self.selected), None)
        if self.error:
            status, message = "error", self.error
        elif not interface or not interface["up"]:
            status, message = "offline", "所选网卡已断开或没有可用网卡。"
        elif latest is None or latest["rx_bps"] is None:
            status, message = "warming", "等待两次连续有效的系统计数器读数。"
        else:
            status, message = "collecting", "正在读取系统网卡计数器。"
        return {
            "selected": self.selected,
            "status": status,
            "message": message,
            "interval": 1,
            "interfaces": self.interfaces,
            "series": series,
            "latest": latest,
        }
