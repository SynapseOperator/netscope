"""Correlate observations around an alert without assigning traffic to a process."""

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import or_, select

from . import packets, speed
from .telemetry_store import alerts, history_query

router = APIRouter()


@router.get("/alerts/{alert_id}/diagnosis")
def diagnosis(alert_id: int, request: Request):
    engine = request.app.state.db
    with engine.connect() as db:
        event = db.execute(select(alerts).where(alerts.c.id == alert_id)).mappings().one_or_none()
        if event is None:
            raise HTTPException(404, "找不到这条告警")
        iface = event["interface"]
        minute = int(event["ts"] // 60) * 60
        start, end = max(0, minute - 60), minute + 120
        window = {"start": start, "end": end, "interface": iface}
        samples = []
        tests = []
        if iface:
            samples = db.execute(history_query(start, end - 1, iface)).mappings().all()
            s = speed.results.c
            tests = (
                db.execute(
                    select(
                        s.started_at,
                        s.ended_at,
                        s.interface,
                        s.mode,
                        s.scope,
                        s.download_mbps,
                        s.upload_mbps,
                    )
                    .where(s.interface == iface, s.started_at < end, s.ended_at > start)
                    .order_by(s.started_at.desc())
                    .limit(5)
                )
                .mappings()
                .all()
            )
        interruptions = (
            db.execute(
                select(alerts.c.ts, alerts.c.kind, alerts.c.interface)
                .where(
                    alerts.c.interface.in_({iface, ""}),
                    alerts.c.kind.in_(("collector", "sample_gap", "interface", "counter")),
                    alerts.c.ts < end,
                    or_(alerts.c.recovered_at.is_(None), alerts.c.recovered_at >= start),
                )
                .order_by(alerts.c.ts.desc())
                .limit(10)
            )
            .mappings()
            .all()
        )

    limitations = []
    capture = None
    if iface:
        stats = packets.capture_analysis(
            request.app.state.capture, scope="history", interface=iface, start=start, end=end, limit=3
        )
        capture = {k: stats[k] for k in ("status", "total", "bytes", "flows", "endpoints")}
        if stats["status"] == "empty":
            if stats["expired_session_ids"]:
                limitations.append("该窗口的抓包明细已过保留期，仅能查看整场汇总。")
            elif stats["source"]:
                limitations.append("窗口内有抓包会话，未找到可归属到该时段的报文。")
            else:
                limitations.append("该时间段没有抓包记录。")
        elif stats["status"] == "legacy":
            limitations.append("旧抓包会话只有整场汇总，无法还原窗口内的流量。")
        elif stats["status"] == "partial":
            limitations.append(stats["message"])
        if stats["capture_filters"]:
            limitations.append("窗口内有会话启用了捕获过滤，统计仅包含通过相应 BPF 的报文。")
        if not tests:
            limitations.append("没有可确认属于此接口且与窗口重叠的测速。")
    else:
        limitations.append("系统级事件没有绑定接口，无法归属到具体网卡、抓包或测速。")
    if not samples and iface:
        limitations.append("所选接口没有可用的分钟计数器记录。")
    if interruptions:
        limitations.append("窗口涉及采集间断或接口状态事件，有效采样可能不完整。")

    counter = None
    if samples:
        counter = {
            "minutes": len(samples),
            "seconds": sum(r["seconds"] for r in samples),
            "rx_bytes": sum(r["rx_bytes"] for r in samples),
            "tx_bytes": sum(r["tx_bytes"] for r in samples),
        }
    if event["kind"] in {"rx_rate", "tx_rate"}:
        possible = (
            "同期有主动测速，测试传输可能贡献部分接口流量。"
            if tests
            else "持续的数据传输可能抬高接口速率，具体来源需要结合同时段的通信流核实。"
        )
    elif event["kind"] in {"counter", "interface"}:
        possible = "接口连接或驱动状态变化可能影响相邻读数。"
    else:
        possible = "主机休眠、采集延迟或系统读取异常均可能造成观测间断。"
    return {
        "event": dict(event),
        "window": window,
        "counter": counter,
        "capture": capture,
        "speed_tests": [dict(t) for t in tests],
        "interruptions": [dict(g) for g in interruptions],
        "limitations": limitations,
        "possible": possible,
        "check": event["advice"],
    }
