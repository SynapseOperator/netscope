import csv
import io
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from .devices import connections, neighbors
from .telemetry import AlertRule
from .telemetry_store import alerts, history_query, logs

router = APIRouter()


class Selection(BaseModel):
    name: str = Field(min_length=1, max_length=512)


@router.get("/monitor")
async def get_monitor(request: Request):
    return request.app.state.monitor.snapshot()


@router.put("/monitor/interface")
async def select_monitor_interface(selection: Selection, request: Request):
    monitor = request.app.state.monitor
    if selection.name not in {i["name"] for i in monitor.interfaces}:
        raise HTTPException(404, "系统中找不到这张网卡。")
    monitor.select_interface(selection.name)
    return monitor.snapshot()


@router.get("/neighbors")
def get_neighbors():
    return neighbors()


@router.get("/connections")
def get_connections():
    return connections()


def ranged_query(start, end, interface):
    end = end if end is not None else time.time()
    start = start if start is not None else end - 86400
    if start > end:
        raise HTTPException(422, "开始时间须早于结束时间。")
    # The first minute may partially overlap the requested interval.
    return history_query(int(start // 60) * 60, end, interface)


@router.get("/history")
def history(
    request: Request,
    start: float | None = Query(None, ge=0, allow_inf_nan=False),
    end: float | None = Query(None, ge=0, allow_inf_nan=False),
    interface: str | None = None,
):
    query = ranged_query(start, end, interface)
    with request.app.state.db.connect() as db:
        rows = db.execute(query.limit(5001)).mappings().all()
    return {"items": [dict(r) for r in rows[:5000]], "truncated": len(rows) > 5000}


@router.get("/history.csv")
def export_history(
    request: Request,
    start: float | None = Query(None, ge=0, allow_inf_nan=False),
    end: float | None = Query(None, ge=0, allow_inf_nan=False),
    interface: str | None = None,
):
    query = ranged_query(start, end, interface)
    engine = request.app.state.db
    request.app.state.monitor.log("history.export", "导出流量分钟汇总 CSV。")

    def chunks():
        yield "\ufeff"
        with engine.connect() as db:
            rows = db.execute(query)
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer)
            writer.writerow(rows.keys())
            for page in rows.mappings().partitions(256):
                for row in page:
                    values = dict(row)
                    # Interface labels are user-controlled and Excel evaluates formula cells.
                    if values["interface"].lstrip().startswith(("=", "+", "-", "@")):
                        values["interface"] = "'" + values["interface"]
                    writer.writerow(values.values())
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
            yield buffer.getvalue()

    return StreamingResponse(
        chunks(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="netscope-traffic.csv"',
        },
    )


@router.get("/alerts/rule")
async def current_rule(request: Request):
    return request.app.state.monitor.rule


@router.put("/alerts/rule")
async def configure_rule(rule: AlertRule, request: Request):
    request.app.state.monitor.configure(rule)
    return rule


@router.get("/alerts")
def get_alerts(request: Request):
    with request.app.state.db.connect() as db:
        rows = db.execute(select(alerts).order_by(alerts.c.id.desc()).limit(500)).mappings()
        return {"items": [dict(row) for row in rows]}


@router.post("/alerts/{alert_id}/ack")
def acknowledge(alert_id: int, request: Request):
    with request.app.state.db.begin() as db:
        row = db.execute(select(alerts.c.acknowledged).where(alerts.c.id == alert_id)).first()
        if row is None:
            raise HTTPException(404, "找不到这条告警。")
        if not row.acknowledged:
            db.execute(update(alerts).where(alerts.c.id == alert_id).values(acknowledged=True))
            db.execute(
                logs.insert().values(
                    ts=time.time(),
                    action="alert.ack",
                    message=f"已确认告警 #{alert_id}。",
                )
            )
    return {"ok": True}


@router.get("/logs")
def get_logs(request: Request):
    with request.app.state.db.connect() as db:
        rows = db.execute(select(logs).order_by(logs.c.id.desc()).limit(250)).mappings()
        return {"items": [dict(row) for row in rows]}
