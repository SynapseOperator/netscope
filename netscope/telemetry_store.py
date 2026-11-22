from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    and_,
    delete,
    select,
    update,
)
from sqlalchemy.dialects.sqlite import insert

metadata = MetaData()
minutes = Table(
    "traffic_minutes",
    metadata,
    Column("ts", Integer, primary_key=True),
    Column("interface", String, primary_key=True),
    Column("seconds", Float, nullable=False),
    *(
        Column(key, Integer, nullable=False)
        for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
    ),
)
alerts = Table(
    "monitor_alerts",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", Float, nullable=False, index=True),
    Column("interface", String, nullable=False),
    Column("kind", String, nullable=False),
    Column("message", String, nullable=False),
    Column("advice", String, nullable=False),
    Column("recovered_at", Float),
    Column("end_reason", String),
    Column("acknowledged", Boolean, nullable=False, default=False),
)
settings = Table(
    "monitor_settings",
    metadata,
    Column("key", String, primary_key=True),
    Column("value", String, nullable=False),
)
logs = Table(
    "monitor_logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", Float, nullable=False, index=True),
    Column("action", String, nullable=False),
    Column("message", String, nullable=False),
)


def write_setting(db, key, value):
    statement = insert(settings).values(key=key, value=value)
    db.execute(statement.on_conflict_do_update(index_elements=["key"], set_={"value": value}))


def save_buckets(engine, buckets):
    if not buckets:
        return
    with engine.begin() as db:
        statement = insert(minutes)
        fields = ["seconds", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets"]
        db.execute(
            statement.on_conflict_do_update(
                index_elements=["ts", "interface"],
                set_={k: minutes.c[k] + statement.excluded[k] for k in fields},
            ),
            list(buckets.values()),
        )


def prune(engine, now):
    cutoff = now - 30 * 86400
    with engine.begin() as db:
        db.execute(delete(minutes).where(minutes.c.ts < cutoff))
        db.execute(delete(logs).where(logs.c.ts < cutoff))
        db.execute(delete(alerts).where(alerts.c.recovered_at < cutoff))


def history_query(start, end, interface):
    query = select(
        minutes,
        (minutes.c.rx_bytes * 8.0 / minutes.c.seconds).label("rx_bps"),
        (minutes.c.tx_bytes * 8.0 / minutes.c.seconds).label("tx_bps"),
    ).where(and_(minutes.c.ts >= start, minutes.c.ts <= end))
    if interface is not None:
        query = query.where(minutes.c.interface == interface)
    return query.order_by(minutes.c.ts.desc(), minutes.c.interface)


def close_alert(db, interface, kind, ts, reason):
    return db.execute(
        update(alerts)
        .where(
            alerts.c.interface == interface,
            alerts.c.kind == kind,
            alerts.c.recovered_at.is_(None),
        )
        .values(recovered_at=ts, end_reason=reason)
    )
