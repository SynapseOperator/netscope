from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select

from netscope.monitor_api import router
from netscope.telemetry import AlertRule, Monitor, ThresholdState, counter_delta
from netscope.telemetry_store import alerts, minutes


@pytest.fixture
def monitor(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'telemetry.sqlite'}")
    yield Monitor(engine)
    engine.dispose()


def sample(monitor, stamp, count, *, up=True, name="lab", present=True):
    iface = {
        "name": name,
        "up": up,
        "speed_mbps": 1000,
        "mtu": 1500,
        "mac": None,
        "ipv4": ["192.0.2.28"],
        "ipv6": [],
    }
    counter = SimpleNamespace(
        bytes_recv=count, bytes_sent=count * 2, packets_recv=count, packets_sent=count
    )
    monitor.ingest([iface] if present else [], {name: counter} if present else {}, stamp, stamp)


def test_rates_use_elapsed_time_and_ignore_gaps_and_resets(monitor):
    sample(monitor, 120, 100)
    assert monitor.snapshot()["status"] == "warming"
    sample(monitor, 122, 200)
    point = monitor.snapshot()["latest"]
    assert (point["rx_bps"], point["tx_bps"]) == (400, 800)
    sample(monitor, 132, 1500)
    assert monitor.snapshot()["latest"]["rx_bps"] is None
    sample(monitor, 133, 0)
    assert monitor.snapshot()["latest"]["rx_bps"] is None
    sample(monitor, 134, 70)
    assert monitor.snapshot()["latest"]["rx_bps"] == 560
    assert counter_delta((0, 0), (0, 0), 0) is None
    monitor.flush()
    with monitor.engine.connect() as db:
        row = db.execute(select(minutes)).one()
        assert (row.seconds, row.rx_bytes, row.tx_bytes) == (3, 170, 340)
        incidents = db.execute(select(alerts.c.kind, alerts.c.recovered_at)).all()
        assert dict(incidents) == {"sample_gap": 133, "counter": 134}


def test_threshold_comparison_and_cooldown():
    # Isolated spike at t=1. Sustained overload at t=3..6. Recovery at t=8.
    trace = [0, 11, 0, 11, 11, 11, 11, 9, 8, 11, 11, 11, 11, 11]
    baseline = [i for i, value in enumerate(trace) if value > 10]
    rule = AlertRule(consecutive=3, recovery_ratio=0.8, cooldown_s=5)
    state = ThresholdState()
    changes = [
        (i, result) for i, value in enumerate(trace) if (result := state.observe(value, 10, rule, i))
    ]
    assert baseline == [1, 3, 4, 5, 6, 9, 10, 11, 12, 13]
    assert changes == [(5, "trigger"), (8, "recover"), (13, "trigger")]
    # Across the two real episodes, direct comparison repeats 3+4 times.
    assert len(baseline) - 1 - 2 == 7
    assert changes[0][0] - 3 == 2
    state = ThresholdState()
    assert [state.observe(v, 10, rule, t) for t, v in enumerate([11, 11, None, 11, 11])] == [None] * 5


def test_interface_disappears_and_returns_without_bridging_measurements(monitor):
    sample(monitor, 120, 10)
    sample(monitor, 121, 20, present=False)
    assert monitor.snapshot()["status"] == "offline"
    sample(monitor, 122, 90)
    assert monitor.snapshot()["status"] == "warming"
    sample(monitor, 123, 100)
    assert monitor.snapshot()["latest"]["rx_bps"] == 80
    with monitor.engine.connect() as db:
        row = db.execute(select(alerts)).one()
        assert (row.kind, row.recovered_at, row.end_reason) == ("interface", 122, "recovered")


def test_bounded_series_and_same_minute_flush(monitor):
    for t in range(420):
        sample(monitor, 120 + t, 3 * t)
    monitor.flush()
    monitor.flush()
    assert len(monitor.snapshot()["series"]) == 300
    with monitor.engine.connect() as db:
        rows = db.execute(select(minutes)).all()
        assert sum(row.rx_bytes for row in rows) == 419 * 3
        assert sum(row.seconds for row in rows) == 419


def test_api_csv_settings_and_restart(monitor):
    app = FastAPI()
    app.state.monitor = monitor
    app.state.db = monitor.engine
    app.include_router(router, prefix="/api")
    name = "=lab,1"
    with TestClient(app) as http:
        sample(monitor, 120, 0, name=name)
        assert http.put("/api/monitor/interface", json={"name": name}).status_code == 200
        assert http.put("/api/monitor/interface", json={"name": "other"}).status_code == 404
        rule = http.get("/api/alerts/rule").json()
        rule.update(rx_mbps=0.001, consecutive=2)
        assert http.put("/api/alerts/rule", json=rule).status_code == 200
        assert http.put("/api/alerts/rule", json={**rule, "recovery_ratio": 1}).status_code == 422
        sample(monitor, 121, 1000, name=name)
        sample(monitor, 122, 2000, name=name)
        monitor.flush()
        restarted = Monitor(monitor.engine)
        app.state.monitor = restarted
        assert restarted.selected == name and restarted.rule.rx_mbps == 0.001
        sample(restarted, 123, 2000, name=name)
        sample(restarted, 124, 3000, name=name)
        sample(restarted, 125, 3000, name=name)
        restarted.flush()
        events = http.get("/api/alerts").json()["items"]
        assert len(events) == 1 and events[0]["recovered_at"] == 125
        assert http.post(f"/api/alerts/{events[0]['id']}/ack").json() == {"ok": True}
        assert http.get("/api/alerts").json()["items"][0]["acknowledged"] is True
        assert http.post("/api/alerts/999/ack").status_code == 404
        params = {"start": 120, "end": 140, "interface": name}
        row = http.get("/api/history", params=params).json()["items"][0]
        assert (row["rx_bytes"], row["seconds"], row["rx_bps"]) == (3000, 4, 6000)
        response = http.get("/api/history.csv", params=params)
        assert response.status_code == 200 and '"\'=lab,1"' in response.text
        assert http.get("/api/history", params={"start": 10, "end": 5}).status_code == 422
        assert http.get("/api/logs").json()["items"][0]["action"] == "history.export"
