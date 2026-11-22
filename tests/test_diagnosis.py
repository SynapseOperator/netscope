import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from scapy.all import IP, UDP, Ether
from sqlalchemy import create_engine, insert

from netscope.diagnosis import router
from netscope.packets import Capture, Observations
from netscope.speed import SpeedTest, results
from netscope.telemetry import AlertRule, Monitor
from netscope.telemetry_store import minutes


@pytest.fixture
def bench(tmp_path):
    app = FastAPI()
    app.include_router(router)
    db = app.state.db = create_engine(f"sqlite:///{tmp_path / 'diagnosis.db'}")
    capture = app.state.capture = Capture(db)
    monitor = Monitor(db)
    SpeedTest(db, monitor.log)
    with TestClient(app) as client:
        yield client, db, capture, monitor
    capture.close()
    db.dispose()


def test_matched_sources_share_interface_and_window(bench):
    client, db, capture, monitor = bench
    minute = int(time.time() // 60) * 60
    monitor.configure(AlertRule(rx_mbps=1, consecutive=2))
    monitor._check_rates("lab", minute + 1, 10, 2_000_000, 0)
    monitor._check_rates("lab", minute + 2, 11, 3_000_000, 0)
    # Two synthetic IPv4 frames on the test interface, one inside and one outside the window.
    data = Observations({"192.0.2.1"})
    packet = Ether(
        bytes(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="198.51.100.1")
            / UDP(sport=1000, dport=2000)
        )
    )
    for ts in (minute - 65, minute + 1):
        packet.time = ts
        data.add(packet)
    for source, iface in (("live", "lab"), ("live", "other"), ("pcap", None)):
        capture._persist(data, source, iface, minute - 70, None)
    with db.begin() as conn:
        for iface in ("lab", "other"):
            conn.execute(
                insert(minutes).values(
                    ts=minute,
                    interface=iface,
                    seconds=10,
                    rx_bytes=1000,
                    tx_bytes=2000,
                    rx_packets=8,
                    tx_packets=7,
                )
            )
        for iface, lo, hi in (
            ("lab", minute - 70, minute - 58),
            ("other", minute, minute + 2),
            ("lab", minute - 75, minute - 60),
            ("lab", minute + 120, minute + 125),
            (None, minute, minute + 2),
        ):
            conn.execute(
                insert(results).values(
                    at=hi,
                    started_at=lo,
                    ended_at=hi,
                    interface=iface,
                    mode="quick",
                    scope="lan",
                    download_mbps=10,
                    upload_mbps=5,
                )
            )
    # Changing today's settings must not change the threshold recorded at trigger time.
    monitor.configure(AlertRule(rx_mbps=50))
    result = client.get("/alerts/1/diagnosis").json()
    assert result["window"] == {"start": minute - 60, "end": minute + 120, "interface": "lab"}
    assert result["event"]["observation"]["threshold_bps"] == 1_000_000
    assert result["event"]["observation"]["observed_bps"] == 3_000_000
    assert result["event"]["end_reason"] == "rule_changed"
    assert result["counter"] == {"minutes": 1, "seconds": 10, "rx_bytes": 1000, "tx_bytes": 2000}
    assert result["capture"]["total"] == 1 and result["capture"]["bytes"] == len(packet)
    assert len(result["speed_tests"]) == 1 and result["speed_tests"][0]["started_at"] == minute - 70
    assert not result["limitations"]


def test_missing_and_system_evidence_remain_explicit(bench):
    client, _, _, monitor = bench
    monitor._incident("lab", "interface", 500, "接口已断开", "检查接口")
    monitor._incident("", "collector", 501, "读取失败", "检查采集状态")
    no_data = client.get("/alerts/1/diagnosis").json()
    assert no_data["counter"] is None and no_data["capture"]["status"] == "empty"
    assert no_data["capture"]["bytes"] is None and no_data["speed_tests"] == []
    assert "该时间段没有抓包记录。" in no_data["limitations"]
    assert len(no_data["interruptions"]) == 2
    system = client.get("/alerts/2/diagnosis").json()
    assert system["capture"] is None and system["speed_tests"] == []
    assert any("没有绑定接口" in msg for msg in system["limitations"])
    assert client.get("/alerts/999/diagnosis").status_code == 404


def test_filtered_capture_limits_the_scope_of_a_diagnosis(bench):
    client, _, capture, monitor = bench
    now = time.time()
    monitor._incident("lab", "rx_rate", now, "下载超过阈值", "核查同期数据")
    observed = Observations()
    packet = Ether(
        bytes(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="198.51.100.1")
            / UDP(sport=4000, dport=5000)
        )
    )
    packet.time = now
    observed.add(packet)
    capture._persist(observed, "live", "lab", now, "udp")
    result = client.get("/alerts/1/diagnosis").json()
    assert result["capture"]["total"] == 1
    assert any("BPF" in note for note in result["limitations"])


def test_additive_migration_preserves_v1_alerts(tmp_path):
    db = create_engine(f"sqlite:///{tmp_path / 'older.db'}")
    with db.begin() as conn:
        conn.exec_driver_sql("""CREATE TABLE monitor_alerts (
          id INTEGER PRIMARY KEY, ts FLOAT, interface TEXT, kind TEXT, message TEXT,
          advice TEXT, recovered_at FLOAT, end_reason TEXT, acknowledged BOOLEAN)""")
        conn.exec_driver_sql("""INSERT INTO monitor_alerts VALUES
          (7,123,'lab','rx_rate','历史触发条件','检查接口',124,'recovered',1)""")
    Monitor(db)
    Monitor(db)
    with db.connect() as conn:
        row = conn.exec_driver_sql(
            "SELECT id, message, acknowledged, observation FROM monitor_alerts"
        ).one()
        assert tuple(row) == (7, "历史触发条件", 1, None)
    db.dispose()
