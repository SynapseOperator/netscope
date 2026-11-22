import json
import struct

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6, Raw
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6ExtHdrHopByHop
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from netscope import packets
from netscope.packets import CAPACITY, Capture, Observations, packet_headers


def classic(frames):
    container = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for n, frame in enumerate(frames):
        wire = bytes(frame)
        container.extend(struct.pack("<IIII", 1000 + n, 500_000, len(wire), len(wire)))
        container.extend(wire)
    return bytes(container)


def frame(body):
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / body


@pytest.fixture
def api():
    app = FastAPI()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    app.state.capture = Capture(engine)
    app.include_router(packets.router)
    with TestClient(app) as client:
        yield client
    app.state.capture.close()
    engine.dispose()


def test_pcap_import_filter_and_history(api):
    base = IP(src="192.0.2.1", dst="192.0.2.2", ttl=42)
    frames = [
        frame(base / TCP(sport=49800, dport=443, seq=7, flags="PA") / Raw(b"private-content-marker")),
        frame(base / UDP(sport=50000, dport=9999)),
        frame(base / ICMP(type=3) / base / TCP()),
        frame(IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()),
        frame(ARP(psrc="192.0.2.1", pdst="192.0.2.2")),
    ]
    out = api.post("/capture/import", content=classic(frames))
    assert out.status_code == 200
    snapshot = out.json()
    assert (snapshot["source"], snapshot["state"], snapshot["total"]) == ("pcap", "imported", 5)
    assert snapshot["bytes"] == sum(map(len, frames))
    assert {row["name"] for row in snapshot["protocols"]} == {"TCP", "UDP", "ICMP", "ICMPv6", "ARP"}
    assert next(e["packets"] for e in snapshot["endpoints"] if e["name"] == "192.0.2.1") == 4
    assert len(api.get("/capture/packets?protocol=ip").json()) == 4
    assert len(api.get("/capture/packets?protocol=ipv6").json()) == 1
    selected = api.get("/capture/packets?protocol=TCP&port=443&ip=192.0.2.1").json()
    assert len(selected) == 1
    tcp = selected[0]
    assert (tcp["id"], tcp["timestamp"], tcp["length"]) == (1, 1000.5, len(frames[0]))
    assert tcp["headers"]["IPv4"]["TTL"] == 42 and tcp["headers"]["TCP"]["Sequence"] == 7
    for path in ["/capture", "/capture/history", "/capture/packets"]:
        assert "private-content-marker" not in api.get(path).text
    assert api.get("/capture/packets?ip=bad").status_code == 422
    assert api.get("/capture/packets?port=65536").status_code == 422
    assert api.get("/capture/packets?protocol=bogus").status_code == 422
    assert api.get("/capture/history?start=2&end=1").status_code == 422
    session = api.get("/capture/history").json()[0]
    assert session["total"] == 5 and session["source"] == "pcap"
    assert api.get(f"/capture/history?start={session['ended_at'] + 1}").json() == []


def test_bounded_resources_and_atomic_import(api):
    sample = frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP())
    data = classic([sample] * (CAPACITY + 2))
    assert api.post("/capture/import", content=data).json()["total"] == CAPACITY + 2
    retained = api.get(f"/capture/packets?limit={CAPACITY}").json()
    assert len(retained) == CAPACITY and retained[-1]["id"] == 3
    for corrupt in [b"", data[:23], data[:-1], data[:25], b"\x1f\x8b" + data]:
        assert api.post("/capture/import", content=corrupt).status_code == 422
    assert api.post("/capture/import", content=bytes(packets.MAX_FILE + 1)).status_code == 413
    too_many = data[:24]
    too_many += (struct.pack("<IIII", 1, 0, 1, 1) + b"\0") * (packets.MAX_RECORDS + 1)
    assert api.post("/capture/import", content=too_many).status_code == 413
    assert len(api.get("/capture/history").json()) == 1
    assert api.get("/capture").json()["total"] == CAPACITY + 2


def test_offline_import_without_driver_and_open_failure(api, monkeypatch):
    monkeypatch.setattr(Capture, "available", property(lambda self: False))
    assert api.get("/capture/interfaces").json() == []
    response = api.post("/capture/start", json={"interface": "example"})
    assert response.status_code == 503 and "Npcap" in response.json()["detail"]
    assert api.get("/capture").json()["state"] == "error"
    assert api.post("/capture/import", content=classic([])).json()["state"] == "imported"


def test_permission_denied_and_removed_interface(api, monkeypatch):
    class DeniedInterface:
        name = "sample"
        description = "test"

        def l2listen(self):
            def denied(**kwargs):
                raise PermissionError()

            return denied

    monkeypatch.setattr(Capture, "available", property(lambda self: True))
    monkeypatch.setattr(packets.conf.ifaces, "values", lambda: [DeniedInterface()])
    assert api.post("/capture/start", json={"interface": "missing"}).status_code == 422
    assert api.post("/capture/start", json={"interface": "sample"}).status_code == 503
    assert "权限" in api.get("/capture").json()["error"]


def test_endpoint_limit_and_same_address_counted_once(monkeypatch):
    monkeypatch.setattr(packets, "MAX_ENDPOINTS", 3)
    observations = Observations()
    for n in range(1, 8):
        address = f"192.0.2.{n}"
        parsed = Ether(bytes(frame(IP(src=address, dst=address) / UDP())))
        observations.add(parsed)
    report = observations.summary()
    assert len(report["endpoints"]) == 4
    assert sum(e["packets"] for e in report["endpoints"]) == 7
    assert sum(e["bytes"] for e in report["endpoints"]) == report["bytes"]
    assert packet_headers(parsed)["sport"] == 53


def test_persisted_only_session_metadata(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "capture.db"))
    capture = Capture(engine)
    marker = b"SENSITIVE_PAYLOAD_NOT_TO_STORE"
    capture.load(classic([frame(IP(src="192.0.2.1", dst="192.0.2.2") / TCP() / Raw(marker))]))
    capture.close()
    engine.dispose()
    new_engine = create_engine(engine.url)
    reopened = Capture(new_engine)
    with new_engine.connect() as connection:
        row = dict(connection.execute(packets.sessions.select()).mappings().one())
    assert row["source"] == "pcap" and row["total"] == 1
    assert "headers" not in json.dumps(row)
    assert marker not in (tmp_path / "capture.db").read_bytes()
    assert reopened.status()["total"] == 0
    new_engine.dispose()


def test_socket_failure_and_disconnected_start(api, monkeypatch):
    from types import SimpleNamespace

    class BrokenSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def select(self, *args, **kwargs):
            raise OSError("device unavailable")

    iface = SimpleNamespace(
        name="sample", description="Test", l2listen=lambda: lambda **kw: BrokenSocket()
    )
    link = SimpleNamespace(isup=False)
    monkeypatch.setattr(Capture, "available", property(lambda self: True))
    monkeypatch.setattr(packets.conf.ifaces, "values", lambda: [iface])
    monkeypatch.setattr(packets.psutil, "net_if_stats", lambda: {iface.name: link})
    assert api.get("/capture/interfaces").json()[0]["is_up"] is False
    assert api.post("/capture/start", json={"interface": "sample"}).status_code == 409
    link.isup = True
    assert api.post("/capture/start", json={"interface": "sample"}).status_code == 200
    capture = api.app.state.capture
    capture.worker.join(timeout=2)
    assert not capture.worker.is_alive()
    assert api.get("/capture").json()["state"] == "error"
    assert api.post("/capture/stop").json()["error"]
    assert len(api.get("/capture/history").json()) == 1
    assert api.post("/capture/stop").status_code == 200
    assert len(api.get("/capture/history").json()) == 1


def test_driver_bpf_presets_and_failure_do_not_fall_back(api, monkeypatch):
    from types import SimpleNamespace

    applied = []

    def reject(**kwargs):
        applied.append((kwargs["filter"], kwargs["promisc"]))
        raise packets.Scapy_Exception("Cannot set filter: rejected test expression")

    iface = SimpleNamespace(name="sample", description="test", l2listen=lambda: reject)
    monkeypatch.setattr(Capture, "available", property(lambda self: True))
    monkeypatch.setattr(packets.conf.ifaces, "values", lambda: [iface])
    url = "/capture/start"
    for params in [
        {"bpf": "tcp", "protocol": "UDP"},
        {"bpf": "tcp\x00udp"},
        {"port": 65536},
        {"ip": "invalid"},
        {"bpf": "x" * 257},
        {"bpf_typo": "udp"},
    ]:
        assert api.post(url, json={"interface": "sample", **params}).status_code == 422
    assert not applied
    assert api.post(url, json={"interface": "sample", "bpf": "tcp"}).status_code == 503
    assert not applied
    monkeypatch.setattr(packets, "supports_bpf", lambda factory: True)
    response = api.post(
        url, json={"interface": "sample", "protocol": "TCP", "ip": "192.0.2.1", "port": 0}
    )
    assert response.status_code == 422 and "BPF" in response.json()["detail"]
    assert applied == [("tcp and host 192.0.2.1 and port 0", False)]
    assert api.app.state.capture.worker is None
    assert not api.get("/capture/history").json()
    assert api.post(url, json={"interface": "sample", "bpf": "tcp and ("}).status_code == 422
    assert applied[-1] == ("tcp and (", False)
    assert (
        packets.StartParams(interface="sample", protocol="IPv6", ip="2001:db8::1").expression()
        == "ip6 and host 2001:db8::1"
    )


def test_directional_flow_drilldown_and_import_time(api):
    a, b = "192.0.2.3", "192.0.2.5"
    out = frame(IP(src=a, dst=b) / TCP(sport=52300, dport=443))
    inbound = frame(IP(src=b, dst=a) / TCP(sport=443, dport=52300))
    sample = [
        out,
        inbound,
        out,
        frame(IP(src=a, dst=b) / ICMP()),
        frame(IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=0, dport=999)),
    ]
    snapshot = api.post("/capture/import", content=classic(sample)).json()
    result = api.get("/capture/analysis?limit=1").json()
    assert (result["total"], result["bytes"], result["flow_count"], result["endpoint_count"]) == (
        5,
        sum(map(len, sample)),
        4,
        4,
    )
    assert result["session_ids"] == [snapshot["session_id"]]
    assert len(result["flows"]) == len(result["endpoints"]) == 1
    assert [p["start"] for p in result["buckets"]] == [1000, 1001, 1002, 1003, 1004]
    assert sum(p["bytes"] for p in result["buckets"]) == result["bytes"]
    top = result["flows"][0]
    assert (top["src"], top["dst"], top["sport"], top["dport"], top["direction"], top["packets"]) == (
        a,
        b,
        52300,
        443,
        "unknown",
        2,
    )
    rows = api.get(
        "/capture/packets",
        params={"flow_id": top["id"], "start": 1001, "end": 1003, "direction": "unknown"},
    ).json()
    assert [r["id"] for r in rows] == [3]
    reverse = api.get(
        "/capture/analysis",
        params={
            "scope": "history",
            "session_id": snapshot["session_id"],
            "start": 1001,
            "end": 1002,
            "protocol": "tcp",
        },
    ).json()
    assert (
        reverse["total"] == 1
        and reverse["flows"][0]["src"] == b
        and reverse["flows"][0]["id"] != top["id"]
    )
    assert api.get("/capture/analysis?direction=outbound").json()["status"] == "empty"
    assert api.get("/capture/history?start=999&end=1005").json() == []
    imported_ipv6 = api.get(
        "/capture/analysis",
        params={
            "session_id": snapshot["session_id"],
            "ip": "2001:0db8:0:0:0:0:0:2",
            "scope": "history",
        },
    ).json()
    assert imported_ipv6["total"] == 1 and imported_ipv6["flows"][0]["dport"] == 999
    assert (
        api.get("/capture/history?time_basis=observed&start=999&end=1005").json()[0]["source"] == "pcap"
    )
    assert (
        api.get("/capture/analysis?scope=history&interface=lab&start=999&end=1005").json()["total"]
        is None
    )
    assert api.get("/capture/analysis?protocol=bogus").status_code == 422
    assert api.get("/capture/analysis?start=1005&end=1000").status_code == 422


def test_ipv6_and_ipv4_fragments_and_short_transport_headers(api):
    from scapy.layers.inet6 import IPv6ExtHdrFragment

    src, dst = "192.0.2.3", "192.0.2.5"
    frag1 = frame(
        IP(src=src, dst=dst, flags="MF", id=10) / UDP(sport=50000, dport=7000) / Raw(b"12345678")
    )
    frag2 = frame(IP(src=src, dst=dst, frag=2, proto=17, id=10) / Raw(bytes(8)))
    v6 = IPv6(src="2001:db8::1", dst="2001:db8::2")
    tail6 = frame(v6 / IPv6ExtHdrHopByHop() / IPv6ExtHdrFragment(offset=2, id=7, nh=6) / Raw(bytes(8)))
    short_tcp = frame(IP(src=src, dst=dst, proto=6) / Raw(b"\x00\x01"))
    ipv6 = frame(v6 / IPv6ExtHdrHopByHop() / TCP(sport=111, dport=222))
    assert (
        api.post("/capture/import", content=classic([frag1, frag2, tail6, short_tcp, ipv6])).status_code
        == 200
    )
    report = api.get("/capture/analysis").json()
    udp = next(f for f in report["flows"] if f["protocol"] == "UDP")
    assert (udp["kind"], udp["sport"], udp["dport"], udp["packets"]) == ("fragment", None, None, 2)
    records = api.get("/capture/packets", params={"flow_id": udp["id"]}).json()
    assert [r["sport"] for r in records] == [None, 50000]
    ipv6_rows = api.get("/capture/packets?protocol=ipv6").json()
    assert len(ipv6_rows) == 2 and ipv6_rows[0]["dport"] == 222
    assert ipv6_rows[1]["headers"]["IPv6 Fragment"]["Offset"] == 2
    assert ipv6_rows[1]["sport"] is None and ipv6_rows[1]["protocol"] == "TCP"
    incomplete = next(f for f in report["flows"] if f["kind"] == "network")
    assert (
        incomplete["protocol"] == "TCP" and incomplete["sport"] is None and incomplete["dport"] is None
    )


def test_true_capture_length_from_truncated_pcap(api):
    raw = bytes(frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=51, dport=52)))
    short_length = len(raw) - 5
    header = classic([]) + struct.pack("<IIII", 1000, 0, short_length, len(raw))
    api.post("/capture/import", content=header + raw[:short_length]).raise_for_status()
    row = api.get("/capture/packets").json()[0]
    assert row["truncated"] and row["captured_length"] == short_length and row["length"] == len(raw)
    assert row["sport"] is None and row["kind"] == "network"


def test_uncertain_boundary_and_caps_are_not_fabricated(api, monkeypatch):
    from netscope import flows

    sample = bytes(frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=20, dport=99)))

    def record(second, us, payload):
        return struct.pack("<IIII", second, us, len(payload), len(payload)) + payload

    base = classic([])
    api.post(
        "/capture/import", content=base + record(1500, 100000, sample) + record(1500, 900000, sample)
    ).raise_for_status()
    partial = api.get("/capture/analysis?scope=history&start=1500.5&end=1501").json()
    assert partial["status"] == "partial" and partial["bytes"] is None and partial["buckets"] == []
    whole = api.get("/capture/analysis?scope=history&start=1500&end=1501").json()
    assert whole["status"] == "ok" and whole["buckets"] == [
        {"start": 1500, "end": 1501, "packets": 2, "bytes": 2 * len(sample)}
    ]
    monkeypatch.setattr(flows, "MAX_SECONDS", 2)
    monkeypatch.setattr(flows, "MAX_GROUPS_PER_SECOND", 1)
    other = bytes(frame(IP(src="192.0.2.7", dst="192.0.2.8") / ICMP()))
    raw = (
        base
        + record(1503, 0, sample)
        + record(1501, 0, sample)
        + record(1502, 0, sample)
        + record(1500, 0, sample)
        + record(1503, 500000, other)
    )
    snapshot = api.post("/capture/import", content=raw).json()
    assert snapshot["total"] == 5
    bounded = api.get("/capture/analysis").json()
    assert bounded["total"] == 2 and bounded["status"] == "partial" and bounded["flow_count"] is None
    assert api.get("/capture/analysis?start=1500&end=1502").json()["bytes"] is None
    assert api.get("/capture/analysis?start=1502&end=1503").json()["status"] == "ok"
    history = api.get("/capture/analysis", params={"session_id": snapshot["session_id"]}).json()
    assert history == bounded


def test_v1_session_has_no_attributable_seconds(api):
    cap = api.app.state.capture
    with cap.engine.begin() as db:
        legacy = db.execute(
            packets.sessions.insert().values(
                source="live",
                interface="lab",
                started_at=100,
                ended_at=200,
                total=1000,
                bytes=12345678,
                protocols=[],
                endpoints=[],
            )
        ).inserted_primary_key[0]
    result = api.get("/capture/analysis?scope=history&interface=lab&start=150&end=151").json()
    assert result["status"] == "legacy" and result["total"] is None and not result["buckets"]
    assert result["session_ids"] == [legacy]
    assert (
        api.get("/capture/analysis?scope=history&interface=other&start=150&end=151").json()["status"]
        == "empty"
    )
    assert (
        api.get("/capture/analysis?scope=history&interface=lab&start=2000&end=2001").json()["bytes"]
        is None
    )
    assert (
        api.get("/capture/history?time_basis=observed&interface=lab&start=150&end=151").json()[0][
            "bytes"
        ]
        == 12345678
    )


def test_live_scope_and_session_pruning(api, monkeypatch):
    from scapy.packet import Raw

    cap = api.app.state.capture
    local, other = "192.0.2.8", "192.0.2.9"
    data = Observations({local})
    for src, dst in [(local, other), (other, local), (local, local), (other, "192.0.2.10")]:
        packet = Ether(
            bytes(frame(IP(src=src, dst=dst) / UDP(sport=80, dport=8080) / Raw(b"NO-STORE")))
        )
        packet.time = 1001.5
        data.add(packet)
    cap.interface, cap.source, cap.started_at, cap.data = "lab", "live", 1000, data
    cap.worker = object()
    try:
        out = api.get("/capture/analysis?scope=history&interface=lab&start=1000&end=1002").json()
        assert out["total"] == 4 and not out["session_ids"]
        assert {f["direction"] for f in out["flows"]} == {"inbound", "outbound", "local", "other"}
        assert api.get("/capture/analysis?direction=inbound").json()["total"] == 1
        assert len(api.get("/capture/packets?direction=local").json()) == 1
    finally:
        cap.worker = None
    first = cap._persist(data, "live", "lab", 1000, "udp")
    assert api.get("/capture/analysis?scope=history&interface=lab&start=1000&end=1002").json()[
        "session_ids"
    ] == [first]
    assert api.get("/capture/history").json()[0]["bpf"] == "udp"
    monkeypatch.setattr(packets, "MAX_SESSIONS", 1)
    cap.load(classic([]))
    with cap.engine.connect() as db:
        assert not db.execute(packets.analysis_seconds.select()).all()
        assert len(db.execute(packets.analysis_sessions.select()).all()) == 1
    assert api.get("/capture/analysis", params={"session_id": first}).json()["total"] is None


def test_upgrade_keeps_v1_tables_and_adds_queryable_new_session(tmp_path):
    from sqlalchemy import inspect

    from netscope.packets import capture_analysis

    engine = create_engine("sqlite:///" + str(tmp_path / "v1.db"))
    packets.sessions.create(engine)
    with engine.begin() as db:
        old_id = db.execute(
            packets.sessions.insert().values(
                source="pcap",
                interface=None,
                started_at=2000,
                ended_at=2001,
                total=7,
                bytes=700,
                protocols=[{"name": "TCP", "packets": 7, "bytes": 700}],
                endpoints=[],
            )
        ).inserted_primary_key[0]
    assert inspect(engine).get_table_names() == ["capture_sessions"]
    updated = Capture(engine)
    assert capture_analysis(updated, session_id=old_id)["status"] == "legacy"
    new_id = updated.load(classic([frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP())]))["session_id"]
    engine.dispose()
    rebuilt = create_engine(engine.url)
    reopened = Capture(rebuilt)
    assert capture_analysis(reopened, scope="history", session_id=new_id)["total"] == 1
    with rebuilt.connect() as db:
        row = db.execute(packets.sessions.select().where(packets.sessions.c.id == old_id)).one()
        assert row.total == 7 and row.bytes == 700 and row.protocols[0]["name"] == "TCP"
    rebuilt.dispose()


def test_capture_detail_retention_uses_save_time_and_keeps_session_summary(api, monkeypatch):
    from types import SimpleNamespace

    from sqlalchemy import select

    cap = api.app.state.capture
    clock = [2_000_000_000.0]
    monkeypatch.setattr(packets, "time", SimpleNamespace(time=lambda: clock[0]))
    # Packet clock is in 1970; TTL starts at today's import/save, not the evidence timestamp.
    sample = classic([frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=7, dport=8))])
    source = api.post("/capture/import", content=sample).json()
    first = source["session_id"]
    lifetime = source["detail_retention_days"] * 86400
    assert lifetime == 30 * 86400
    clock[0] += lifetime - 1
    assert api.get("/capture/analysis", params={"session_id": first}).json()["total"] == 1
    clock[0] += 1
    for params in [{}, {"scope": "history", "session_id": first, "start": 1000, "end": 1001}]:
        expired = api.get("/capture/analysis", params=params).json()
        assert expired["status"] == "empty" and "保留期" in expired["message"]
        assert expired["expired_session_ids"] == [first]
        assert expired["total"] is None and not expired["buckets"] and not expired["flows"]
    assert api.get("/capture/packets").json() == []
    assert api.get("/capture").json()["total"] == 1
    with cap.engine.connect() as db:
        assert not db.execute(select(packets.analysis_seconds)).all()
        row = db.execute(select(packets.sessions)).one()
        assert row.id == first and row.total == 1 and row.protocols[0]["name"] == "UDP"
        assert db.execute(select(packets.analysis_sessions)).one().expired_at == clock[0]
    clock[0] += 1
    second = api.post("/capture/import", content=sample).json()["session_id"]
    assert second != first
    mixed = api.get("/capture/analysis?scope=history&start=1000&end=1001").json()
    assert mixed["status"] == "partial" and "已到期" in mixed["message"]
    assert mixed["total"] == 1 and mixed["expired_session_ids"] == [first]
    assert api.get("/capture/analysis", params={"session_id": second}).json()["status"] == "ok"


def test_early_analysis_schema_migrates_on_startup_and_prunes_idle_data(tmp_path):
    from sqlalchemy import select

    engine = create_engine("sqlite:///" + str(tmp_path / "old-development.db"))
    cap = Capture(engine)
    sid = cap.load(classic([frame(IP(src="192.0.2.1", dst="192.0.2.2") / TCP())]))["session_id"]
    with engine.begin() as db:
        db.execute(packets.sessions.update().values(ended_at=86400, started_at=86390))
        db.exec_driver_sql("ALTER TABLE capture_analysis_sessions DROP COLUMN expired_at")
        db.exec_driver_sql("ALTER TABLE capture_analysis_sessions DROP COLUMN saved_at")
    engine.dispose()
    engine = create_engine(engine.url)
    reopened = Capture(engine)
    result = packets.capture_analysis(reopened, session_id=sid)
    assert result["expired_session_ids"] == [sid] and result["total"] is None
    with engine.connect() as db:
        assert db.execute(select(packets.sessions.c.total)).scalar_one() == 1
        assert not db.execute(select(packets.analysis_seconds)).all()
    engine.dispose()


def test_observation_time_bounds_and_query_limits(api):
    for endpoint in ("history", "analysis", "packets"):
        for query in ["start=nan", "end=inf", "start=-1", "end=1e99", "start=10&end=9"]:
            assert api.get(f"/capture/{endpoint}?{query}").status_code == 422
    for endpoint in ("analysis", "packets", "history?time_basis=observed"):
        separator = "&" if "?" in endpoint else "?"
        assert api.get(f"/capture/{endpoint}{separator}start=1&end=1").status_code == 422
    assert api.get("/capture/history?start=1&end=1").status_code == 200
    for query in ["session_id=9223372036854775808", "limit=0", "limit=101"]:
        assert api.get("/capture/analysis?" + query).status_code == 422


def test_out_of_order_timestamps_and_fraction_validation(api):
    wire = bytes(frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP()))

    def record(ts, fraction):
        return struct.pack("<IIII", ts, fraction, len(wire), len(wire)) + wire

    base = classic([])
    content = base + record(104, 0) + record(101, 500000) + record(101, 100000)
    api.post("/capture/import", content=content).raise_for_status()
    stats = api.get("/capture/analysis").json()
    assert [b["start"] for b in stats["buckets"]] == [101, 104]
    assert (stats["flows"][0]["first_seen"], stats["flows"][0]["last_seen"]) == (101.1, 104.0)
    assert api.post("/capture/import", content=base + record(101, 1_000_000)).status_code == 422
    nano = b"\x4d\x3c\xb2\xa1" + base[4:]
    assert api.post("/capture/import", content=nano + record(101, 1_000_000_000)).status_code == 422
    assert api.post("/capture/import", content=nano + record(101, 900_000_000)).status_code == 200
    assert api.get("/capture/analysis?start=101.9&end=102").json()["total"] == 1


def test_quiet_windows_inside_live_session_differ_from_no_session(api, monkeypatch):
    from types import SimpleNamespace

    clock = 2_000_000_000
    monkeypatch.setattr(packets, "time", SimpleNamespace(time=lambda: clock))
    cap = api.app.state.capture
    data = Observations({"192.0.2.1"})
    observed = Ether(bytes(frame(IP(src="192.0.2.1", dst="192.0.2.2") / UDP())))
    observed.time = 103.75
    data.add(observed)
    cap.source, cap.interface, cap.started_at, cap.data = "live", "lab", 100.0, data
    # The only packet is in second 103. The same adapter was actively observing
    # the intervals immediately before and after that packet.
    cap.worker = object()
    try:
        for a, b in [(100, 101), (105, 106)]:
            report = api.get(
                "/capture/analysis",
                params={"scope": "history", "interface": "lab", "start": a, "end": b},
            ).json()
            assert (
                report["session_count"] == 1 and report["status"] == "empty" and report["total"] is None
            )
            assert "存在实时抓包会话" in report["message"]
        assert (
            api.get("/capture/analysis?scope=history&interface=lab&start=90&end=100").json()[
                "session_count"
            ]
            == 0
        )
    finally:
        cap.worker = None
    # Preserve the actual stop time even if an errored capture was only saved later.
    cap.ended_at = 108.0
    cap.session_id = cap._persist(data, "live", "lab", 100.0, "udp", ended=cap.ended_at)
    for scope in ["current", "history"]:
        base = {"scope": scope, "interface": "lab"}
        during = api.get("/capture/analysis", params={**base, "start": 106, "end": 107}).json()
        assert during["session_count"] == 1 and during["session_ids"] == [cap.session_id]
        assert during["total"] is None
        after = api.get("/capture/analysis", params={**base, "start": 108, "end": 109}).json()
        assert (
            after["session_count"] == 0
            and after["source"] is None
            and "没有匹配的抓包会话" in after["message"]
        )
        assert (
            api.get("/capture/analysis", params={**base, "start": 103, "end": 104}).json()["total"] == 1
        )
    saved = api.get("/capture/history").json()[0]
    assert saved["ended_at"] == 108 and saved["saved_at"] == clock and saved["expired_at"] is None
