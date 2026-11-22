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
