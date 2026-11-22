import asyncio
import threading
import time
from contextlib import closing
from http.client import HTTPConnection
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine, select

from netscope import peer as peer_module
from netscope import speed as speed_module
from netscope.peer import SIZE, PeerServer, signature
from netscope.speed import SpeedTest, Target, endpoint, results


@pytest.fixture
def peer():
    server = PeerServer(("127.0.0.1", 0), "fixture-pairing-key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(3)


def test_real_loopback_exchange(peer, tmp_path):
    path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{path}")
    test = SpeedTest(engine, lambda *_: None)
    asyncio.run(test.measure(peer, "fixture-pairing-key"))
    assert test.state["phase"] == "complete", test.state
    result = test.state["result"]
    assert result["scope"] == "loopback"
    assert min(result["latency_ms"], result["upload_mbps"], result["download_mbps"]) > 0
    engine.dispose()
    reopened = create_engine(f"sqlite:///{path}")
    with reopened.connect() as db:
        assert db.scalar(select(results.c.target)) == peer
    reopened.dispose()


def test_sustained_times_out_without_saving_partial_data(peer, monkeypatch, tmp_path):
    original_get = peer_module.PeerHandler.do_GET
    monkeypatch.setattr(peer_module, "DEADLINE", 0.3)

    def stalled(self):
        if self.path.startswith("/v2/download"):
            time.sleep(0.8)
        else:
            original_get(self)

    monkeypatch.setattr(peer_module.PeerHandler, "do_GET", stalled)
    engine = create_engine(f"sqlite:///{tmp_path / 'stalled.db'}")
    test = SpeedTest(engine, lambda *_: None)
    asyncio.run(test.measure(peer, "fixture-pairing-key", "sustained", 5))
    assert not test.state["running"] and test.state["phase"] == "error"
    assert test.state["error"] and test.state["result"] is None
    with engine.connect() as db:
        assert db.execute(select(results)).first() is None
    engine.dispose()


def test_peer_rejects_wrong_key_and_unbounded_body(peer, tmp_path):
    test = SpeedTest(create_engine(f"sqlite:///{tmp_path / 'peer.db'}"), lambda *_: None)
    asyncio.run(test.measure(peer, "incorrect-key"))
    assert test.state["phase"] == "error" and "密钥" in test.state["error"]
    stamp, nonce = str(int(time.time())), "0" * 32
    proof = signature("fixture-pairing-key", f"POST /v1/upload {stamp} {nonce}")
    with closing(HTTPConnection("127.0.0.1", urlsplit(peer).port, timeout=3)) as client:
        client.putrequest("POST", "/v1/upload")
        client.putheader("X-NetScope-Time", stamp)
        client.putheader("X-NetScope-Nonce", nonce)
        client.putheader("X-NetScope-Auth", proof)
        client.putheader("Content-Length", str(SIZE + 1))
        client.endheaders()
        assert client.getresponse().status == 413
    assert SIZE == 4 * 1024 * 1024


@pytest.mark.parametrize(
    "value",
    [
        "http://example.org",
        "http://127.0.0.1/x",
        "http://a:b@127.0.0.1",
        "http://0.0.0.0",
        "http://224.0.0.1",
        "ftp://127.0.0.1",
    ],
)
def test_endpoint_limits(value):
    with pytest.raises(ValueError):
        endpoint(value)


def test_repeated_measurement_records_variation(peer, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'repeated.db'}")
    test = SpeedTest(engine, lambda *_: None)
    asyncio.run(test.measure(peer, "fixture-pairing-key", "repeated"))
    assert test.state["phase"] == "complete", test.state
    result = test.state["result"]
    assert result["mode"] == "repeated" and result["rounds"] == 8
    assert result["download_cv_pct"] >= 0 and result["upload_cv_pct"] >= 0
    assert result["download_mbps"] > 0 and result["upload_mbps"] > 0
    with engine.connect() as db:
        row = db.execute(select(results)).mappings().one()
        assert row["rounds"] == 8 and row["mode"] == "repeated"
    engine.dispose()


def test_peer_rejects_replayed_signed_request(peer):
    stamp, nonce = str(int(time.time())), "f" * 32
    proof = signature("fixture-pairing-key", f"GET /v1/ping {stamp} {nonce}")
    with closing(HTTPConnection("127.0.0.1", urlsplit(peer).port, timeout=3)) as client:
        for expected in (200, 401):
            client.request(
                "GET",
                "/v1/ping",
                headers={
                    "X-NetScope-Time": stamp,
                    "X-NetScope-Nonce": nonce,
                    "X-NetScope-Auth": proof,
                },
            )
            answer = client.getresponse()
            assert answer.status == expected
            answer.read()


def test_sustained_streams_measure_actual_bytes_and_concurrent_rtt(peer, monkeypatch, tmp_path):
    # A deliberately slow fixture keeps network use small while real sockets remain
    # busy for the full five-second measurement in both directions.
    setup = peer_module.PeerHandler.setup

    def paced(self):
        setup(self)
        write, read = self.wfile.write, self.rfile.read

        def slow_write(data):
            if data is peer_module.WIRE_BLOCK:
                time.sleep(0.015)
            return write(data)

        def slow_read(size):
            if size == len(peer_module.BLOCK):
                time.sleep(0.015)
            return read(size)

        self.wfile.write, self.rfile.read = slow_write, slow_read

    monkeypatch.setattr(peer_module.PeerHandler, "setup", paced)
    engine = create_engine(f"sqlite:///{tmp_path / 'sustained.db'}")
    test = SpeedTest(engine, lambda *_: None)
    asyncio.run(test.measure(peer, "fixture-pairing-key", "sustained", 5))
    assert test.state["phase"] == "complete", test.state
    r = test.state["result"]
    assert r["mode"] == "sustained" and r["duration_s"] == 5 and not r["limit_reached"]
    assert r["started_at"] < r["ended_at"] == r["at"]
    for direction in ("download", "upload"):
        seconds, amount = r[direction + "_seconds"], r[direction + "_bytes"]
        assert 5 <= seconds < 15 and 0 < amount < speed_module.MAX_STREAM_BYTES
        segments = [s for s in r["segments"] if s["direction"] == direction]
        assert len(segments) >= 4
        assert sum(s["seconds"] for s in segments) == pytest.approx(seconds)
        assert sum(s["bytes"] for s in segments) == amount
        assert r[direction + "_mbps"] == pytest.approx(amount * 8 / seconds / 1e6)
        assert r[direction + "_cv_pct"] is not None
    assert r["loaded_samples"] >= 2 and r["loaded_latency_ms"] > 0
    assert r["latency_delta_ms"] == pytest.approx(r["loaded_latency_ms"] - r["latency_ms"])
    assert r["idle_jitter_ms"] >= 0 and r["loaded_jitter_ms"] >= 0
    with engine.connect() as db:
        assert db.scalar(select(results.c.segments)) == r["segments"]
    engine.dispose()


def test_duration_byte_cap_and_peer_limits(peer, monkeypatch, tmp_path):
    cap = 2 * 1024**2
    monkeypatch.setattr(peer_module, "MAX_STREAM_BYTES", cap)
    monkeypatch.setattr(speed_module, "MAX_STREAM_BYTES", cap)
    with pytest.raises(ValidationError):
        Target(target=peer, token="fixture-pairing-key", mode="sustained", duration_s=11)
    engine = create_engine(f"sqlite:///{tmp_path / 'limit.db'}")
    test = SpeedTest(engine, lambda *_: None)
    asyncio.run(test.measure(peer, "fixture-pairing-key", "sustained", 10))
    assert test.state["phase"] == "complete", test.state
    r = test.state["result"]
    assert r["duration_s"] == 10 and r["limit_reached"] is True
    assert r["download_bytes"] == r["upload_bytes"] == cap
    for path, expected in [("/v2/upload/10", 413), ("/v2/upload/60", 404)]:
        _, headers = speed_module.signed_headers("fixture-pairing-key", "POST", path)
        with closing(HTTPConnection("127.0.0.1", urlsplit(peer).port, timeout=3)) as client:
            client.request(
                "POST", path, b"10001\r\n", headers={**headers, "Transfer-Encoding": "chunked"}
            )
            assert client.getresponse().status == expected
    engine.dispose()


def test_cancel_and_older_peer_preserve_quick_mode(peer, monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'cancel.db'}")
    test = SpeedTest(engine, lambda *_: None)

    async def cancel_in_flight():
        test.start(peer, "fixture-pairing-key", "sustained", 10)
        with pytest.raises(HTTPException) as exc:
            test.start(peer, "fixture-pairing-key")
        assert exc.value.status_code == 409
        async with asyncio.timeout(4):
            while test.state["phase"] != "download":
                await asyncio.sleep(0.01)
        await test.close()
        assert test.state["phase"] == "cancelled" and not test.state["running"]
        assert test.state["result"] is None

    asyncio.run(cancel_in_flight())
    with engine.connect() as db:
        assert db.execute(select(results)).first() is None
    original = peer_module.PeerHandler.do_GET

    def old_peer(self):
        if self.path.startswith("/v2/"):
            self.reply(404)
        else:
            original(self)

    monkeypatch.setattr(peer_module.PeerHandler, "do_GET", old_peer)
    asyncio.run(test.measure(peer, "fixture-pairing-key", "sustained", 5))
    assert test.state["phase"] == "error" and "对端版本" in test.state["error"]
    asyncio.run(test.measure(peer, "fixture-pairing-key", "quick"))
    assert test.state["phase"] == "complete"
    assert test.state["result"]["loaded_latency_ms"] is None
    engine.dispose()
