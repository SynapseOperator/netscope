import asyncio
import threading
import time
from contextlib import closing
from http.client import HTTPConnection
from urllib.parse import urlsplit

import pytest
from sqlalchemy import create_engine, select

from netscope.peer import SIZE, PeerServer, signature
from netscope.speed import SpeedTest, endpoint, results


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
