import socket
import threading

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, insert

from netscope import peer, speed


def test_history_range_reaches_older_retained_tests(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'history.db'}")
    app = FastAPI()
    app.state.db = engine
    app.include_router(speed.router)
    speed.metadata.create_all(engine)
    with engine.begin() as db:
        db.execute(insert(speed.results), [{"at": float(t)} for t in range(150)])
    with TestClient(app) as client:
        latest = client.get("/speed/history").json()
        assert len(latest) == 100 and latest[-1]["at"] == 50
        selected = client.get("/speed/history?start=0&end=4").json()
        assert [r["at"] for r in selected] == [4, 3, 2, 1, 0]
        assert client.get("/speed/history?start=5&end=4").status_code == 422
    engine.dispose()


def test_idle_peer_connection_obeys_deadline(monkeypatch):
    monkeypatch.setattr(peer, "DEADLINE", 0.2)
    with peer.PeerServer(("127.0.0.1", 0), "test-pairing-key") as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with socket.create_connection(server.server_address, timeout=3) as idle:
                assert idle.recv(1) == b""
            # The connection deadline releases the worker even before a request arrives.
            with server.slots:
                assert server.slots.acquire(timeout=2), "expired connection still holds a peer slot"
                server.slots.release()
        finally:
            server.shutdown()
            worker.join(timeout=3)
