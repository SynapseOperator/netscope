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


def test_existing_speed_database_gets_optional_columns(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'older.db'}")
    with engine.begin() as db:
        db.exec_driver_sql(
            "CREATE TABLE speed_results (id INTEGER PRIMARY KEY, at FLOAT, target TEXT, "
            "scope TEXT, latency_ms FLOAT, download_mbps FLOAT, upload_mbps FLOAT)"
        )
        db.exec_driver_sql("INSERT INTO speed_results (at, target) VALUES (100, 'legacy-peer')")
    speed.SpeedTest(engine, lambda *_: None)
    with engine.connect() as db:
        columns = {row[1] for row in db.exec_driver_sql("PRAGMA table_info(speed_results)")}
        assert {"mode", "rounds", "download_cv_pct", "upload_cv_pct"} <= columns
        record = db.execute(speed.results.select()).mappings().one()
        assert record["target"] == "legacy-peer" and record["mode"] is None
        assert all(
            record[field] is None
            for field in (
                "interface",
                "started_at",
                "ended_at",
                "segments",
                "loaded_latency_ms",
                "loaded_samples",
                "duration_s",
                "limit_reached",
            )
        )
    engine.dispose()
