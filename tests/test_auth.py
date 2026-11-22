import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from netscope.main import create_app

BASE = "http://127.0.0.1:8765"
CREDENTIALS = {"username": "operator", "password": "local-test-password"}


def test_access_and_restart(tmp_path):
    path = tmp_path / "workbench.db"
    with TestClient(create_app(path), base_url=BASE) as client:
        for route in ["/monitor", "/capture", "/speed", "/alerts", "/history.csv", "/connections"]:
            assert client.get("/api" + route).status_code == 401
        assert (
            client.post(
                "/api/auth/register", json=CREDENTIALS, headers={"origin": "https://example.org"}
            ).status_code
            == 403
        )
        assert client.get("/api/auth/me", headers={"host": "example.org"}).status_code == 400
        response = client.post("/api/auth/register", json=CREDENTIALS)
        assert response.status_code == 201
        assert "httponly" in response.headers["set-cookie"].lower()
        assert client.post("/api/auth/register", json=CREDENTIALS).status_code == 409
        assert client.get("/api/auth/me").json() == {"username": "operator"}
        with client.websocket_connect(
            "ws://127.0.0.1:8765/api/live",
            headers={"cookie": response.headers["set-cookie"].split(";")[0]},
        ) as ws:
            assert "interfaces" in ws.receive_json()
        client.post("/api/auth/logout").raise_for_status()
        assert client.get("/api/auth/me").status_code == 401
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("ws://127.0.0.1:8765/api/live"),
        ):
            pass
    with TestClient(create_app(path), base_url=BASE) as client:
        assert (
            client.post(
                "/api/auth/login", json={**CREDENTIALS, "password": "invalid-password"}
            ).status_code
            == 401
        )
        assert client.post("/api/auth/login", json=CREDENTIALS).status_code == 200
        assert client.get("/api/monitor").status_code == 200
        assert client.get("/api/missing").status_code == 404


def test_registration_requires_session_after_setup_and_limits_failed_logins(tmp_path):
    with TestClient(create_app(tmp_path / "secured.db"), base_url=BASE) as client:
        assert client.get("/api/auth/setup").json() == {"needs_initial_account": True}
        first = {"username": "secured-operator", "password": "long-enough-password"}
        second = {"username": "second-operator", "password": "second-long-password"}
        assert client.post("/api/auth/register", json=first).status_code == 201
        assert client.get("/api/auth/setup").json() == {"needs_initial_account": False}
        assert client.post("/api/auth/register", json=second).status_code == 201
        assert client.get("/api/auth/me").json()["username"] == first["username"]
        client.post("/api/auth/logout").raise_for_status()
        response = client.post(
            "/api/auth/register", json={"username": "stranger", "password": "password-123"}
        )
        assert response.status_code == 403
        for _ in range(6):
            response = client.post("/api/auth/login", json={**first, "password": "wrong-password"})
            assert response.status_code == 401
        blocked = client.post("/api/auth/login", json=first)
        assert blocked.status_code == 429 and blocked.headers["retry-after"] == "60"
