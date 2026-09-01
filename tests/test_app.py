from __future__ import annotations

import os

os.environ["RADIUS_ADMIN_SECURE_COOKIE"] = "0"
os.environ["RADIUS_ADMIN_SESSION_SECRET"] = "test-session-secret-that-is-not-used-in-production"

from fastapi.testclient import TestClient

from radius_user_admin import app as app_module


def fake_helper(operation: str, _payload=None):
    assert operation == "list"
    return {
        "ok": True,
        "users": [
            {
                "username": "vpn-test-user",
                "enabled": True,
                "created_at": "2026-09-01T06:00:00+00:00",
                "updated_at": "2026-09-01T06:00:00+00:00",
            }
        ],
        "health": {"active": True, "config_valid": True},
    }


def test_dashboard_renders_user_without_password(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "call_helper", fake_helper)
    response = TestClient(app_module.app).get("/")
    assert response.status_code == 200
    assert "vpn-test-user" in response.text
    assert "FreeRADIUS healthy" in response.text
    assert "long-enough-password" not in response.text
    assert "js-manage" in response.text
    assert "dropdown-menu" not in response.text


def test_health_endpoint() -> None:
    response = TestClient(app_module.app).get("/healthz")
    assert response.json() == {"status": "ok"}
