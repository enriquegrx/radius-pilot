from __future__ import annotations

import os

os.environ["RADIUS_ADMIN_SECURE_COOKIE"] = "0"
os.environ["RADIUS_ADMIN_SESSION_SECRET"] = "test-session-secret-that-is-not-used-in-production"

from fastapi.testclient import TestClient

from radius_user_admin import app as app_module


def fake_helper(operation: str, _payload=None):
    if operation == "authenticate-admin":
        return {"ok": True, "authenticated": True}
    if operation == "audit":
        return {"ok": True, "events": [], "auth_events": []}
    if operation == "backups":
        return {"ok": True, "backups": []}
    if operation == "panel-status":
        return {"ok": True, "panel_access": True}
    assert operation == "list"
    return {
        "ok": True,
        "users": [
            {
                "username": "vpn-test-user",
                "enabled": True,
                "duo_required": True,
                "effective_enabled": True,
                "effective_duo_required": True,
                "expires_at": None,
                "duo_bypass_until": None,
                "duo_bypass_reason": "",
                "last_auth": None,
                "panel_access": True,
                "duo_enrollment_active": False,
                "created_at": "2026-09-01T06:00:00+00:00",
                "updated_at": "2026-09-01T06:00:00+00:00",
            }
        ],
        "health": {
            "active": True,
            "config_valid": True,
            "duo_active": True,
            "nginx_active": True,
            "certificate": {"valid": True, "days_remaining": 89},
            "last_backup": None,
            "disk_free_mb": 4096,
        },
    }


def test_dashboard_renders_user_without_password(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "call_helper", fake_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    token = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"csrf": token, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "vpn-test-user" in response.text
    assert "Authentication healthy" in response.text
    assert "Duo Push" in response.text
    assert "long-enough-password" not in response.text
    assert "js-manage" in response.text
    assert "dropdown-menu" not in response.text


def test_health_endpoint() -> None:
    response = TestClient(app_module.app).get("/healthz")
    assert response.json() == {"status": "ok"}
