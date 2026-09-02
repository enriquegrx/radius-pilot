from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

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
    if operation == "invite-list":
        return {"ok": True, "invitations": []}
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
                "credential_scheme": "nt-hash",
                "access_policy": {"mode": "full", "rules": []},
                "access_summary": "Full access",
                "access_avpairs": [],
                "custom_access_eligible": True,
                "created_at": "2026-09-01T06:00:00+00:00",
                "updated_at": "2026-09-01T06:00:00+00:00",
            },
            {
                "username": "acl-user",
                "enabled": True,
                "duo_required": True,
                "effective_enabled": True,
                "effective_duo_required": True,
                "expires_at": "2026-09-03T06:00:00+00:00",
                "duo_bypass_until": None,
                "duo_bypass_reason": "",
                "last_auth": None,
                "panel_access": False,
                "duo_enrollment_active": False,
                "credential_scheme": "legacy-cleartext",
                "access_policy": {
                    "mode": "custom",
                    "rules": [
                        {
                            "destination": "192.168.50.112/32",
                            "protocol": "tcp",
                            "ports": [[443, 443]],
                        }
                    ],
                },
                "access_summary": "Custom · 1 destination · 1 service",
                "access_avpairs": [
                    "ipsec:route-set=prefix 192.168.50.112/32",
                    "ip:inacl#1=permit tcp any host 192.168.50.112 eq 443",
                    "ip:inacl#2=deny ip any any",
                ],
                "custom_access_eligible": True,
                "created_at": "2026-09-01T06:00:00+00:00",
                "updated_at": "2026-09-01T06:00:00+00:00",
            },
        ],
        "health": {
            "active": True,
            "config_valid": True,
            "duo_active": True,
            "nginx_active": True,
            "certificate": {"valid": True, "days_remaining": 89},
            "last_backup": {
                "name": "20260901T060000000000Z",
                "created_at": "2026-09-01T06:00:00+00:00",
                "user_count": 2,
            },
            "disk_free_mb": 4096,
        },
        "duo_enrollment_api": {
            "configured": False,
            "api_host": "",
            "ikey_hint": "",
        },
        "access_policy": {
            "custom_enabled": False,
            "avpair_forwarding": True,
            "gate_enabled": False,
            "allowed_destinations": ["192.0.2.0/24"],
            "objects": [
                {
                    "name": "core-dns",
                    "description": "Internal resolvers",
                    "rules": [
                        {
                            "destination": "192.0.2.53/32",
                            "protocol": "udp",
                            "ports": [[53, 53]],
                        }
                    ],
                    "summary": "Custom · 1 destination · 1 service",
                    "used_by": 2,
                }
            ],
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
    assert "data-row-action" in response.text
    assert "js-manage" not in response.text
    assert "dropdown-menu" not in response.text


def test_dashboard_shows_expandable_details_and_expiry_warning(monkeypatch) -> None:
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
    assert "user-detail-row" in response.text
    assert "Expires soon" in response.text
    assert "Expiring soon" in response.text
    assert "Legacy password" in response.text
    assert "deny ip any any" in response.text
    assert 'data-copy-text="acl-user"' in response.text
    assert "Access objects" in response.text
    assert "core-dns" in response.text
    assert "js-object-edit" in response.text
    assert "Duo enrollment API" in response.text
    assert "Not configured" in response.text
    assert "Setup readiness" in response.text
    assert "1 account still on legacy clear text" in response.text
    assert "RADIUS_ADMIN_CUSTOM_DACL_ENABLED=0" in response.text
    assert "Latest snapshot 2026-09-01 06:00 UTC" in response.text


def test_duo_enrollment_settings_endpoint_forwards_payload(monkeypatch) -> None:
    mutations = []

    def recording_helper(operation: str, payload=None):
        if operation == "set-duo-enroll-api":
            mutations.append(payload)
            return {"ok": True}
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", recording_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings/duo-enrollment",
        data={
            "csrf": csrf,
            "ikey": "DIABCDEFABCDEFABCDEF",
            "skey": "secret-key-value-that-never-renders",
            "api_host": "api-12345678.duosecurity.com",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert len(mutations) == 1
    assert mutations[0]["ikey"] == "DIABCDEFABCDEFABCDEF"
    assert mutations[0]["api_host"] == "api-12345678.duosecurity.com"
    assert "secret-key-value-that-never-renders" not in response.text


def test_access_object_endpoints_forward_payloads(monkeypatch) -> None:
    mutations = []

    def recording_helper(operation: str, payload=None):
        if operation in ("object-set", "object-delete"):
            mutations.append((operation, payload))
            return {"ok": True}
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", recording_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/access-objects",
        data={
            "csrf": csrf,
            "name": "core-dns",
            "description": "Internal resolvers",
            "object_rules": (
                '[{"destination":"192.0.2.53","protocol":"udp","ports":"53"},'
                '{"object":"other"}]'
            ),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    delete = client.post(
        "/access-objects/core-dns/delete", data={"csrf": csrf}, follow_redirects=False
    )
    assert delete.status_code == 303
    assert mutations[0][0] == "object-set"
    assert mutations[0][1]["name"] == "core-dns"
    assert mutations[0][1]["rules"][1] == {"object": "other"}
    assert mutations[1][0] == "object-delete"
    assert mutations[1][1]["name"] == "core-dns"


def _rich_list_payload() -> dict:
    """A maximally varied dashboard payload: custom + legacy + expiring +
    panel-admin + password-only users, backups present, objects present,
    enrollment configured. A render smoke test over this catches template
    bugs (bad slices, wrong types) regardless of the fake helper's happy path."""
    return {
        "ok": True,
        "users": [
            {
                "username": "custom-user",
                "enabled": True,
                "duo_required": True,
                "effective_enabled": True,
                "effective_duo_required": True,
                "expires_at": (datetime.now(UTC) + timedelta(days=3)).isoformat(
                    timespec="seconds"
                ),
                "duo_bypass_until": None,
                "duo_bypass_reason": "",
                "note": "Accounting laptop",
                "activates_at": None,
                "scheduled": False,
                "last_auth": {"status": "Allow", "timestamp": "2026-09-02T07:00:00+00:00"},
                "panel_access": True,
                "duo_enrollment_active": True,
                "credential_scheme": "nt-hash",
                "access_policy": {
                    "mode": "custom",
                    "rules": [
                        {"object": "core-dns"},
                        {"destination": "192.0.2.10/32", "protocol": "tcp", "ports": [[443, 443]]},
                    ],
                },
                "access_summary": "Custom · 2 destinations · 2 services",
                "access_avpairs": [
                    "ipsec:route-set=prefix 192.0.2.10/32",
                    "ip:inacl#1=permit tcp any host 192.0.2.10 eq 443",
                    "ip:inacl#2=deny ip any any",
                ],
                "session": {
                    "ip": "192.0.2.201",
                    "client_ip": "150.214.205.52",
                    "since": "2026-09-02T07:00:00+00:00",
                    "seconds": 3720,
                    "rx": "5.0 MB",
                    "tx": "1.0 MB",
                    "session_count": 2,
                    "sessions": [],
                },
                "connection_history": [
                    {
                        "session_id": "000010DA",
                        "ip": "192.0.2.201",
                        "since": "2026-09-02T07:00:00+00:00",
                        "seconds": 3720,
                        "rx": "5.0 MB",
                        "tx": "1.0 MB",
                        "active": True,
                        "ended_at": None,
                    }
                ],
                "custom_access_eligible": True,
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-09-01T00:00:00+00:00",
            },
            {
                "username": "legacy-user",
                "enabled": True,
                "duo_required": False,
                "effective_enabled": True,
                "effective_duo_required": False,
                "expires_at": None,
                "duo_bypass_until": "2026-09-05T00:00:00+00:00",
                "duo_bypass_reason": "Vendor maintenance window that is quite long indeed",
                "last_auth": None,
                "panel_access": False,
                "duo_enrollment_active": False,
                "credential_scheme": "legacy-cleartext",
                "access_policy": {"mode": "full", "rules": []},
                "access_summary": "Full access",
                "access_avpairs": [],
                "custom_access_eligible": False,
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-09-01T00:00:00+00:00",
            },
        ],
        "health": {
            "active": True,
            "config_valid": True,
            "duo_active": True,
            "nginx_active": True,
            "certificate": {"valid": True, "days_remaining": 12},
            "last_backup": {
                "name": "20260901T060000000000Z",
                "created_at": "2026-09-01T06:00:00+00:00",
                "user_count": 2,
            },
            "disk_free_mb": 512,
        },
        "online_count": 1,
        "concurrent_count": 1,
        "coa_enabled": True,
        "accounting_enabled": True,
        "duo_enrollment_api": {
            "configured": True,
            "api_host": "api-xxxxxxxx.duosecurity.com",
            "ikey_hint": "DIXX",
        },
        "access_policy": {
            "custom_enabled": True,
            "avpair_forwarding": True,
            "gate_enabled": True,
            "allowed_destinations": ["192.0.2.0/24"],
            "objects": [
                {
                    "name": "core-dns",
                    "description": "Internal resolvers",
                    "rules": [
                        {"destination": "192.0.2.53/32", "protocol": "udp", "ports": [[53, 53]]}
                    ],
                    "summary": "Custom · 1 destination · 1 service",
                    "used_by": 1,
                }
            ],
        },
    }


def test_dashboard_render_smoke(monkeypatch) -> None:
    def rich_helper(operation: str, payload=None):
        if operation == "authenticate-admin":
            return {"ok": True, "authenticated": True}
        if operation == "list":
            return _rich_list_payload()
        if operation == "audit":
            return {
                "ok": True,
                "events": [
                    {
                        "timestamp": f"2026-09-02T07:{index:02d}:00+00:00",
                        "actor": "admin",
                        "source_ip": "192.0.2.5",
                        "action": "reset-password",
                        "target": "custom-user",
                        "result": "success" if index % 2 else "failure",
                    }
                    for index in range(30)
                ],
                "auth_events": [
                    {
                        "timestamp": f"2026-09-02T06:{index:02d}:00+00:00",
                        "username": "custom-user",
                        "client_ip": "192.0.2.9",
                        "stage": "primary",
                        "status": "Allow" if index % 2 else "Deny",
                    }
                    for index in range(25)
                ],
            }
        if operation == "backups":
            return {
                "ok": True,
                "backups": [
                    {
                        "name": "20260901T060000000000Z",
                        "created_at": "2026-09-01T06:00:00+00:00",
                        "user_count": 2,
                    }
                ],
            }
        if operation == "invite-list":
            return {
                "ok": True,
                "invitations": [
                    {
                        "username": "pending-user",
                        "email": "p@example.test",
                        "status": "pending",
                        "expires_at": "2030-01-01T00:00:00+00:00",
                    }
                ],
            }
        if operation == "panel-status":
            return {"ok": True, "panel_access": True}
        raise AssertionError(f"unexpected helper operation {operation}")

    monkeypatch.setattr(app_module, "call_helper", rich_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    token = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"csrf": token, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    # Every section renders without a 500 across the varied data.
    for marker in (
        "custom-user",
        "legacy-user",
        "Legacy password",
        "Expires soon",
        "deny ip any any",
        "core-dns",
        "Setup readiness",
        "Latest snapshot",
        "pending-user",
        "reset-password",
        "Online now",
        'value="online"',
        'data-filter-online="online"',
        "Concurrent",
        "Recent connections",
        "5.0 MB",
        'data-row-action="disconnect"',
        'data-row-action="note"',
        'data-row-action="activation"',
        "Accounting laptop",
    ):
        assert marker in response.text, marker


def test_sessions_json_returns_online(monkeypatch) -> None:
    def online_helper(operation: str, payload=None):
        if operation == "list":
            data = fake_helper("list", payload)
            data["online_count"] = 1
            data["accounting_enabled"] = True
            data["concurrent_count"] = 0
            data["users"][0]["session"] = {"ip": "192.0.2.5", "session_count": 1}
            return data
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", online_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    token = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    client.post(
        "/login",
        data={"csrf": token, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    response = client.get("/sessions.json")
    assert response.status_code == 200
    body = response.json()
    assert body["online_count"] == 1
    assert body["accounting_enabled"] is True
    assert "vpn-test-user" in body["online"]


def test_sessions_json_requires_login() -> None:
    assert TestClient(app_module.app).get("/sessions.json").status_code == 401


def test_disconnect_route_forwards_to_helper(monkeypatch) -> None:
    calls = []

    def recording_helper(operation: str, payload=None):
        if operation == "disconnect":
            calls.append(payload)
            return {"ok": True, "disconnected": 2}
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", recording_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/users/demo-user/disconnect", data={"csrf": csrf}, follow_redirects=False
    )
    assert response.status_code == 303
    assert calls[0]["username"] == "demo-user"


def test_logout_survives_an_expired_csrf_token(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "call_helper", fake_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    response = client.post(
        "/logout", data={"csrf": "stale-or-wrong-token"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    # The session is gone: the dashboard now redirects back to login.
    after = client.get("/", follow_redirects=False)
    assert after.status_code == 303
    assert after.headers["location"].endswith("/login")


def test_access_object_export_and_import(monkeypatch) -> None:
    imports = []

    def recording_helper(operation: str, payload=None):
        if operation == "object-import":
            imports.append(payload)
            return {"ok": True, "imported": len(payload["objects"])}
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", recording_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    export = client.get("/access-objects/export")
    assert export.status_code == 200
    assert export.headers["content-disposition"].endswith('filename="access-objects.json"')
    exported = export.json()["access_objects"]
    assert exported[0]["name"] == "core-dns"
    assert "used_by" not in exported[0]

    imported = client.post(
        "/access-objects/import",
        data={"csrf": csrf, "objects_json": export.text},
        follow_redirects=False,
    )
    assert imported.status_code == 303
    assert imports[0]["objects"][0]["name"] == "core-dns"


def test_access_policy_endpoint_forwards_valid_rules(monkeypatch) -> None:
    mutations = []

    def recording_helper(operation: str, payload=None):
        if operation == "set-access-policy":
            mutations.append(payload)
            return {"ok": True}
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", recording_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/users/vpn-test-user/access",
        data={
            "csrf": csrf,
            "access_mode": "custom",
            "access_rules": (
                '[{"destination":"192.0.2.10/32","protocol":"tcp","ports":"443"}]'
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert len(mutations) == 1
    assert mutations[0]["username"] == "vpn-test-user"
    assert mutations[0]["_actor"] == "admin"
    assert mutations[0]["access_policy"] == {
        "mode": "custom",
        "rules": [
            {"destination": "192.0.2.10/32", "protocol": "tcp", "ports": "443"}
        ],
    }


def test_access_policy_endpoint_rejects_malformed_rules(monkeypatch) -> None:
    operations = []

    def recording_helper(operation: str, payload=None):
        operations.append(operation)
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", recording_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/users/vpn-test-user/access",
        data={"csrf": csrf, "access_mode": "custom", "access_rules": "{"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "The custom access rules are invalid." in response.text
    assert "set-access-policy" not in operations


def test_health_endpoint() -> None:
    response = TestClient(app_module.app).get("/healthz")
    assert response.json() == {"status": "ok"}


def test_invitation_page_never_exposes_existing_password(monkeypatch) -> None:
    def invitation_helper(operation: str, _payload=None):
        assert operation == "invite-status"
        return {
            "ok": True,
            "invitation": {
                "username": "new-user",
                "email": "new-user@example.test",
                "duo_required": True,
                "expires_at": "2030-01-01T00:00:00+00:00",
            },
        }

    monkeypatch.setattr(app_module, "call_helper", invitation_helper)
    response = TestClient(app_module.app).get("/invite/" + "A" * 43)
    assert response.status_code == 200
    assert "Welcome, new-user" in response.text
    assert "Choose your VPN password" in response.text
    assert "existing password" not in response.text


def test_created_invitation_shows_a_qr_code(monkeypatch) -> None:
    def creating_helper(operation: str, payload=None):
        if operation == "invite-create":
            return {
                "ok": True,
                "invitation": {
                    "token": "T" * 43,
                    "username": "new-user",
                    "email": "",
                    "expires_at": "2030-01-01T00:00:00+00:00",
                },
            }
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", creating_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    login_csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": login_csrf, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/invitations",
        data={"csrf": csrf, "username": "new-user"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert 'class="invitation-qr"' in response.text
    assert "data:image/svg+xml" in response.text
    # The one-time link is still shown as text alongside the QR.
    assert "/invite/" + "T" * 43 in response.text


def test_login_failure_uses_server_side_flash(monkeypatch) -> None:
    def rejecting_helper(operation: str, _payload=None):
        assert operation == "authenticate-admin"
        return {"ok": True, "authenticated": False}

    monkeypatch.setattr(app_module, "call_helper", rejecting_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    token = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"csrf": token, "username": "admin", "password": "wrong-password"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.history[0].headers["location"] == "/login"
    assert "Invalid credentials." in response.text


def test_enrollment_redirect_has_a_fixed_local_destination(monkeypatch) -> None:
    def enrollment_helper(operation: str, payload=None):
        if operation == "duo-enrollment":
            return {
                "ok": True,
                "enrollment": {
                    "username": payload["username"],
                    "activation_url": "https://example.duosecurity.com/activate",
                    "activation_barcode": "safe-barcode",
                    "expiration": 2_000_000_000,
                },
            }
        return fake_helper(operation, payload)

    monkeypatch.setattr(app_module, "call_helper", enrollment_helper)
    client = TestClient(app_module.app)
    login_page = client.get("/login")
    token = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    dashboard = client.post(
        "/login",
        data={"csrf": token, "username": "admin", "password": "test-password"},
        follow_redirects=True,
    )
    csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/users/vpn-test-user/duo-enrollment",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/duo-enrollment"
    enrollment = client.get("/duo-enrollment")
    assert enrollment.status_code == 200
    assert "vpn-test-user" in enrollment.text
