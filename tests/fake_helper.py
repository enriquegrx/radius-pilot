#!/usr/bin/env python3
import json
import sys

_payload = json.load(sys.stdin)
if sys.argv[1] == "authenticate-admin":
    print(json.dumps({"ok": True, "authenticated": True}))
elif sys.argv[1] == "list":
    print(
        json.dumps(
            {
                "ok": True,
                "users": [
                    {
                        "username": "demo-user",
                        "enabled": True,
                        "effective_enabled": True,
                        "duo_required": True,
                        "effective_duo_required": True,
                        "duo_bypass_until": None,
                        "duo_bypass_reason": "",
                        "duo_enrollment_active": True,
                        "expires_at": None,
                        "panel_access": True,
                        "credential_scheme": "nt-hash",
                        "access_policy": {"mode": "full", "rules": []},
                        "access_summary": "Full access",
                        "access_avpairs": [],
                        "session": {
                            "ip": "192.0.2.201",
                            "since": "2026-09-02T07:00:00+00:00",
                            "seconds": 3720,
                        },
                        "custom_access_eligible": True,
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                        "last_auth": None,
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
                "online_count": 1,
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
                                {
                                    "destination": "192.0.2.53/32",
                                    "protocol": "udp",
                                    "ports": [[53, 53]],
                                }
                            ],
                            "summary": "Custom · 1 destination · 1 service",
                            "used_by": 0,
                        }
                    ],
                },
            }
        )
    )
elif sys.argv[1] == "audit":
    print(json.dumps({"ok": True, "events": [], "auth_events": []}))
elif sys.argv[1] == "backups":
    print(json.dumps({"ok": True, "backups": []}))
elif sys.argv[1] == "invite-list":
    print(json.dumps({"ok": True, "invitations": []}))
elif sys.argv[1] == "invite-status":
    print(
        json.dumps(
            {
                "ok": True,
                "invitation": {
                    "username": "demo-user",
                    "email": "demo-user@example.test",
                    "duo_required": True,
                    "expires_at": "2030-01-01T00:00:00+00:00",
                },
            }
        )
    )
elif sys.argv[1] == "invite-accept":
    print(
        json.dumps(
            {
                "ok": True,
                "invitation": {
                    "username": "demo-user",
                    "duo_required": False,
                    "enrollment": None,
                },
            }
        )
    )
elif sys.argv[1] == "panel-status":
    print(json.dumps({"ok": True, "panel_access": True}))
else:
    print(json.dumps({"ok": True}))
