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
                "users": [],
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
