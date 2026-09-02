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
                        "note": "Accounting laptop",
                        "activates_at": None,
                        "scheduled": False,
                        "duo_enrollment_active": True,
                        "expires_at": None,
                        "panel_access": True,
                        "credential_scheme": "nt-hash",
                        "access_policy": {"mode": "full", "rules": []},
                        "access_summary": "Full access",
                        "access_avpairs": [],
                        "session": {
                            "ip": "192.0.2.201",
                            "client_ip": "150.214.205.52",
                            "since": "2026-09-02T07:00:00+00:00",
                            "seconds": 3720,
                            "bytes_rx": 5242880,
                            "bytes_tx": 1048576,
                            "rx": "5.0 MB",
                            "tx": "1.0 MB",
                            "session_count": 1,
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
                        "updated_at": "2026-01-01T00:00:00+00:00",
                        "last_auth": None,
                        "geo": {
                            "source": "default", "regions": ["EU_EEA"],
                            "countries_add": ["CH"], "countries_remove": [],
                            "fail_open": True, "allowed_count": 31,
                        },
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
                "concurrent_count": 0,
                "coa_enabled": True,
                "accounting_enabled": True,
                "duo_enrollment_api": {
                    "configured": True,
                    "api_host": "api-xxxxxxxx.duosecurity.com",
                    "ikey_hint": "DIXX",
                },
                "geo": {
                    "mode": "monitor",
                    "default": {
                        "source": "default", "regions": ["EU_EEA"], "countries_add": ["CH"],
                        "countries_remove": [], "fail_open": True, "allowed_count": 31,
                    },
                    "regions": {
                        "EU_EEA": {"label": "EU / EEA", "count": 30},
                        "SCHENGEN": {"label": "Schengen area", "count": 29},
                        "EUROPE": {"label": "Europe (incl. UK & Switzerland)", "count": 44},
                        "ES": {"label": "Spain only", "count": 1},
                    },
                },
                "access_policy": {
                    "custom_enabled": True,
                    "avpair_forwarding": True,
                    "gate_enabled": True,
                    "destinations_explicit": True,
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
elif sys.argv[1] == "dashboard":
    _curve = [0, 0, 0, 0, 1, 1, 2, 4, 7, 9, 8, 7, 6, 8, 9, 7, 5, 4, 3, 2, 2, 1, 1, 0]
    _hours = [f"{h:02d}:00" for h in range(24)]
    online_series = [{"hour": _hours[h], "count": _curve[h]} for h in range(24)]
    hourly = [0, 0, 0, 0, 1, 2, 4, 8, 14, 18, 16, 12, 10, 13, 17, 15, 11, 7, 5, 3, 2, 1, 1, 0]
    heatmap = [
        [hourly[h] // (2 if d >= 5 else 1) - (2 if d >= 5 else 0) for h in range(24)]
        for d in range(7)
    ]
    heatmap = [[max(0, v) for v in row] for row in heatmap]
    _daysessions = [12, 15, 9, 18, 22, 6, 4, 19, 24, 17, 21, 13, 20, 26]
    daily = [
        {
            "date": f"2026-08-{20 + i:02d}",
            "label": f"{20 + i} Aug",
            "sessions": _daysessions[i],
            "bytes": _daysessions[i] * 220_000_000,
        }
        for i in range(14)
    ]
    def _tl(user, a, b, live, usage):
        return {"user": user, "start_min": a, "end_min": b, "active": live, "usage": usage}

    timeline = [
        _tl("hola@quique.es", 420, 540, False, "3.1 MB"),
        _tl("contractor-eu", 480, 605, False, "812 KB"),
        _tl("hola@quique.es", 600, 843, True, "6.0 MB"),
        _tl("ops-madrid", 540, 720, False, "44 MB"),
        _tl("night-shift", 660, 843, True, "1.2 MB"),
        _tl("london-dev", 705, 843, True, "128 MB"),
    ]
    top_users = [
        {"user": "london-dev", "bytes": 3_100_000_000, "usage": "3.1 GB"},
        {"user": "ops-madrid", "bytes": 1_400_000_000, "usage": "1.4 GB"},
        {"user": "hola@quique.es", "bytes": 620_000_000, "usage": "620 MB"},
        {"user": "contractor-eu", "bytes": 210_000_000, "usage": "210 MB"},
        {"user": "night-shift", "bytes": 84_000_000, "usage": "84 MB"},
    ]
    def _pt(lat, lon, city, cc, name, count, users):
        return {
            "lat": lat, "lon": lon, "city": city, "country": cc,
            "country_name": name, "count": count, "users": users,
        }

    geo_points = [
        _pt(37.1773, -3.5986, "Granada", "ES", "Spain", 2, ["hola@quique.es", "night-shift"]),
        _pt(40.4168, -3.7038, "Madrid", "ES", "Spain", 1, ["ops-madrid"]),
        _pt(51.5074, -0.1278, "London", "GB", "United Kingdom", 1, ["london-dev"]),
        _pt(50.1109, 8.6821, "Frankfurt", "DE", "Germany", 1, ["contractor-eu"]),
        _pt(40.7128, -74.0060, "New York", "US", "United States", 1, ["us-east"]),
    ]
    print(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-09-02T14:03:00",
                "online_series": online_series,
                "hourly": hourly,
                "heatmap": heatmap,
                "daily": daily,
                "timeline": timeline,
                "top_users": top_users,
                "totals": {
                    "online": 6,
                    "concurrent": 1,
                    "sessions_today": 24,
                    "sessions_prev": 20,
                    "bytes_today": 5_400_000_000,
                    "bytes_prev": 4_100_000_000,
                    "usage_today": "5.4 GB",
                    "users_today": 9,
                },
                "geo": {
                    "points": geo_points,
                    "unresolved": 1,
                    "server": {"lat": 37.1773, "lon": -3.5986, "label": "Granada gateway"},
                },
                "health": {
                    "active": True,
                    "config_valid": True,
                    "duo_active": True,
                    "nginx_active": True,
                    "certificate": {"valid": True, "days_remaining": 89},
                    "last_backup": "2026-09-02T03:00:00",
                    "disk_free_mb": 4096,
                },
                "accounting_enabled": True,
                "coa_enabled": True,
            }
        )
    )
elif sys.argv[1] == "geo":
    def _ge(user, ip, country, name, city, decision, blocked, private=False):
        return {
            "username": user, "client_ip": ip, "country": country,
            "country_name": name, "city": city, "decision": decision,
            "blocked": blocked, "private": private, "policy_source": "default",
            "status": "Allow", "auth_stage": "Primary authentication",
            "timestamp": "2026-09-02T13:55:00",
        }

    print(
        json.dumps(
            {
                "ok": True,
                "mode": "monitor",
                "default": {
                    "source": "default", "regions": ["EU_EEA"], "countries_add": ["CH"],
                    "countries_remove": [], "fail_open": True, "allowed_count": 31,
                },
                "regions": {
                    "EU_EEA": "EU / EEA", "SCHENGEN": "Schengen area",
                    "EUROPE": "Europe (incl. UK & Switzerland)", "ES": "Spain only",
                },
                "events": [
                    _ge("hola@quique.es", "150.214.205.52", "ES", "Spain", "Granada", "allow", 0),
                    _ge("us-east", "8.8.8.8", "US", "United States", "Mountain View", "deny", True),
                    _ge("london-dev", "80.0.0.1", "GB", "UK", "London", "deny", True),
                    _ge("night-shift", "10.0.0.5", "", "", "", "unknown-allow", False, True),
                ],
                "online": [],
                "would_block_count": 2,
                "geoip_ready": True,
                "geolite_ready": True,
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
    print(json.dumps({"ok": True, "panel_access": True, "role": "admin"}))
else:
    print(json.dumps({"ok": True}))
