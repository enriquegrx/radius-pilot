from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "radius-pilot-geo-check"
SRC = Path(__file__).resolve().parent.parent / "src"


def _run(tmp_path, policy, username, ip):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    audit_path = tmp_path / "geo.log"
    env = {
        "RADIUS_ADMIN_APP_SOURCE": str(SRC),
        "RADIUS_ADMIN_GEO_POLICY_PATH": str(policy_path),
        "RADIUS_ADMIN_GEO_AUDIT_PATH": str(audit_path),
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(
        [sys.executable, str(SCRIPT), username, ip],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    log = []
    if audit_path.exists():
        log = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    return result, log


def test_enforce_rejects_disallowed_country(tmp_path) -> None:
    policy = {"mode": "enforce", "default": {"allowed": ["ES"], "fail_open": True}, "users": {}}
    result, log = _run(tmp_path, policy, "u", "8.8.8.8")  # US
    assert result.returncode == 0
    assert "Auth-Type := Reject" in result.stdout
    assert log[0]["blocked"] is True


def test_enforce_allows_permitted_country(tmp_path) -> None:
    policy = {"mode": "enforce", "default": {"allowed": ["ES"], "fail_open": True}, "users": {}}
    result, log = _run(tmp_path, policy, "u", "150.214.205.52")  # Granada, ES
    assert result.stdout.strip() == ""
    assert log[0]["decision"] == "allow"


def test_monitor_logs_but_never_rejects(tmp_path) -> None:
    policy = {"mode": "monitor", "default": {"allowed": ["ES"], "fail_open": True}, "users": {}}
    result, log = _run(tmp_path, policy, "u", "8.8.8.8")  # US would be blocked
    assert result.stdout.strip() == ""  # monitor never emits a reject
    assert log[0]["blocked"] is True  # but records what it would do
    assert log[0]["mode"] == "monitor"


def test_off_mode_does_nothing(tmp_path) -> None:
    policy = {"mode": "off", "default": {"allowed": ["ES"], "fail_open": True}, "users": {}}
    result, log = _run(tmp_path, policy, "u", "8.8.8.8")
    assert result.stdout.strip() == ""
    assert log == []


def test_private_ip_is_allowed_under_fail_open(tmp_path) -> None:
    policy = {"mode": "enforce", "default": {"allowed": ["ES"], "fail_open": True}, "users": {}}
    result, _ = _run(tmp_path, policy, "u", "10.0.0.5")
    assert result.stdout.strip() == ""


def test_per_user_override_is_used(tmp_path) -> None:
    policy = {
        "mode": "enforce",
        "default": {"allowed": ["ES", "US"], "fail_open": True},
        "users": {"eu-only": {"allowed": ["ES"], "fail_open": True}},
    }
    # default allows US, but the per-user override does not
    result, _ = _run(tmp_path, policy, "eu-only", "8.8.8.8")
    assert "Auth-Type := Reject" in result.stdout


def test_missing_policy_file_allows(tmp_path) -> None:
    audit = tmp_path / "geo.log"
    env = {
        "RADIUS_ADMIN_APP_SOURCE": str(SRC),
        "RADIUS_ADMIN_GEO_POLICY_PATH": str(tmp_path / "nope.json"),
        "RADIUS_ADMIN_GEO_AUDIT_PATH": str(audit),
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "u", "8.8.8.8"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""
