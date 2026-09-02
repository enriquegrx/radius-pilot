#!/usr/bin/python3
from __future__ import annotations

import argparse
import base64
import fcntl
import grp
import gzip
import hashlib
import hmac
import json
import logging
import os
import pwd
import re
import secrets
import shutil
import smtplib
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from typing import Any

from radius_user_admin.access_policy import (
    DEFAULT_ALLOWED_DESTINATIONS,
    AccessPolicyError,
    access_summary,
    allowed_destinations,
    cisco_avpairs,
    clean_access_objects,
    clean_access_policy,
    clean_object_name,
    full_access_policy,
    resolved_policy,
)

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{0,63}$")
CLEAR_AUTHORIZE_LINE = re.compile(
    r'^([a-z0-9][a-z0-9._@-]{0,63})\s+Cleartext-Password\s*:=\s*"((?:[^"\\]|\\.)*)"\s*$'
)
NT_AUTHORIZE_LINE = re.compile(
    r"^([a-z0-9][a-z0-9._@-]{0,63})\s+NT-Password\s*:=\s*0x([0-9a-fA-F]{32})\s*$"
)
ACCESS_POLICY_LINE = re.compile(r"^# Access-Policy: ([A-Za-z0-9_-]+)$")
CISCO_AVPAIR_LINE = re.compile(
    r'^\s+Cisco-AVPair\s*\+=\s*"((?:[^"\\]|\\.)*)"\s*,?\s*$'
)
OPERATIONS = {
    "bootstrap",
    "list",
    "create",
    "rename",
    "reset-password",
    "set-enabled",
    "set-duo",
    "set-access-policy",
    "set-expiry",
    "object-set",
    "object-delete",
    "object-import",
    "delete",
    "sync",
    "reconcile",
    "authenticate-admin",
    "bootstrap-admin",
    "set-admin-password",
    "set-panel-access",
    "panel-status",
    "audit",
    "backups",
    "restore",
    "duo-check",
    "duo-enroll",
    "duo-enrollment",
    "set-duo-enroll-api",
    "session-history",
    "disconnect",
    "migrate-passwords",
    "invite-create",
    "invite-list",
    "invite-status",
    "invite-accept",
    "invite-revoke",
}
DUO_BEGIN = "# BEGIN RADIUS USER ADMIN EXEMPTIONS"
DUO_END = "# END RADIUS USER ADMIN EXEMPTIONS"
DUO_SECTION = "radius_server_auto"
BACKUP_NAME = re.compile(r"^(?:\d{8}T\d{12}Z|deploy-\d{8}T\d{6}Z)$")
AUDIT_ROTATE_LINES = 10000
AUDIT_ARCHIVES_KEPT = 6
BACKUPS_KEPT = 40
ADMIN_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,63}$")


def runtime_setting(name: str, default: str) -> str:
    if value := os.environ.get(name):
        return value
    environment_path = Path("/etc/radius-user-admin/environment")
    try:
        for line in environment_path.read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == name and value.strip():
                return value.strip()
    except OSError:
        pass
    return default


DEFAULT_AUTHORIZE_PATH = Path(
    runtime_setting(
        "RADIUS_ADMIN_AUTHORIZE_PATH",
        "/etc/freeradius/3.0/mods-config/files/vpn-users/authorize",
    )
)


class AdminError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def human_bytes(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{count} B"


def decode_radius(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def encode_radius(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def clean_username(value: object) -> str:
    username = str(value or "").strip().lower()
    if (
        not USERNAME.fullmatch(username)
        or username.count("@") > 1
        or username.endswith("@")
    ):
        raise AdminError(
            "Use 1–64 lowercase letters, numbers, dots, dashes, underscores, or one @ sign."
        )
    return username


def clean_password(value: object) -> str:
    password = str(value or "")
    if len(password) < 14 or len(password) > 128:
        raise AdminError("Passwords must contain between 14 and 128 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise AdminError("Passwords cannot contain control characters.")
    return password


def nt_password(password: object) -> str:
    """Return the MS-CHAPv2-compatible NT hash without exposing the secret in argv."""
    encoded = clean_password(password).encode("utf-16le")
    commands = (
        ["/usr/bin/openssl", "dgst", "-md4", "-binary"],
        ["/usr/bin/openssl", "dgst", "-provider", "legacy", "-md4", "-binary"],
    )
    for command in commands:
        result = subprocess.run(command, input=encoded, capture_output=True, check=False)
        if result.returncode == 0 and len(result.stdout) == 16:
            return result.stdout.hex()
    raise AdminError("This host cannot generate an MS-CHAPv2 credential safely.")


def clean_nt_password(value: object) -> str:
    password_hash = str(value or "").lower()
    if not re.fullmatch(r"[0-9a-f]{32}", password_hash):
        raise AdminError("The stored MS-CHAPv2 credential is invalid.")
    return password_hash


def password_matches(user: dict[str, Any], password: object) -> bool:
    supplied = str(password or "")
    if "nt_password" in user:
        try:
            return hmac.compare_digest(
                nt_password(supplied), clean_nt_password(user["nt_password"])
            )
        except (AdminError, ValueError, TypeError):
            return False
    return hmac.compare_digest(supplied, str(user.get("password") or ""))


def clean_optional_time(value: object, field: str) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdminError(f"Invalid {field}.") from exc
    if parsed.tzinfo is None:
        raise AdminError(f"{field.capitalize()} must include a timezone.")
    return parsed.astimezone(UTC).isoformat(timespec="seconds")


def is_past(value: str | None) -> bool:
    if not value:
        return False
    return datetime.fromisoformat(value).astimezone(UTC) <= datetime.now(UTC)


def clean_reason(value: object) -> str:
    reason = str(value or "").strip()
    if len(reason) > 160 or any(ord(char) < 32 for char in reason):
        raise AdminError("The reason must contain at most 160 printable characters.")
    return reason


def clean_email(value: object) -> str:
    email = str(value or "").strip().lower()
    if not email:
        return ""
    if (
        len(email) > 254
        or email.count("@") != 1
        or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", email)
        or email.endswith(".")
        or ".." in email
    ):
        raise AdminError("Enter a valid invitation email address.")
    return email


def clean_admin_username(value: object) -> str:
    username = str(value or "").strip().lower()
    if (
        not ADMIN_USERNAME.fullmatch(username)
        or username.count("@") > 1
        or username.endswith("@")
    ):
        raise AdminError("Invalid administrator username.")
    return username


def encode_access_policy(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_access_policy(value: str) -> object:
    if not value or len(value) > 8192:
        raise AdminError("The generated access policy metadata is invalid.")
    padding = "=" * (-len(value) % 4)
    try:
        payload = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        return json.loads(payload)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdminError("The generated access policy metadata is invalid.") from exc


class Store:
    def __init__(
        self,
        state_path: Path = Path("/var/lib/radius-user-admin/users.json"),
        authorize_path: Path = DEFAULT_AUTHORIZE_PATH,
        backup_dir: Path = Path("/var/backups/radius-user-admin"),
        lock_path: Path = Path("/run/lock/radius-user-admin.lock"),
        duo_config_path: Path = Path("/opt/duoauthproxy/conf/authproxy.cfg"),
        admin_path: Path = Path("/var/lib/radius-user-admin/admins.json"),
        audit_path: Path = Path("/var/lib/radius-user-admin/audit.jsonl"),
        auth_events_path: Path = Path("/opt/duoauthproxy/log/authevents.log"),
        accounting_detail_path: Path = Path(
            "/var/log/freeradius/radacct/radius-pilot-detail"
        ),
        certificate_path: Path = Path("/etc/ssl/radius-user-admin/fullchain.pem"),
        enrollment_path: Path = Path("/var/lib/radius-user-admin/duo-enrollments.json"),
        invitation_path: Path = Path("/var/lib/radius-user-admin/invitations.json"),
        duo_enroll_config_path: Path = Path("/etc/radius-user-admin/duo-enroll-api.json"),
        monitor_path: Path = Path("/var/lib/radius-user-admin/monitor.json"),
        policy_destinations: str | None = None,
        local_fallback_users: str | None = None,
        custom_dacl_enabled: bool | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.state_path = state_path
        self.authorize_path = authorize_path
        self.backup_dir = backup_dir
        self.lock_path = lock_path
        self.duo_config_path = duo_config_path
        self.admin_path = admin_path
        self.audit_path = audit_path
        self.auth_events_path = auth_events_path
        self.accounting_detail_path = accounting_detail_path
        self.certificate_path = certificate_path
        self.enrollment_path = enrollment_path
        self.invitation_path = invitation_path
        self.duo_enroll_config_path = duo_enroll_config_path
        self.monitor_path = monitor_path
        if policy_destinations is None:
            policy_destinations = runtime_setting(
                "RADIUS_ADMIN_POLICY_DESTINATIONS", DEFAULT_ALLOWED_DESTINATIONS
            )
        try:
            self.policy_destinations = allowed_destinations(policy_destinations)
        except AccessPolicyError as exc:
            raise AdminError(str(exc)) from exc
        if local_fallback_users is None:
            local_fallback_users = runtime_setting(
                "RADIUS_ADMIN_LOCAL_FALLBACK_USERS", ""
            )
        self.local_fallback_users = frozenset(
            clean_username(item)
            for item in local_fallback_users.split(",")
            if item.strip()
        )
        if custom_dacl_enabled is None:
            custom_dacl_enabled = runtime_setting(
                "RADIUS_ADMIN_CUSTOM_DACL_ENABLED", "0"
            ).casefold() in {"1", "true", "yes", "on"}
        self.custom_dacl_enabled = custom_dacl_enabled
        self.runner = runner

    def bootstrap(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                self._bootstrap_locked()
            except (AdminError, AccessPolicyError, OSError, json.JSONDecodeError):
                if self.authorize_path.exists():
                    self._fail_closed_authorize()
                raise

    def _bootstrap_locked(self) -> None:
        if self.state_path.exists():
            raw = json.loads(self.state_path.read_text())
            if not isinstance(raw, dict):
                raise AdminError("User state has an unsupported format.")
            migration_needed = raw.get("version") != 3 or any(
                any(
                    field not in user
                    for field in (
                        "duo_required",
                        "expires_at",
                        "duo_bypass_until",
                        "duo_bypass_reason",
                        "access_policy",
                    )
                )
                for user in raw.get("users", [])
            )
            data = self.load()
            if migration_needed:
                data["version"] = 3
                self._atomic_json(data)
            self._reconcile_locked()
            return
        users: list[dict[str, Any]] = []
        current_user: dict[str, Any] | None = None
        current_avpairs: list[str] = []
        pending_policy: object = None

        def finish_user() -> None:
            nonlocal current_user, current_avpairs
            if current_user is None:
                return
            expected = cisco_avpairs(
                current_user["access_policy"],
                destination_allowlist=self.policy_destinations,
            )
            if current_avpairs != expected:
                raise AdminError("The existing authorize file contains unmanaged attributes.")
            users.append(current_user)
            current_user = None
            current_avpairs = []

        for line in self.authorize_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            policy_match = ACCESS_POLICY_LINE.fullmatch(stripped)
            if policy_match:
                finish_user()
                pending_policy = decode_access_policy(policy_match.group(1))
                continue
            if stripped.startswith("#"):
                continue
            clear_match = CLEAR_AUTHORIZE_LINE.fullmatch(stripped)
            nt_match = NT_AUTHORIZE_LINE.fullmatch(stripped)
            avpair_match = CISCO_AVPAIR_LINE.fullmatch(line)
            if avpair_match:
                if current_user is None:
                    raise AdminError("The existing authorize file contains an unmanaged entry.")
                current_avpairs.append(decode_radius(avpair_match.group(1)))
                continue
            if not clear_match and not nt_match:
                raise AdminError("The existing authorize file contains an unmanaged entry.")
            finish_user()
            stamp = now()
            credential = (
                {"password": decode_radius(clear_match.group(2))}
                if clear_match
                else {"nt_password": clean_nt_password(nt_match.group(2))}
            )
            try:
                policy = clean_access_policy(
                    pending_policy,
                    destination_allowlist=self.policy_destinations,
                )
            except AccessPolicyError as exc:
                raise AdminError(str(exc)) from exc
            pending_policy = None
            current_user = {
                "username": (clear_match or nt_match).group(1),
                **credential,
                "enabled": True,
                "duo_required": True,
                "expires_at": None,
                "duo_bypass_until": None,
                "duo_bypass_reason": "",
                "access_policy": policy,
                "created_at": stamp,
                "updated_at": stamp,
            }
        finish_user()
        if pending_policy is not None:
            raise AdminError("The existing authorize file contains orphaned policy metadata.")
        if not users:
            raise AdminError("The existing authorize file contains no users.")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_json({"version": 3, "users": users})
        self._reconcile_locked()

    def load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            raise AdminError("User state has not been bootstrapped.")
        data = json.loads(self.state_path.read_text())
        if data.get("version") not in {1, 2, 3} or not isinstance(data.get("users"), list):
            raise AdminError("User state has an unsupported format.")
        legacy = data["version"] in {1, 2}
        try:
            objects = clean_access_objects(
                data.setdefault("access_objects", []),
                destination_allowlist=self.policy_destinations,
            )
        except AccessPolicyError as exc:
            raise AdminError(str(exc)) from exc
        data["access_objects"] = list(objects.values())
        for user in data["users"]:
            has_clear = "password" in user
            has_hash = "nt_password" in user
            if has_clear == has_hash:
                raise AdminError("Each user must have exactly one VPN credential.")
            if has_clear:
                clean_password(user["password"])
            else:
                clean_nt_password(user["nt_password"])
            if legacy:
                user.setdefault("duo_required", True)
                user.setdefault("expires_at", None)
                user.setdefault("duo_bypass_until", None)
                user.setdefault("duo_bypass_reason", "")
                user.setdefault("access_policy", full_access_policy())
            elif any(
                field not in user
                for field in (
                    "duo_required",
                    "expires_at",
                    "duo_bypass_until",
                    "duo_bypass_reason",
                    "access_policy",
                )
            ):
                raise AdminError("Version 3 user state is missing required security fields.")
            if not isinstance(user["access_policy"], dict):
                raise AdminError("The stored access policy is corrupt.")
            try:
                user["access_policy"] = clean_access_policy(
                    user["access_policy"],
                    destination_allowlist=self.policy_destinations,
                    objects=objects,
                )
            except AccessPolicyError as exc:
                raise AdminError(str(exc)) from exc
            try:
                cisco_avpairs(
                    user["access_policy"],
                    destination_allowlist=self.policy_destinations,
                    objects=objects,
                )
            except AccessPolicyError as exc:
                raise AdminError(str(exc)) from exc
            self._reject_local_fallback_policy(
                user["username"], user["access_policy"]
            )
        return data

    @staticmethod
    def _objects_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in data.get("access_objects", [])}

    @staticmethod
    def _referenced_objects(policy_rules: list[dict[str, Any]]) -> set[str]:
        return {entry["object"] for entry in policy_rules if "object" in entry}

    def public_list(self) -> dict[str, Any]:
        data = self.load()
        objects = self._objects_map(data)
        auth = self.last_authentication()
        sessions = self.active_sessions()
        connections = self.recent_connections(per_user=8)
        panel_admins = self.panel_admin_usernames()
        current_timestamp = int(datetime.now(UTC).timestamp())
        active_enrollments = {
            username
            for username, enrollment in self._load_enrollments().items()
            if int(enrollment.get("expiration") or 0) > current_timestamp
        }
        users = []
        for item in sorted(data["users"], key=lambda user: user["username"]):
            public = {
                key: item[key]
                for key in (
                    "username",
                    "enabled",
                    "duo_required",
                    "expires_at",
                    "duo_bypass_until",
                    "duo_bypass_reason",
                    "access_policy",
                    "created_at",
                    "updated_at",
                )
            }
            public["effective_enabled"] = self._effective_enabled(item)
            public["effective_duo_required"] = self._effective_duo_required(item)
            public["last_auth"] = auth.get(item["username"])
            public["session"] = sessions.get(item["username"])
            public["connection_history"] = connections.get(item["username"], [])
            public["panel_access"] = item["username"] in panel_admins
            public["duo_enrollment_active"] = item["username"] in active_enrollments
            public["credential_scheme"] = (
                "nt-hash" if "nt_password" in item else "legacy-cleartext"
            )
            public["access_summary"] = access_summary(
                item["access_policy"],
                destination_allowlist=self.policy_destinations,
                objects=objects,
            )
            public["access_avpairs"] = cisco_avpairs(
                item["access_policy"],
                destination_allowlist=self.policy_destinations,
                objects=objects,
            )
            public["custom_access_eligible"] = (
                item["username"] not in self.local_fallback_users
            )
            users.append(public)
        used_by: dict[str, int] = {name: 0 for name in objects}
        for item in data["users"]:
            for name in self._referenced_objects(item["access_policy"]["rules"]):
                used_by[name] += 1
        for definition in objects.values():
            for name in self._referenced_objects(definition["rules"]):
                used_by[name] += 1
        for invitation in self._load_invitations(objects=objects)["invitations"]:
            if invitation.get("used_at"):
                continue
            for name in self._referenced_objects(invitation["access_policy"]["rules"]):
                used_by[name] += 1
        return {
            "users": users,
            "health": self.health(),
            "online_count": len(sessions),
            "concurrent_count": sum(
                1 for entry in sessions.values() if entry.get("session_count", 1) > 1
            ),
            "coa_enabled": bool(
                runtime_setting("RADIUS_ADMIN_COA_TARGET", "").strip()
                and runtime_setting("RADIUS_ADMIN_COA_SECRET", "").strip()
            ),
            "accounting_enabled": self.accounting_detail_path.exists(),
            "duo_enrollment_api": self.duo_enroll_api_status(),
            "access_policy": {
                "custom_enabled": self._custom_dacl_ready(),
                "avpair_forwarding": self._duo_passes_cisco_avpair(),
                "gate_enabled": self.custom_dacl_enabled,
                "allowed_destinations": [item.with_prefixlen for item in self.policy_destinations],
                "objects": [
                    {
                        "name": definition["name"],
                        "description": definition["description"],
                        "rules": definition["rules"],
                        "summary": access_summary(
                            {"mode": "custom", "rules": definition["rules"]},
                            destination_allowlist=self.policy_destinations,
                            objects=objects,
                        ),
                        "used_by": used_by[definition["name"]],
                    }
                    for definition in objects.values()
                ],
            },
        }

    def invitation_list(self) -> list[dict[str, Any]]:
        current = datetime.now(UTC)
        invitations = []
        for invitation in self._load_invitations()["invitations"]:
            expires = datetime.fromisoformat(invitation["expires_at"]).astimezone(UTC)
            invitations.append(
                {
                    "username": invitation["username"],
                    "email": invitation.get("email", ""),
                    "duo_required": bool(invitation["duo_required"]),
                    "access_summary": access_summary(
                        invitation["access_policy"],
                        destination_allowlist=self.policy_destinations,
                    ),
                    "created_at": invitation["created_at"],
                    "expires_at": invitation["expires_at"],
                    "used_at": invitation.get("used_at"),
                    "status": (
                        "accepted"
                        if invitation.get("used_at")
                        else "expired"
                        if expires <= current
                        else "pending"
                    ),
                }
            )
        return sorted(invitations, key=lambda item: item["created_at"], reverse=True)

    def invite_create(
        self,
        username: object,
        email: object,
        duo_required: object,
        valid_hours: object = 24,
        access_policy: object = None,
    ) -> dict[str, Any]:
        clean = clean_username(username)
        clean_address = clean_email(email)
        require_duo = self._clean_bool(duo_required, "authentication mode")
        policy = self._clean_policy_for_assignment(access_policy, username=clean)
        try:
            hours = int(valid_hours)
        except (TypeError, ValueError) as exc:
            raise AdminError("Invitation lifetime must be a whole number of hours.") from exc
        if not 1 <= hours <= 168:
            raise AdminError("Invitation lifetime must be between 1 and 168 hours.")
        token = secrets.token_urlsafe(32)
        created = datetime.now(UTC)
        expires = datetime.fromtimestamp(created.timestamp() + hours * 3600, UTC)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if any(user["username"] == clean for user in self.load()["users"]):
                raise AdminError("That username already exists.")
            data = self._load_invitations()
            data["invitations"] = [
                invitation
                for invitation in data["invitations"]
                if invitation["username"] != clean or invitation.get("used_at")
            ]
            data["invitations"].append(
                {
                    "token_digest": self._invitation_digest(token),
                    "username": clean,
                    "email": clean_address,
                    "duo_required": require_duo,
                    "access_policy": policy,
                    "created_at": created.isoformat(timespec="seconds"),
                    "expires_at": expires.isoformat(timespec="seconds"),
                    "used_at": None,
                }
            )
            self._write_invitations(data)
        return {
            "token": token,
            "username": clean,
            "email": clean_address,
            "expires_at": expires.isoformat(timespec="seconds"),
        }

    def invite_status(self, token: object) -> dict[str, Any]:
        invitation = self._active_invitation(token)
        return {
            key: invitation[key]
            for key in (
                "username",
                "email",
                "duo_required",
                "access_policy",
                "expires_at",
            )
        }

    def invite_accept(self, token: object, password: object) -> dict[str, Any]:
        clean_password_value = clean_password(password)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            invitations = self._load_invitations()
            invitation = self._active_invitation(token, invitations)
            username = invitation["username"]
            data = self.load()
            if any(user["username"] == username for user in data["users"]):
                raise AdminError("That VPN account already exists.")
            stamp = now()
            access_policy = self._clean_policy_for_assignment(
                invitation.get("access_policy"),
                username=username,
                objects=self._objects_map(data),
            )
            data["users"].append(
                {
                    "username": username,
                    "nt_password": nt_password(clean_password_value),
                    "enabled": True,
                    "duo_required": bool(invitation["duo_required"]),
                    "expires_at": None,
                    "duo_bypass_until": None,
                    "duo_bypass_reason": (
                        "" if invitation["duo_required"] else "Invitation bootstrap"
                    ),
                    "access_policy": access_policy,
                    "created_at": stamp,
                    "updated_at": stamp,
                }
            )
            data["version"] = 3
            self._commit(data)
            invitation["used_at"] = stamp
            self._write_invitations(invitations)

        result: dict[str, Any] = {
            "username": username,
            "duo_required": bool(invitation["duo_required"]),
            "enrollment": None,
        }
        if invitation["duo_required"]:
            try:
                readiness = self.duo_check(username)
                if readiness["result"] == "enroll":
                    result["enrollment"] = self.duo_enroll(username)
                elif readiness["result"] != "auth" or not readiness["push_capable"]:
                    result["duo_warning"] = readiness["status"]
            except AdminError as exc:
                result["duo_warning"] = str(exc)
        return result

    def invite_revoke(self, username: object) -> None:
        clean = clean_username(username)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self._load_invitations()
            before = len(data["invitations"])
            data["invitations"] = [
                invitation
                for invitation in data["invitations"]
                if invitation["username"] != clean or invitation.get("used_at")
            ]
            if len(data["invitations"]) == before:
                raise AdminError("No pending invitation was found for that user.")
            self._write_invitations(data)

    def _load_invitations(
        self, objects: dict[str, dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        if not self.invitation_path.exists():
            return {"version": 2, "invitations": []}
        if objects is None:
            objects = self._objects_map(self.load())
        try:
            data = json.loads(self.invitation_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise AdminError("Invitation state is unavailable.") from exc
        if data.get("version") not in {1, 2} or not isinstance(
            data.get("invitations"), list
        ):
            raise AdminError("Invitation state has an unsupported format.")
        legacy = data["version"] == 1
        for invitation in data["invitations"]:
            if legacy:
                invitation.setdefault("access_policy", full_access_policy())
            elif "access_policy" not in invitation:
                raise AdminError(
                    "Version 2 invitation state is missing its access policy."
                )
            if invitation.get("used_at"):
                # Historical record only; it can never be accepted again, so a
                # policy that no longer validates must not poison the store.
                continue
            try:
                invitation["access_policy"] = clean_access_policy(
                    invitation["access_policy"],
                    destination_allowlist=self.policy_destinations,
                    objects=objects,
                )
                cisco_avpairs(
                    invitation["access_policy"],
                    destination_allowlist=self.policy_destinations,
                    objects=objects,
                )
            except AccessPolicyError as exc:
                raise AdminError(
                    f"Invitation for '{invitation.get('username')}': {exc}"
                ) from exc
            self._reject_local_fallback_policy(
                invitation["username"], invitation["access_policy"]
            )
        data["version"] = 2
        return data

    def _write_invitations(self, data: dict[str, Any]) -> None:
        self._atomic_write(self.invitation_path, json.dumps(data, indent=2) + "\n", 0o600)

    @staticmethod
    def _invitation_digest(token: object) -> str:
        value = str(token or "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", value):
            raise AdminError("The invitation link is invalid.")
        return hashlib.sha256(value.encode()).hexdigest()

    def _active_invitation(
        self, token: object, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        digest = self._invitation_digest(token)
        invitations = (data or self._load_invitations())["invitations"]
        invitation = next(
            (
                item
                for item in invitations
                if hmac.compare_digest(str(item.get("token_digest") or ""), digest)
            ),
            None,
        )
        if not invitation or invitation.get("used_at"):
            raise AdminError("The invitation is invalid or has already been used.")
        try:
            expires = datetime.fromisoformat(invitation["expires_at"]).astimezone(UTC)
        except (KeyError, TypeError, ValueError) as exc:
            raise AdminError("The invitation is invalid.") from exc
        if expires <= datetime.now(UTC):
            raise AdminError("The invitation has expired.")
        return invitation

    def health(self) -> dict[str, Any]:
        active = (
            self.runner(
                ["/usr/bin/systemctl", "is-active", "--quiet", "freeradius"],
                check=False,
                capture_output=True,
                text=True,
            ).returncode
            == 0
        )
        valid = (
            self.runner(
                ["/usr/sbin/freeradius", "-C", "-l", "stdout"],
                check=False,
                capture_output=True,
                text=True,
            ).returncode
            == 0
        )
        duo_active = (
            self.runner(
                ["/usr/bin/systemctl", "is-active", "--quiet", "duoauthproxy"],
                check=False,
                capture_output=True,
                text=True,
            ).returncode
            == 0
        )
        nginx_active = self._service_active("nginx")
        certificate = self._certificate_status()
        backups = self.list_backups(limit=1)
        disk_free_mb = shutil.disk_usage(self.state_path.parent).free // (1024 * 1024)
        return {
            "active": active,
            "config_valid": valid,
            "duo_active": duo_active,
            "nginx_active": nginx_active,
            "certificate": certificate,
            "last_backup": backups[0] if backups else None,
            "disk_free_mb": disk_free_mb,
        }

    def _service_active(self, service: str) -> bool:
        return (
            self.runner(
                ["/usr/bin/systemctl", "is-active", "--quiet", service],
                check=False,
                capture_output=True,
                text=True,
            ).returncode
            == 0
        )

    def _certificate_status(self) -> dict[str, Any]:
        result = self.runner(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(self.certificate_path),
                "-noout",
                "-enddate",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode or not result.stdout.startswith("notAfter="):
            return {"valid": False, "expires_at": None, "days_remaining": None}
        try:
            expires = datetime.strptime(
                result.stdout.strip().removeprefix("notAfter="), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=UTC)
        except ValueError:
            return {"valid": False, "expires_at": None, "days_remaining": None}
        days = int((expires - datetime.now(UTC)).total_seconds() // 86400)
        return {
            "valid": days >= 0,
            "expires_at": expires.isoformat(timespec="seconds"),
            "days_remaining": days,
        }

    def mutate(self, operation: str, payload: dict[str, Any]) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self.load()
            users = data["users"]
            username = clean_username(payload.get("username"))
            matches = [item for item in users if item["username"] == username]
            admin_data: dict[str, Any] | None = None

            if operation == "create":
                if matches:
                    raise AdminError("That username already exists.")
                stamp = now()
                duo_required = self._clean_bool(payload.get("duo_required"), "authentication mode")
                bypass_until = clean_optional_time(
                    payload.get("duo_bypass_until"), "Duo bypass expiry"
                )
                reason = clean_reason(payload.get("duo_bypass_reason"))
                expires_at = clean_optional_time(payload.get("expires_at"), "account expiry")
                access_policy = self._clean_policy_for_assignment(
                    payload.get("access_policy"),
                    username=username,
                    objects=self._objects_map(data),
                )
                if not duo_required and not reason:
                    raise AdminError("A reason is required for password-only access.")
                if not duo_required and bypass_until and is_past(bypass_until):
                    raise AdminError("The Duo bypass expiry must be in the future.")
                if expires_at and is_past(expires_at):
                    raise AdminError("The account expiry must be in the future.")
                users.append(
                    {
                        "username": username,
                        "nt_password": nt_password(payload.get("password")),
                        "enabled": True,
                        "duo_required": duo_required,
                        "expires_at": expires_at,
                        "duo_bypass_until": None if duo_required else bypass_until,
                        "duo_bypass_reason": "" if duo_required else reason,
                        "access_policy": access_policy,
                        "created_at": stamp,
                        "updated_at": stamp,
                    }
                )
                panel_access = self._clean_bool(payload.get("panel_access", False), "panel access")
                if panel_access:
                    if str(payload.get("panel_password") or "") == str(
                        payload.get("password") or ""
                    ):
                        raise AdminError("The console password must differ from the VPN password.")
                    readiness = self.duo_check(username)
                    if readiness["result"] != "auth" or not readiness["push_capable"]:
                        raise AdminError("Duo Push must be ready before granting panel access.")
                    admin_data = self._panel_access_data(
                        username, True, payload.get("panel_password")
                    )
            else:
                if not matches:
                    raise AdminError("User not found.")
                user = matches[0]
                if operation == "rename":
                    new_username = clean_username(payload.get("new_username"))
                    if any(item["username"] == new_username for item in users):
                        raise AdminError("That username already exists.")
                    self._reject_local_fallback_policy(
                        new_username, user["access_policy"]
                    )
                    user["username"] = new_username
                    user["updated_at"] = now()
                    if username in self.panel_admin_usernames():
                        readiness = self.duo_check(new_username)
                        if readiness["result"] != "auth" or not readiness["push_capable"]:
                            raise AdminError(
                                "Duo Push must be ready before renaming a panel administrator."
                            )
                        admin_data = self._rename_panel_admin(username, new_username)
                elif operation == "reset-password":
                    user["nt_password"] = nt_password(payload.get("password"))
                    user.pop("password", None)
                    user["updated_at"] = now()
                elif operation == "set-enabled":
                    enabled = self._clean_bool(payload.get("enabled"), "account status")
                    if not enabled and user["enabled"] and self._enabled_count(users) == 1:
                        raise AdminError(
                            "Add another enabled user before blocking the final account."
                        )
                    user["enabled"] = enabled
                    user["updated_at"] = now()
                elif operation == "set-duo":
                    duo_required = self._clean_bool(
                        payload.get("duo_required"), "authentication mode"
                    )
                    bypass_until = clean_optional_time(
                        payload.get("duo_bypass_until"), "Duo bypass expiry"
                    )
                    reason = clean_reason(payload.get("duo_bypass_reason"))
                    if not duo_required:
                        if not reason:
                            raise AdminError("A reason is required for password-only access.")
                        if bypass_until and is_past(bypass_until):
                            raise AdminError("The Duo bypass expiry must be in the future.")
                    user["duo_required"] = duo_required
                    user["duo_bypass_until"] = None if duo_required else bypass_until
                    user["duo_bypass_reason"] = "" if duo_required else reason
                    user["updated_at"] = now()
                elif operation == "set-expiry":
                    expires_at = clean_optional_time(payload.get("expires_at"), "account expiry")
                    if expires_at and is_past(expires_at):
                        raise AdminError("The account expiry must be in the future.")
                    user["expires_at"] = expires_at
                    user["updated_at"] = now()
                elif operation == "set-access-policy":
                    user["access_policy"] = self._clean_policy_for_assignment(
                        payload.get("access_policy"),
                        username=username,
                        objects=self._objects_map(data),
                    )
                    user["updated_at"] = now()
                elif operation == "delete":
                    if username in self.panel_admin_usernames():
                        raise AdminError("Revoke panel access before deleting this user.")
                    if user["enabled"] and self._enabled_count(users) == 1:
                        raise AdminError(
                            "Add another enabled user before deleting the final account."
                        )
                    users.remove(user)
                else:
                    raise AdminError("Unsupported operation.")

            data["version"] = 3
            self._commit(data, admin_data=admin_data)

    def mutate_objects(self, operation: str, payload: dict[str, Any]) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self.load()
            try:
                name = clean_object_name(payload.get("name"))
            except AccessPolicyError as exc:
                raise AdminError(str(exc)) from exc
            remaining = [
                item for item in data.get("access_objects", []) if item["name"] != name
            ]
            if operation == "object-set":
                candidate = remaining + [
                    {
                        "name": name,
                        "description": payload.get("description"),
                        "rules": payload.get("rules"),
                    }
                ]
                try:
                    objects = clean_access_objects(
                        candidate, destination_allowlist=self.policy_destinations
                    )
                except AccessPolicyError as exc:
                    raise AdminError(str(exc)) from exc
                data["access_objects"] = list(objects.values())
                for user in data["users"]:
                    try:
                        user["access_policy"] = clean_access_policy(
                            user["access_policy"],
                            destination_allowlist=self.policy_destinations,
                            objects=objects,
                        )
                        cisco_avpairs(
                            user["access_policy"],
                            destination_allowlist=self.policy_destinations,
                            objects=objects,
                        )
                    except AccessPolicyError as exc:
                        raise AdminError(
                            f"The change breaks the policy of '{user['username']}': {exc}"
                        ) from exc
                self._load_invitations(objects=objects)
            elif operation == "object-delete":
                if len(remaining) == len(data.get("access_objects", [])):
                    raise AdminError("Access object not found.")
                held_by = sorted(
                    {
                        user["username"]
                        for user in data["users"]
                        if name
                        in self._referenced_objects(user["access_policy"]["rules"])
                    }
                    | {
                        item["name"]
                        for item in remaining
                        if name in self._referenced_objects(item["rules"])
                    }
                    | {
                        invitation["username"]
                        for invitation in self._load_invitations(
                            objects=self._objects_map(data)
                        )["invitations"]
                        if not invitation.get("used_at")
                        and name
                        in self._referenced_objects(
                            invitation["access_policy"]["rules"]
                        )
                    }
                )
                if held_by:
                    raise AdminError(
                        "The access object is still in use by: " + ", ".join(held_by)
                    )
                data["access_objects"] = remaining
            else:
                raise AdminError("Unsupported operation.")
            data["version"] = 3
            self._commit(data)

    def import_objects(self, payload: dict[str, Any]) -> int:
        incoming = payload.get("objects")
        if not isinstance(incoming, list) or not incoming:
            raise AdminError("Provide a non-empty list of access objects to import.")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self.load()
            merged = {item["name"]: item for item in data.get("access_objects", [])}
            names: list[str] = []
            for raw in incoming:
                if not isinstance(raw, dict):
                    raise AdminError("Each imported object must be an object.")
                try:
                    name = clean_object_name(raw.get("name"))
                except AccessPolicyError as exc:
                    raise AdminError(str(exc)) from exc
                merged[name] = {
                    "name": name,
                    "description": raw.get("description"),
                    "rules": raw.get("rules"),
                }
                names.append(name)
            try:
                objects = clean_access_objects(
                    list(merged.values()), destination_allowlist=self.policy_destinations
                )
            except AccessPolicyError as exc:
                raise AdminError(str(exc)) from exc
            data["access_objects"] = list(objects.values())
            for user in data["users"]:
                try:
                    user["access_policy"] = clean_access_policy(
                        user["access_policy"],
                        destination_allowlist=self.policy_destinations,
                        objects=objects,
                    )
                    cisco_avpairs(
                        user["access_policy"],
                        destination_allowlist=self.policy_destinations,
                        objects=objects,
                    )
                except AccessPolicyError as exc:
                    raise AdminError(
                        f"The import breaks the policy of '{user['username']}': {exc}"
                    ) from exc
            self._load_invitations(objects=objects)
            data["version"] = 3
            self._commit(data)
        return len(names)

    def migrate_passwords(self, username: object = None) -> list[str]:
        """Replace legacy clear-text VPN credentials with MS-CHAPv2 NT hashes."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self.load()
            selected = clean_username(username) if username else None
            if selected and not any(user["username"] == selected for user in data["users"]):
                raise AdminError("User not found.")
            migrated = []
            for user in data["users"]:
                if "password" not in user or (selected and user["username"] != selected):
                    continue
                user["nt_password"] = nt_password(user.pop("password"))
                user["updated_at"] = now()
                migrated.append(user["username"])
            if not migrated:
                return []
            data["version"] = 3
            self._commit(data)
            return migrated

    def sync(self) -> None:
        """Render managed files from the current state without changing a user."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                data = self.load()
            except (AdminError, OSError, json.JSONDecodeError):
                self._fail_closed_authorize()
                raise
            self._commit(data)

    def reconcile(self) -> list[str]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                return self._reconcile_locked()
            except (AdminError, OSError, json.JSONDecodeError):
                self._fail_closed_authorize()
                raise

    def _fail_closed_authorize(self) -> None:
        old_authorize = self.authorize_path.read_bytes()
        emergency = (
            b"# Emergency fail-closed: RadiusPilot state requires operator review.\n"
        )
        if old_authorize == emergency:
            self._check(
                ["/usr/bin/systemctl", "is-active", "--quiet", "freeradius"],
                "FreeRADIUS is not active in fail-closed mode.",
            )
            return
        try:
            self._atomic_write(
                self.authorize_path,
                emergency.decode(),
                0o640,
            )
            os.chown(self.authorize_path, 0, grp.getgrnam("freerad").gr_gid)
            self._check(
                ["/usr/sbin/freeradius", "-C", "-l", "stdout"],
                "FreeRADIUS rejected the fail-closed configuration.",
            )
            self._check(
                ["/usr/bin/systemctl", "restart", "freeradius"],
                "FreeRADIUS could not enter fail-closed mode.",
            )
            self._check(
                ["/usr/bin/systemctl", "is-active", "--quiet", "freeradius"],
                "FreeRADIUS is not active in fail-closed mode.",
            )
        except Exception:
            self._atomic_write(self.authorize_path, old_authorize.decode(), 0o640)
            os.chown(self.authorize_path, 0, grp.getgrnam("freerad").gr_gid)
            self.runner(["/usr/bin/systemctl", "restart", "freeradius"], check=False)
            raise

    def _reconcile_locked(self) -> list[str]:
        data = self.load()
        changes = []
        for user in data["users"]:
            if user["enabled"] and is_past(user["expires_at"]):
                user["enabled"] = False
                user["updated_at"] = now()
                changes.append(f"expired account {user['username']}")
            if not user["duo_required"] and is_past(user["duo_bypass_until"]):
                user["duo_required"] = True
                user["duo_bypass_until"] = None
                user["duo_bypass_reason"] = ""
                user["updated_at"] = now()
                changes.append(f"expired Duo bypass {user['username']}")
        changes.extend(self._expiry_warnings(data))
        expected_authorize = self._render(data)
        managed_files_changed = expected_authorize.encode() != self.authorize_path.read_bytes()
        if changes or managed_files_changed:
            self._commit(data)
        if managed_files_changed:
            changes.append("reconciled managed RADIUS authorization")
        changes.extend(self._rotate_audit())
        changes.extend(self._prune_backups())
        changes.extend(self._health_alerts())
        return changes

    def _health_issues(self) -> list[tuple[str, str]]:
        try:
            threshold = int(runtime_setting("RADIUS_ADMIN_CERT_WARNING_DAYS", "21"))
        except ValueError:
            threshold = 21
        health = self.health()
        issues: list[tuple[str, str]] = []
        if not health["active"]:
            issues.append(("freeradius", "FreeRADIUS is not active."))
        if not health["config_valid"]:
            issues.append(("config", "The FreeRADIUS configuration does not validate."))
        if not health["duo_active"]:
            issues.append(("duo", "The Duo Authentication Proxy is not active."))
        if not health["nginx_active"]:
            issues.append(("nginx", "Nginx is not active."))
        certificate = health["certificate"]
        days = certificate.get("days_remaining")
        if not certificate.get("valid"):
            issues.append(("certificate", "The HTTPS certificate is invalid or unreadable."))
        elif days is not None and days <= threshold:
            issues.append(("certificate", f"The HTTPS certificate expires in {days} day(s)."))
        disk = health["disk_free_mb"]
        if disk is not None and disk < 512:
            issues.append(("disk", f"Low disk space: {disk} MiB free."))
        return issues

    def _health_alerts(self) -> list[str]:
        recipient = runtime_setting("RADIUS_ADMIN_ADMIN_EMAIL", "").strip()
        host = runtime_setting("RADIUS_ADMIN_SMTP_HOST", "").strip()
        if not recipient or not host:
            return []
        issues = self._health_issues()
        current = sorted(key for key, _ in issues)
        try:
            previous = json.loads(self.monitor_path.read_text()).get("alerted", [])
        except (OSError, json.JSONDecodeError):
            previous = []
        if current == sorted(previous):
            return []
        if issues:
            subject = "RadiusPilot: service needs attention"
            body = "\n".join(
                ["RadiusPilot detected problems with the authentication service:", "",
                 *(f"- {message}" for _, message in issues), "",
                 "Check the System tab in the console."]
            )
            summary = f"health alert: {len(issues)} issue(s)"
        else:
            subject = "RadiusPilot: service recovered"
            body = "The previously reported authentication service problems have cleared."
            summary = "health recovered"
        try:
            self._send_admin_email(recipient, subject, body)
        except (OSError, smtplib.SMTPException):
            return []
        try:
            self._atomic_write(
                self.monitor_path, json.dumps({"alerted": current}) + "\n", 0o600
            )
        except OSError:
            pass
        return [summary]

    def _send_admin_email(self, recipient: str, subject: str, body: str) -> None:
        host = runtime_setting("RADIUS_ADMIN_SMTP_HOST", "").strip()
        try:
            port = int(runtime_setting("RADIUS_ADMIN_SMTP_PORT", "587"))
        except ValueError:
            port = 587
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = runtime_setting(
            "RADIUS_ADMIN_SMTP_FROM", "RadiusPilot <radiuspilot@your-domain.com>"
        )
        message["To"] = recipient
        message.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if runtime_setting("RADIUS_ADMIN_SMTP_STARTTLS", "1") == "1":
                smtp.starttls(context=ssl.create_default_context())
            smtp_user = runtime_setting("RADIUS_ADMIN_SMTP_USERNAME", "")
            if smtp_user:
                smtp.login(smtp_user, runtime_setting("RADIUS_ADMIN_SMTP_PASSWORD", ""))
            smtp.send_message(message)

    def _expiry_warnings(self, data: dict[str, Any]) -> list[str]:
        recipient = runtime_setting("RADIUS_ADMIN_ADMIN_EMAIL", "").strip()
        host = runtime_setting("RADIUS_ADMIN_SMTP_HOST", "").strip()
        if not recipient or not host:
            return []
        try:
            days = int(runtime_setting("RADIUS_ADMIN_EXPIRY_WARNING_DAYS", "7"))
        except ValueError:
            days = 7
        horizon = datetime.now(UTC) + timedelta(days=max(1, days))
        due = []
        for user in data["users"]:
            if not self._effective_enabled(user):
                continue
            raw = user.get("expires_at")
            if not raw or user.get("expiry_warned") == raw:
                continue
            try:
                expires = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= horizon:
                due.append(user)
        if not due:
            return []
        lines = [
            f"{len(due)} VPN account(s) expire within {days} day(s):",
            "",
            *(f"- {user['username']} expires {user['expires_at'][:16].replace('T', ' ')} UTC"
              for user in due),
            "",
            "Renew or remove them in the RadiusPilot console.",
        ]
        try:
            self._send_admin_email(
                recipient, "RadiusPilot: VPN accounts expiring soon", "\n".join(lines)
            )
        except (OSError, smtplib.SMTPException):
            return []
        stamp = now()
        for user in due:
            user["expiry_warned"] = user["expires_at"]
            user["updated_at"] = stamp
        return [f"warned about {len(due)} expiring account(s)"]

    def _rotate_audit(self) -> list[str]:
        # Maintenance must never take authentication down: swallow I/O errors.
        try:
            if not self.audit_path.exists():
                return []
            with self.audit_path.open("rb") as source:
                line_count = sum(1 for _ in source)
            if line_count <= AUDIT_ROTATE_LINES:
                return []
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            rotated = self.audit_path.with_name(f"audit-{stamp}.jsonl")
            archive = self.audit_path.with_name(f"audit-{stamp}.jsonl.gz")
            os.rename(self.audit_path, rotated)
            with rotated.open("rb") as source, gzip.open(archive, "wb") as target:
                shutil.copyfileobj(source, target)
            os.chmod(archive, 0o600)
            rotated.unlink()
            archives = sorted(self.audit_path.parent.glob("audit-*.jsonl.gz"))
            for old in archives[: max(0, len(archives) - AUDIT_ARCHIVES_KEPT)]:
                old.unlink()
            return [f"rotated audit log ({line_count} events archived)"]
        except OSError:
            return []

    def _prune_backups(self) -> list[str]:
        try:
            if not self.backup_dir.exists():
                return []
            snapshots = sorted(
                entry
                for entry in self.backup_dir.iterdir()
                if entry.is_dir() and BACKUP_NAME.fullmatch(entry.name)
            )
            excess = snapshots[: max(0, len(snapshots) - BACKUPS_KEPT)]
            for entry in excess:
                shutil.rmtree(entry)
            if not excess:
                return []
            return [f"pruned {len(excess)} old configuration backups"]
        except OSError:
            return []

    @staticmethod
    def _clean_bool(value: object, field: str) -> bool:
        if not isinstance(value, bool):
            raise AdminError(f"Invalid {field}.")
        return value

    @staticmethod
    def _enabled_count(users: list[dict[str, Any]]) -> int:
        return sum(bool(item["enabled"]) and not is_past(item.get("expires_at")) for item in users)

    @staticmethod
    def _effective_enabled(user: dict[str, Any]) -> bool:
        return bool(user["enabled"]) and not is_past(user.get("expires_at"))

    @staticmethod
    def _effective_duo_required(user: dict[str, Any]) -> bool:
        return bool(user["duo_required"]) or is_past(user.get("duo_bypass_until"))

    def _render(self, data: dict[str, Any]) -> str:
        objects = self._objects_map(data)
        lines = ["# Generated by radius-user-admin. Do not edit by hand."]
        for user in sorted(data["users"], key=lambda item: item["username"]):
            if self._effective_enabled(user):
                try:
                    policy = clean_access_policy(
                        user.get("access_policy"),
                        destination_allowlist=self.policy_destinations,
                        objects=objects,
                    )
                except AccessPolicyError as exc:
                    raise AdminError(str(exc)) from exc
                # Fail closed: if Duo can no longer forward the ACL, remove the
                # restricted account from RADIUS until reconciliation is healthy.
                if policy["mode"] == "custom" and not self._custom_dacl_ready():
                    continue
                # The comment stores the resolved rules so bootstrap recovery
                # never depends on the saved-object store being present.
                lines.append(
                    "# Access-Policy: "
                    f"{encode_access_policy(resolved_policy(policy, objects=objects))}"
                )
                if "nt_password" in user:
                    password_hash = clean_nt_password(user["nt_password"])
                    lines.append(f'{user["username"]} NT-Password := 0x{password_hash}')
                else:
                    lines.append(
                        f'{user["username"]} Cleartext-Password := '
                        f'"{encode_radius(user["password"])}"'
                    )
                attributes = cisco_avpairs(
                    policy,
                    destination_allowlist=self.policy_destinations,
                    objects=objects,
                )
                for index, attribute in enumerate(attributes):
                    suffix = "," if index < len(attributes) - 1 else ""
                    lines.append(
                        f'    Cisco-AVPair += "{encode_radius(attribute)}"{suffix}'
                    )
        return "\n".join(lines) + "\n"

    def _render_duo(self, original: str, data: dict[str, Any]) -> str:
        if original.count(DUO_BEGIN) != original.count(DUO_END):
            raise AdminError("The managed Duo exemption block is incomplete.")
        managed = re.compile(
            rf"\n?{re.escape(DUO_BEGIN)}.*?{re.escape(DUO_END)}\n?",
            re.DOTALL,
        )
        cleaned = managed.sub("\n", original).rstrip() + "\n"
        lines = cleaned.splitlines()
        section_start = next(
            (
                index
                for index, line in enumerate(lines)
                if line.strip().lower() == f"[{DUO_SECTION}]"
            ),
            None,
        )
        if section_start is None:
            raise AdminError("The Duo RADIUS server section was not found.")
        section_end = next(
            (
                index
                for index in range(section_start + 1, len(lines))
                if re.fullmatch(r"\s*\[[^]]+]\s*", lines[index])
            ),
            len(lines),
        )
        if any(
            re.match(r"\s*exempt_username_\d+\s*=", line, re.IGNORECASE)
            for line in lines[section_start + 1 : section_end]
        ):
            raise AdminError("Unmanaged Duo username exemptions require manual review.")
        exemptions = sorted(
            user["username"]
            for user in data["users"]
            if self._effective_enabled(user) and not self._effective_duo_required(user)
        )
        block = [DUO_BEGIN]
        block.extend(
            f"exempt_username_{index}={username}"
            for index, username in enumerate(exemptions, start=1)
        )
        block.append(DUO_END)
        insertion = [""] + block
        lines[section_end:section_end] = insertion
        return "\n".join(lines).rstrip() + "\n"

    def _duo_passes_cisco_avpair(self) -> bool:
        try:
            section = self._config_section(self.duo_config_path.read_text(), "radius_client")
        except OSError:
            return False
        if section.get("pass_through_all", "").casefold() in {"1", "true", "yes", "on"}:
            return True
        names = {
            item.strip().casefold()
            for item in section.get("pass_through_attr_names", "").split(",")
            if item.strip()
        }
        return "cisco-avpair" in names

    def _custom_dacl_ready(self) -> bool:
        return self.custom_dacl_enabled and self._duo_passes_cisco_avpair()

    def _reject_local_fallback_policy(
        self, username: str, policy: dict[str, Any]
    ) -> None:
        if policy["mode"] == "custom" and username in self.local_fallback_users:
            raise AdminError(
                "Custom access cannot be assigned to a router-local fallback account."
            )

    def _clean_policy_for_assignment(
        self,
        value: object,
        *,
        username: str | None = None,
        objects: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if objects is None:
            objects = self._objects_map(self.load())
        try:
            policy = clean_access_policy(
                value,
                destination_allowlist=self.policy_destinations,
                objects=objects,
            )
        except AccessPolicyError as exc:
            raise AdminError(str(exc)) from exc
        try:
            cisco_avpairs(
                policy,
                destination_allowlist=self.policy_destinations,
                objects=objects,
            )
        except AccessPolicyError as exc:
            raise AdminError(str(exc)) from exc
        if policy["mode"] == "custom" and not self._custom_dacl_ready():
            raise AdminError(
                "Custom access is disabled until Duo attribute forwarding and the IOS XE "
                "downloadable ACL capability have been validated."
            )
        if username is not None:
            self._reject_local_fallback_policy(username, policy)
        return policy

    def bootstrap_admin(self, username: object, password: object) -> None:
        if self.admin_path.exists():
            raise AdminError("An administrator account already exists.")
        admin = self._admin_record(clean_admin_username(username), clean_password(password))
        self._write_admin_data({"version": 1, "admins": [admin]})

    def set_admin_password(self, username: object, password: object) -> None:
        clean = clean_admin_username(username)
        data = self._load_admin_data()
        if not any(item["username"] == clean for item in data["admins"]):
            raise AdminError("Panel administrator not found.")
        data["admins"] = [
            self._admin_record(clean, clean_password(password))
            if item["username"] == clean
            else item
            for item in data["admins"]
        ]
        self._write_admin_data(data)

    @staticmethod
    def _admin_record(username: str, password: str) -> dict[str, Any]:
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return {
            "username": username,
            "salt": base64.b64encode(salt).decode(),
            "digest": base64.b64encode(digest).decode(),
            "duo_required": True,
            "updated_at": now(),
        }

    def _load_admin_data(self) -> dict[str, Any]:
        try:
            data = json.loads(self.admin_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise AdminError("Panel administrator state is unavailable.") from exc
        if data.get("version") != 1 or not isinstance(data.get("admins"), list):
            raise AdminError("Panel administrator state has an unsupported format.")
        return data

    def _write_admin_data(self, data: dict[str, Any]) -> None:
        self._atomic_write(self.admin_path, json.dumps(data, indent=2) + "\n", 0o600)

    def panel_admin_usernames(self) -> set[str]:
        if not self.admin_path.exists():
            return set()
        return {item["username"] for item in self._load_admin_data()["admins"]}

    def _panel_access_data(
        self, username: str, enabled: bool, password: object = None
    ) -> dict[str, Any]:
        data = self._load_admin_data()
        matches = [item for item in data["admins"] if item["username"] == username]
        if enabled:
            if matches:
                raise AdminError("That user already has panel access.")
            data["admins"].append(self._admin_record(username, clean_password(password)))
        else:
            if not matches:
                raise AdminError("That user does not have panel access.")
            if len(data["admins"]) == 1:
                raise AdminError(
                    "Grant panel access to another user before revoking the final administrator."
                )
            data["admins"] = [item for item in data["admins"] if item["username"] != username]
        return data

    def _rename_panel_admin(self, username: str, new_username: str) -> dict[str, Any]:
        data = self._load_admin_data()
        for admin in data["admins"]:
            if admin["username"] == username:
                admin["username"] = new_username
                admin["updated_at"] = now()
        return data

    def set_panel_access(self, username: object, enabled: object, password: object = None) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._set_panel_access_locked(username, enabled, password)

    def _set_panel_access_locked(
        self, username: object, enabled: object, password: object = None
    ) -> None:
        clean = clean_username(username)
        if not any(user["username"] == clean for user in self.load()["users"]):
            raise AdminError("User not found.")
        user = next(user for user in self.load()["users"] if user["username"] == clean)
        enabled_bool = self._clean_bool(enabled, "panel access")
        if enabled_bool and password_matches(user, password):
            raise AdminError("The console password must differ from the VPN password.")
        if enabled_bool:
            readiness = self.duo_check(clean)
            if readiness["result"] != "auth" or not readiness["push_capable"]:
                raise AdminError("Duo Push must be ready before granting panel access.")
        data = self._panel_access_data(clean, enabled_bool, password)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = self.backup_dir / stamp
        destination.mkdir(parents=True, exist_ok=False)
        shutil.copy2(self.state_path, destination / "users.json")
        shutil.copy2(self.authorize_path, destination / "authorize")
        shutil.copy2(self.duo_config_path, destination / "authproxy.cfg")
        shutil.copy2(self.admin_path, destination / "admins.json")
        self._write_admin_data(data)

    def authenticate_admin(self, username: object, password: object) -> bool:
        supplied_username = str(username or "").strip().lower()
        supplied_password = str(password or "")
        try:
            data = self._load_admin_data()
            admin = next(
                item for item in data.get("admins", []) if item["username"] == supplied_username
            )
            salt = base64.b64decode(admin["salt"], validate=True)
            expected = base64.b64decode(admin["digest"], validate=True)
        except (OSError, ValueError, KeyError, StopIteration, json.JSONDecodeError):
            salt, expected = bytes(16), bytes(32)
        actual = hashlib.scrypt(supplied_password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        password_valid = bool(supplied_username) and hmac.compare_digest(actual, expected)
        if not password_valid:
            return False
        if admin.get("duo_required", True):
            return self.duo_authenticate(supplied_username)
        return True

    def record_audit(
        self,
        *,
        actor: str,
        source_ip: str,
        action: str,
        target: str = "",
        result: str = "success",
        detail: str = "",
    ) -> None:
        event = {
            "timestamp": now(),
            "actor": str(actor or "unknown")[:64],
            "source_ip": str(source_ip or "unknown")[:64],
            "action": str(action)[:64],
            "target": str(target)[:64],
            "result": result if result in {"success", "failure"} else "failure",
            "detail": str(detail)[:240],
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        events = []
        for line in self.audit_path.read_text(errors="replace").splitlines()[-limit:]:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(event)
        return list(reversed(events))

    def last_authentication(self) -> dict[str, dict[str, Any]]:
        if not self.auth_events_path.exists():
            return {}
        latest: dict[str, dict[str, Any]] = {}
        lines = self.auth_events_path.read_text(errors="replace").splitlines()
        for line in reversed(lines[-2000:]):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            username = str(event.get("username") or "")
            if not username or username in latest:
                continue
            latest[username] = {
                "timestamp": event.get("timestamp"),
                "status": event.get("status"),
                "stage": event.get("auth_stage"),
                "client_ip": event.get("client_ip"),
                "message": str(event.get("msg") or "")[:120],
            }
        return latest

    def recent_authentication(self, limit: int = 25) -> list[dict[str, Any]]:
        if not self.auth_events_path.exists():
            return []
        events = []
        for line in reversed(self.auth_events_path.read_text(errors="replace").splitlines()):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not raw.get("username"):
                continue
            events.append(
                {
                    "timestamp": raw.get("timestamp"),
                    "username": raw.get("username"),
                    "status": raw.get("status"),
                    "stage": raw.get("auth_stage"),
                    "client_ip": raw.get("client_ip"),
                    "message": str(raw.get("msg") or "")[:120],
                }
            )
            if len(events) >= limit:
                break
        return events

    def _accounting_records(self) -> dict[str, dict[str, Any]]:
        """Latest accounting record per session id, parsed from the detail file.
        Returns {session_id: {stamp, status, username, attributes}}."""
        try:
            with self.accounting_detail_path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 1048576))
                text = handle.read().decode("utf-8", errors="replace")
        except OSError:
            return {}
        records: dict[str, dict[str, Any]] = {}
        for block in text.split("\n\n"):
            lines = [line for line in block.splitlines() if line.strip()]
            if not lines:
                continue
            attributes: dict[str, str] = {}
            for line in lines[1:]:
                key, separator, value = line.strip().partition("=")
                if not separator:
                    continue
                key = key.strip()
                value = value.strip().strip('"')
                if key == "Cisco-AVPair" and value.startswith("audit-session-id="):
                    attributes["audit-session-id"] = value.split("=", 1)[1]
                else:
                    attributes[key] = value
            session_id = attributes.get("Acct-Session-Id")
            if not session_id:
                continue
            try:
                stamp = datetime.strptime(lines[0].strip(), "%a %b %d %H:%M:%S %Y")
            except ValueError:
                stamp = None
            # Some identifying attributes (audit-session-id, NAS-IP, the client
            # address) only appear in the Start record; carry them forward so the
            # latest record still knows them.
            previous = records.get(session_id)
            if previous:
                for sticky in ("audit-session-id", "NAS-IP-Address", "Calling-Station-Id"):
                    if sticky not in attributes and sticky in previous["attributes"]:
                        attributes[sticky] = previous["attributes"][sticky]
            records[session_id] = {
                "stamp": stamp,
                "status": attributes.get("Acct-Status-Type", ""),
                "username": attributes.get("User-Name", ""),
                "attributes": attributes,
            }
        return records

    @staticmethod
    def _octets(attributes: dict[str, str], base: str) -> int:
        try:
            octets = int(attributes.get(f"Acct-{base}-Octets") or 0)
            octets += int(attributes.get(f"Acct-{base}-Gigawords") or 0) << 32
        except ValueError:
            return 0
        return octets

    def _session_view(self, session_id: str, record: dict[str, Any]) -> dict[str, Any]:
        attributes = record["attributes"]
        stamp = record["stamp"]
        try:
            seconds = int(attributes.get("Acct-Session-Time") or 0)
        except ValueError:
            seconds = 0
        rx = self._octets(attributes, "Output")
        tx = self._octets(attributes, "Input")
        return {
            "session_id": session_id,
            "ip": attributes.get("Framed-IP-Address", ""),
            "client_ip": attributes.get("Calling-Station-Id", ""),
            "nas_ip": attributes.get("NAS-IP-Address", ""),
            "audit_session_id": attributes.get("audit-session-id", ""),
            "since": stamp.isoformat() if stamp else None,
            "stamp": stamp,
            "seconds": seconds,
            "bytes_rx": rx,
            "bytes_tx": tx,
            "rx": human_bytes(rx),
            "tx": human_bytes(tx),
        }

    def active_sessions(self, now: datetime | None = None) -> dict[str, dict[str, Any]]:
        """Currently-online VPN sessions keyed by username. A session is online
        while its latest accounting record is not a Stop and is newer than the
        staleness window, so a lost Stop cannot pin a user online forever. Each
        entry carries the most recent session's fields plus session_count (for
        concurrency) and the full list of that user's active sessions."""
        if now is None:
            now = datetime.now()
        try:
            window = timedelta(
                seconds=int(runtime_setting("RADIUS_ADMIN_ACCT_STALE_SECONDS", "1800"))
            )
        except ValueError:
            window = timedelta(seconds=1800)
        by_user: dict[str, list[dict[str, Any]]] = {}
        for session_id, record in self._accounting_records().items():
            if record["status"] == "Stop":
                continue
            stamp = record["stamp"]
            if stamp is not None and now - stamp > window:
                continue
            username = record["username"]
            if not username:
                continue
            by_user.setdefault(username, []).append(self._session_view(session_id, record))
        online: dict[str, dict[str, Any]] = {}
        for username, sessions in by_user.items():
            sessions.sort(key=lambda item: item["stamp"] or datetime.min, reverse=True)
            primary = dict(sessions[0])
            primary["session_count"] = len(sessions)
            primary["sessions"] = [
                {key: value for key, value in item.items() if key != "stamp"}
                for item in sessions
            ]
            primary.pop("stamp", None)
            online[username] = primary
        return online

    def recent_connections(
        self, now: datetime | None = None, per_user: int = 10
    ) -> dict[str, list[dict[str, Any]]]:
        """Recent connections per user reconstructed from accounting in a single
        pass, newest first: start, end (or active), duration, IP and data usage."""
        if now is None:
            now = datetime.now()
        try:
            window = timedelta(
                seconds=int(runtime_setting("RADIUS_ADMIN_ACCT_STALE_SECONDS", "1800"))
            )
        except ValueError:
            window = timedelta(seconds=1800)
        grouped: dict[str, list[tuple[datetime, dict[str, Any]]]] = {}
        for session_id, record in self._accounting_records().items():
            username = record["username"]
            if not username:
                continue
            view = self._session_view(session_id, record)
            stopped = record["status"] == "Stop"
            stale = record["stamp"] is not None and now - record["stamp"] > window
            view["active"] = not stopped and not stale
            view["ended_at"] = view["since"] if stopped else None
            grouped.setdefault(username, []).append((record["stamp"] or datetime.min, view))
        result: dict[str, list[dict[str, Any]]] = {}
        for username, views in grouped.items():
            views.sort(key=lambda item: item[0], reverse=True)
            result[username] = [
                {key: value for key, value in view.items() if key != "stamp"}
                for _stamp, view in views[:per_user]
            ]
        return result

    def session_history(
        self, username: object, now: datetime | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        clean = clean_username(username)
        return self.recent_connections(now=now, per_user=limit).get(clean, [])

    def disconnect_session(self, username: object) -> int:
        """Ask the gateway to drop a user's live session(s) via RADIUS CoA
        (Disconnect-Request). Requires RADIUS_ADMIN_COA_TARGET and
        RADIUS_ADMIN_COA_SECRET, and dynamic-author configured on the gateway."""
        clean = clean_username(username)
        target = runtime_setting("RADIUS_ADMIN_COA_TARGET", "").strip()
        secret = runtime_setting("RADIUS_ADMIN_COA_SECRET", "").strip()
        if not target or not secret:
            raise AdminError("Session disconnect is not configured (RADIUS CoA).")
        sessions = self.active_sessions().get(clean, {}).get("sessions", [])
        if not sessions:
            raise AdminError("That account has no live session to disconnect.")
        disconnected = 0
        for session in sessions:
            # IOS XE matches the disconnect on the assigned Framed-IP-Address for
            # AnyConnect/FlexVPN sessions; adding other identifiers makes it NAK.
            if session.get("ip"):
                lines = [f'Framed-IP-Address = {session["ip"]}']
            elif session.get("audit_session_id"):
                lines = [f'Cisco-AVPair = "audit-session-id={session["audit_session_id"]}"']
            else:
                lines = [f'User-Name = "{clean}"']
            result = self.runner(
                ["/usr/bin/radclient", "-t", "5", "-r", "1", target, "disconnect", secret],
                input="\n".join(lines) + "\n",
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0 and "Disconnect-ACK" in (result.stdout or ""):
                disconnected += 1
        if not disconnected:
            raise AdminError("The gateway did not acknowledge the disconnect.")
        return disconnected

    def list_backups(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.backup_dir.exists():
            return []
        backups = []
        for path in sorted(self.backup_dir.iterdir(), reverse=True):
            if not path.is_dir() or not BACKUP_NAME.fullmatch(path.name):
                continue
            state = path / "users.json"
            try:
                data = json.loads(state.read_text())
                user_count = len(data.get("users", []))
            except (OSError, json.JSONDecodeError):
                user_count = None
            backups.append(
                {
                    "name": path.name,
                    "created_at": datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat(
                        timespec="seconds"
                    ),
                    "user_count": user_count,
                }
            )
            if len(backups) >= limit:
                break
        return backups

    def restore_backup(self, name: object) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._restore_backup_locked(name)

    def _restore_backup_locked(self, name: object) -> None:
        backup_name = str(name or "")
        if not BACKUP_NAME.fullmatch(backup_name):
            raise AdminError("Invalid backup identifier.")
        source = self.backup_dir / backup_name / "users.json"
        if not source.is_file():
            raise AdminError("Backup not found.")
        data = json.loads(source.read_text())
        if data.get("version") not in {1, 2, 3} or not isinstance(data.get("users"), list):
            raise AdminError("The backup contains unsupported user data.")
        legacy = data["version"] in {1, 2}
        try:
            backup_objects = clean_access_objects(
                data.setdefault("access_objects", []),
                destination_allowlist=self.policy_destinations,
            )
        except AccessPolicyError as exc:
            raise AdminError(str(exc)) from exc
        data["access_objects"] = list(backup_objects.values())
        for user in data["users"]:
            clean_username(user.get("username"))
            has_clear = "password" in user
            has_hash = "nt_password" in user
            if has_clear == has_hash:
                raise AdminError("The backup contains an invalid VPN credential.")
            if has_clear:
                clean_password(user.get("password"))
            else:
                clean_nt_password(user.get("nt_password"))
            if legacy:
                user.setdefault("duo_required", True)
                user.setdefault("expires_at", None)
                user.setdefault("duo_bypass_until", None)
                user.setdefault("duo_bypass_reason", "")
                user.setdefault("access_policy", full_access_policy())
            elif any(
                field not in user
                for field in (
                    "duo_required",
                    "expires_at",
                    "duo_bypass_until",
                    "duo_bypass_reason",
                    "access_policy",
                )
            ):
                raise AdminError("Version 3 backup is missing required security fields.")
            if not isinstance(user["access_policy"], dict):
                raise AdminError("The backup contains a corrupt access policy.")
            user["access_policy"] = self._clean_policy_for_assignment(
                user["access_policy"],
                username=user["username"],
                objects=backup_objects,
            )
        if not any(self._effective_enabled(user) for user in data["users"]):
            raise AdminError("The backup contains no enabled, unexpired users.")
        admin_source = source.parent / "admins.json"
        admin_data = json.loads(admin_source.read_text()) if admin_source.is_file() else None
        if admin_data is not None:
            if admin_data.get("version") != 1 or not admin_data.get("admins"):
                raise AdminError("The backup contains unsupported panel administrator data.")
            user_names = {user["username"] for user in data["users"]}
            if any(admin.get("username") not in user_names for admin in admin_data["admins"]):
                raise AdminError("The backup contains an orphaned panel administrator.")
        data["version"] = 3
        self._commit(data, admin_data=admin_data)

    def duo_check(self, username: object) -> dict[str, Any]:
        clean = clean_username(username)
        duo = self._duo_request("/auth/v2/preauth", {"username": clean}, timeout=10)
        devices = duo.get("devices", [])
        return {
            "username": clean,
            "result": duo.get("result", "unknown"),
            "status": str(duo.get("status_msg", "Unknown Duo status"))[:160],
            "device_count": len(devices) if isinstance(devices, list) else 0,
            "push_capable": any(
                "push" in device.get("capabilities", [])
                for device in devices
                if isinstance(device, dict)
            ),
        }

    def duo_authenticate(self, username: str) -> bool:
        duo = self._duo_request(
            "/auth/v2/auth",
            {"username": clean_username(username), "factor": "push", "device": "auto"},
            timeout=65,
        )
        return duo.get("result") == "allow"

    def duo_enroll(self, username: object, valid_secs: int = 604800) -> dict[str, Any]:
        clean = clean_username(username)
        if not any(user["username"] == clean for user in self.load()["users"]):
            raise AdminError("Create the local VPN user before enrolling it in Duo.")
        if not isinstance(valid_secs, int) or not 300 <= valid_secs <= 2592000:
            raise AdminError("Invalid Duo enrollment lifetime.")
        readiness = self.duo_check(clean)
        if readiness["result"] == "auth":
            raise AdminError("That user is already enrolled in Duo.")
        if readiness["result"] != "enroll":
            raise AdminError(f"Duo cannot enroll this user: {readiness['status']}")
        duo = self._duo_request(
            "/auth/v2/enroll",
            {"username": clean, "valid_secs": str(valid_secs)},
            timeout=15,
            error_message="Duo could not create the enrollment.",
            credentials=self._duo_enroll_credentials(),
        )
        if not isinstance(duo, dict):
            raise AdminError("Duo returned an invalid enrollment response.")
        enrollment = {
            "username": clean,
            "user_id": str(duo.get("user_id") or ""),
            "activation_url": self._validated_duo_url(duo.get("activation_url")),
            "activation_barcode": self._validated_duo_url(duo.get("activation_barcode")),
            "expiration": int(duo.get("expiration") or 0),
            "created_at": now(),
        }
        if not enrollment["user_id"] or enrollment["expiration"] <= int(
            datetime.now(UTC).timestamp()
        ):
            raise AdminError("Duo returned an incomplete enrollment response.")
        data = self._load_enrollments()
        data[clean] = enrollment
        self._atomic_write(
            self.enrollment_path,
            json.dumps({"version": 1, "enrollments": data}, indent=2) + "\n",
            0o600,
        )
        return enrollment

    def duo_enrollment(self, username: object) -> dict[str, Any]:
        clean = clean_username(username)
        enrollment = self._load_enrollments().get(clean)
        if not enrollment:
            raise AdminError("No active Duo enrollment was found for that user.")
        if int(enrollment.get("expiration") or 0) <= int(datetime.now(UTC).timestamp()):
            raise AdminError("The Duo enrollment has expired.")
        return enrollment

    def _load_enrollments(self) -> dict[str, Any]:
        if not self.enrollment_path.exists():
            return {}
        try:
            payload = json.loads(self.enrollment_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise AdminError("Duo enrollment state is unavailable.") from exc
        if payload.get("version") != 1 or not isinstance(payload.get("enrollments"), dict):
            raise AdminError("Duo enrollment state has an unsupported format.")
        return {
            username: enrollment
            for username, enrollment in payload["enrollments"].items()
            if isinstance(enrollment, dict)
        }

    @staticmethod
    def _validated_duo_url(value: object) -> str:
        url = str(value or "")
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not hostname.endswith(".duosecurity.com"):
            raise AdminError("Duo returned an invalid activation URL.")
        return url

    def _duo_request(
        self,
        path: str,
        parameters: dict[str, str],
        *,
        timeout: int,
        error_message: str = "Duo user readiness could not be checked.",
        credentials: dict[str, str] | None = None,
    ) -> Any:
        if credentials is None:
            config = self.duo_config_path.read_text()
            section = self._config_section(config, DUO_SECTION)
            required = {name: section.get(name, "") for name in ("ikey", "skey", "api_host")}
        else:
            required = credentials
        if not all(required.values()):
            raise AdminError("The Duo integration is incomplete.")
        params = urllib.parse.urlencode(sorted(parameters.items()))
        date = format_datetime(datetime.now(UTC), usegmt=True)
        canonical = "\n".join([date, "POST", required["api_host"].lower(), path, params])
        signature = hmac.new(
            required["skey"].encode(), canonical.encode(), hashlib.sha1
        ).hexdigest()
        authorization = base64.b64encode(f"{required['ikey']}:{signature}".encode()).decode()
        request = urllib.request.Request(
            f"https://{required['api_host']}{path}",
            data=params.encode(),
            headers={
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Date": date,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                payload = json.loads(response.read())
        except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            raise AdminError(error_message) from exc
        if payload.get("stat") != "OK":
            duo_message = str(payload.get("message") or error_message)[:160]
            raise AdminError(duo_message)
        return payload.get("response", {})

    def _duo_enroll_credentials(self) -> dict[str, str]:
        try:
            config = json.loads(self.duo_enroll_config_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise AdminError("The Duo enrollment integration is not configured.") from exc
        required = {
            name: str(config.get(name) or "").strip()
            for name in ("ikey", "skey", "api_host")
        }
        host = required["api_host"].lower()
        if not all(required.values()) or not host.endswith(".duosecurity.com"):
            raise AdminError("The Duo enrollment integration is invalid.")
        required["api_host"] = host
        return required

    def duo_enroll_api_status(self) -> dict[str, Any]:
        try:
            credentials = self._duo_enroll_credentials()
        except AdminError:
            return {"configured": False, "api_host": "", "ikey_hint": ""}
        return {
            "configured": True,
            "api_host": credentials["api_host"],
            "ikey_hint": credentials["ikey"][:4],
        }

    def set_duo_enroll_api(self, payload: dict[str, Any]) -> None:
        credentials = {
            name: str(payload.get(name) or "").strip()
            for name in ("ikey", "skey", "api_host")
        }
        credentials["api_host"] = credentials["api_host"].lower()
        if not all(credentials.values()) or any(
            len(value) > 128 for value in credentials.values()
        ):
            raise AdminError("Provide the integration key, secret key and API hostname.")
        if not re.fullmatch(r"api-[a-z0-9-]+\.duosecurity\.com", credentials["api_host"]):
            raise AdminError(
                "The API hostname must look like api-XXXXXXXX.duosecurity.com."
            )
        self._duo_request(
            "/auth/v2/check",
            {},
            timeout=10,
            error_message="Duo rejected the enrollment API credentials.",
            credentials=credentials,
        )
        self._atomic_write(
            self.duo_enroll_config_path,
            json.dumps(credentials, indent=2) + "\n",
            0o600,
        )

    @staticmethod
    def _config_section(config: str, name: str) -> dict[str, str]:
        values: dict[str, str] = {}
        active = False
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                active = stripped[1:-1].strip().lower() == name.lower()
                continue
            if active and stripped and not stripped.startswith("#") and "=" in stripped:
                key, value = stripped.split("=", 1)
                values[key.strip().lower()] = value.strip()
        return values

    def _atomic_json(self, data: dict[str, Any]) -> None:
        self._atomic_write(self.state_path, json.dumps(data, indent=2) + "\n", 0o600)

    @staticmethod
    def _atomic_write(path: Path, content: str, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _commit(self, data: dict[str, Any], *, admin_data: dict[str, Any] | None = None) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        old_state = self.state_path.read_bytes()
        old_authorize = self.authorize_path.read_bytes()
        old_duo = self.duo_config_path.read_bytes()
        old_admin = self.admin_path.read_bytes() if self.admin_path.exists() else None
        new_authorize = self._render(data)
        new_duo = self._render_duo(old_duo.decode(), data)
        duo_changed = new_duo.encode() != old_duo
        destination = self.backup_dir / stamp
        destination.mkdir(parents=True, exist_ok=False)
        shutil.copy2(self.state_path, destination / "users.json")
        shutil.copy2(self.authorize_path, destination / "authorize")
        shutil.copy2(self.duo_config_path, destination / "authproxy.cfg")
        if old_admin is not None:
            shutil.copy2(self.admin_path, destination / "admins.json")
        candidate: Path | None = None
        try:
            self._atomic_json(data)
            self._atomic_write(self.authorize_path, new_authorize, 0o640)
            if admin_data is not None:
                self._write_admin_data(admin_data)
            os.chown(self.authorize_path, 0, grp.getgrnam("freerad").gr_gid)
            if duo_changed:
                candidate = self.duo_config_path.parent / ".authproxy.cfg.candidate"
                self._atomic_write(candidate, new_duo, 0o600)
                os.chown(candidate, pwd.getpwnam("duo_authproxy_svc").pw_uid, 0)
                self._check(
                    [
                        "/opt/duoauthproxy/bin/authproxy_connectivity_tool",
                        "--no-explicit-connectivity-check",
                        "--config",
                        str(candidate),
                    ],
                    "Duo Authentication Proxy rejected the new configuration.",
                )
                self._atomic_write(self.duo_config_path, new_duo, 0o600)
                os.chown(
                    self.duo_config_path,
                    pwd.getpwnam("duo_authproxy_svc").pw_uid,
                    0,
                )
            self._check(
                ["/usr/sbin/freeradius", "-C", "-l", "stdout"],
                "FreeRADIUS rejected the new configuration.",
            )
            self._check(
                ["/usr/bin/systemctl", "restart", "freeradius"], "FreeRADIUS could not restart."
            )
            self._check(
                ["/usr/bin/systemctl", "is-active", "--quiet", "freeradius"],
                "FreeRADIUS is not active.",
            )
            if duo_changed:
                self._check(
                    ["/usr/bin/systemctl", "restart", "duoauthproxy"],
                    "Duo Authentication Proxy could not restart.",
                )
                self._check(
                    ["/usr/bin/systemctl", "is-active", "--quiet", "duoauthproxy"],
                    "Duo Authentication Proxy is not active.",
                )
        except Exception:
            self._atomic_write(self.state_path, old_state.decode(), 0o600)
            self._atomic_write(self.authorize_path, old_authorize.decode(), 0o640)
            self._atomic_write(self.duo_config_path, old_duo.decode(), 0o600)
            if old_admin is not None:
                self._atomic_write(self.admin_path, old_admin.decode(), 0o600)
            elif admin_data is not None:
                self.admin_path.unlink(missing_ok=True)
            os.chown(self.authorize_path, 0, grp.getgrnam("freerad").gr_gid)
            os.chown(
                self.duo_config_path,
                pwd.getpwnam("duo_authproxy_svc").pw_uid,
                0,
            )
            self.runner(["/usr/bin/systemctl", "restart", "freeradius"], check=False)
            if duo_changed:
                self.runner(["/usr/bin/systemctl", "restart", "duoauthproxy"], check=False)
            raise
        finally:
            if candidate is not None:
                candidate.unlink(missing_ok=True)

    def _check(self, command: list[str], message: str) -> None:
        result = self.runner(command, check=False, capture_output=True, text=True)
        if result.returncode:
            raise AdminError(message)


def ensure_caller() -> None:
    sudo_user = os.environ.get("SUDO_USER", "")
    if os.geteuid() != 0 or sudo_user != "radiusui":
        raise AdminError("The helper must be called by the radiusui service account.")
    if pwd.getpwnam(sudo_user).pw_uid == 0:
        raise AdminError("Invalid service account.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=sorted(OPERATIONS))
    args = parser.parse_args()
    store: Store | None = None
    payload: dict[str, Any] = {}
    try:
        ensure_caller()
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise AdminError("Invalid request.")
        store = Store()
        actor = str(payload.get("_actor") or "system")
        source_ip = str(payload.get("_source_ip") or "local")
        target = str(
            payload.get("username") or payload.get("backup") or payload.get("name") or ""
        )
        if args.operation == "bootstrap":
            store.bootstrap()
            result: dict[str, Any] = {}
        elif args.operation == "bootstrap-admin":
            store.bootstrap_admin(payload.get("username"), payload.get("password"))
            result = {}
        elif args.operation == "set-admin-password":
            store.set_admin_password(payload.get("username"), payload.get("password"))
            result = {}
        elif args.operation == "authenticate-admin":
            authenticated = store.authenticate_admin(
                payload.get("username"), payload.get("password")
            )
            store.record_audit(
                actor=str(payload.get("username") or "unknown"),
                source_ip=source_ip,
                action="administrator login",
                result="success" if authenticated else "failure",
                detail="Interactive console sign-in",
            )
            result = {"authenticated": authenticated}
        elif args.operation == "list":
            result = store.public_list()
        elif args.operation == "audit":
            result = {
                "events": store.audit_events(),
                "auth_events": store.recent_authentication(),
            }
        elif args.operation == "backups":
            result = {"backups": store.list_backups()}
        elif args.operation == "restore":
            store.restore_backup(payload.get("backup"))
            result = {}
        elif args.operation == "duo-check":
            result = {"duo": store.duo_check(payload.get("username"))}
        elif args.operation == "duo-enroll":
            result = {"enrollment": store.duo_enroll(payload.get("username"))}
        elif args.operation == "duo-enrollment":
            result = {"enrollment": store.duo_enrollment(payload.get("username"))}
        elif args.operation == "set-duo-enroll-api":
            store.set_duo_enroll_api(payload)
            result = {}
        elif args.operation == "session-history":
            result = {"history": store.session_history(payload.get("username"))}
        elif args.operation == "disconnect":
            result = {"disconnected": store.disconnect_session(payload.get("username"))}
        elif args.operation == "migrate-passwords":
            result = {"migrated": store.migrate_passwords(payload.get("username"))}
        elif args.operation == "invite-create":
            result = {
                "invitation": store.invite_create(
                    payload.get("username"),
                    payload.get("email"),
                    payload.get("duo_required"),
                    payload.get("valid_hours", 24),
                    payload.get("access_policy"),
                )
            }
        elif args.operation == "invite-list":
            result = {"invitations": store.invitation_list()}
        elif args.operation == "invite-status":
            result = {"invitation": store.invite_status(payload.get("token"))}
        elif args.operation == "invite-accept":
            result = {
                "invitation": store.invite_accept(
                    payload.get("token"), payload.get("password")
                )
            }
            target = result["invitation"]["username"]
        elif args.operation == "invite-revoke":
            store.invite_revoke(payload.get("username"))
            result = {}
        elif args.operation == "set-panel-access":
            store.set_panel_access(
                payload.get("username"),
                payload.get("enabled"),
                payload.get("panel_password"),
            )
            result = {}
        elif args.operation == "panel-status":
            username = str(payload.get("username") or "").strip().lower()
            result = {"panel_access": username in store.panel_admin_usernames()}
        elif args.operation == "sync":
            store.sync()
            result = {}
        elif args.operation == "reconcile":
            changes = store.reconcile()
            result = {"changes": changes}
        elif args.operation in {"object-set", "object-delete"}:
            store.mutate_objects(args.operation, payload)
            result = {}
        elif args.operation == "object-import":
            result = {"imported": store.import_objects(payload)}
        else:
            store.mutate(args.operation, payload)
            result = {}
        if args.operation in {
            "create",
            "rename",
            "reset-password",
            "set-enabled",
            "set-duo",
            "set-access-policy",
            "set-expiry",
            "object-set",
            "object-delete",
            "object-import",
            "delete",
            "restore",
            "set-admin-password",
            "set-panel-access",
            "duo-enroll",
            "set-duo-enroll-api",
            "disconnect",
            "migrate-passwords",
            "invite-create",
            "invite-accept",
            "invite-revoke",
            "reconcile",
        }:
            detail_items = (
                result.get("changes", [])
                if args.operation == "reconcile"
                else result.get("migrated", [])
                if args.operation == "migrate-passwords"
                else []
            )
            detail = ", ".join(detail_items)
            store.record_audit(
                actor=actor,
                source_ip=source_ip,
                action=args.operation,
                target=target,
                detail=detail,
            )
        logging.getLogger("radius-user-admin").info("operation=%s", args.operation)
        print(json.dumps({"ok": True, **result}))
        return 0
    except (AdminError, OSError, json.JSONDecodeError) as exc:
        if store is not None and args.operation not in {"list", "audit", "backups"}:
            try:
                store.record_audit(
                    actor=str(payload.get("_actor") or payload.get("username") or "system"),
                    source_ip=str(payload.get("_source_ip") or "local"),
                    action=args.operation,
                    target=str(payload.get("username") or payload.get("backup") or ""),
                    result="failure",
                    detail=str(exc),
                )
            except OSError:
                pass
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
