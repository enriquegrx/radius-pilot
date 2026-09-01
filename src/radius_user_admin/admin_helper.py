#!/usr/bin/python3
from __future__ import annotations

import argparse
import base64
import fcntl
import grp
import hashlib
import hmac
import json
import logging
import os
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import bcrypt

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{0,63}$")
CLEAR_AUTHORIZE_LINE = re.compile(
    r'^([a-z0-9][a-z0-9._@-]{0,63})\s+Cleartext-Password\s*:=\s*"((?:[^"\\]|\\.)*)"\s*$'
)
CRYPT_AUTHORIZE_LINE = re.compile(
    r'^([a-z0-9][a-z0-9._@-]{0,63})\s+Crypt-Password\s*:=\s*"([^"\\]+)"\s*$'
)
OPERATIONS = {
    "bootstrap",
    "list",
    "create",
    "rename",
    "reset-password",
    "set-enabled",
    "set-duo",
    "set-expiry",
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
ADMIN_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,63}$")
DEFAULT_AUTHORIZE_PATH = Path(
    os.environ.get(
        "RADIUS_ADMIN_AUTHORIZE_PATH",
        "/etc/freeradius/3.0/mods-config/files/vpn-users/authorize",
    )
)


class AdminError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


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


def hash_password(password: object) -> str:
    return bcrypt.hashpw(clean_password(password).encode(), bcrypt.gensalt(rounds=12)).decode()


def clean_password_hash(value: object) -> str:
    password_hash = str(value or "")
    if not re.fullmatch(r"\$2[aby]\$12\$[./A-Za-z0-9]{53}", password_hash):
        raise AdminError("The stored VPN password hash is invalid.")
    return password_hash


def password_matches(user: dict[str, Any], password: object) -> bool:
    supplied = str(password or "")
    if "password_hash" in user:
        try:
            return bcrypt.checkpw(
                supplied.encode(), clean_password_hash(user["password_hash"]).encode()
            )
        except (ValueError, TypeError):
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
        certificate_path: Path = Path("/etc/ssl/radius-user-admin/fullchain.pem"),
        enrollment_path: Path = Path("/var/lib/radius-user-admin/duo-enrollments.json"),
        invitation_path: Path = Path("/var/lib/radius-user-admin/invitations.json"),
        duo_enroll_config_path: Path = Path("/etc/radius-user-admin/duo-enroll-api.json"),
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
        self.certificate_path = certificate_path
        self.enrollment_path = enrollment_path
        self.invitation_path = invitation_path
        self.duo_enroll_config_path = duo_enroll_config_path
        self.runner = runner

    def bootstrap(self) -> None:
        if self.state_path.exists():
            raw = json.loads(self.state_path.read_text())
            migration_needed = any(
                any(
                    field not in user
                    for field in (
                        "duo_required",
                        "expires_at",
                        "duo_bypass_until",
                        "duo_bypass_reason",
                    )
                )
                for user in raw.get("users", [])
            )
            data = self.load()
            if migration_needed:
                self._atomic_json(data)
            return
        users = []
        for line in self.authorize_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            clear_match = CLEAR_AUTHORIZE_LINE.fullmatch(stripped)
            crypt_match = CRYPT_AUTHORIZE_LINE.fullmatch(stripped)
            if not clear_match and not crypt_match:
                raise AdminError("The existing authorize file contains an unmanaged entry.")
            stamp = now()
            credential = (
                {"password": decode_radius(clear_match.group(2))}
                if clear_match
                else {"password_hash": clean_password_hash(crypt_match.group(2))}
            )
            users.append(
                {
                    "username": (clear_match or crypt_match).group(1),
                    **credential,
                    "enabled": True,
                    "duo_required": True,
                    "expires_at": None,
                    "duo_bypass_until": None,
                    "duo_bypass_reason": "",
                    "created_at": stamp,
                    "updated_at": stamp,
                }
            )
        if not users:
            raise AdminError("The existing authorize file contains no users.")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_json({"version": 2, "users": users})

    def load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            raise AdminError("User state has not been bootstrapped.")
        data = json.loads(self.state_path.read_text())
        if data.get("version") not in {1, 2} or not isinstance(data.get("users"), list):
            raise AdminError("User state has an unsupported format.")
        for user in data["users"]:
            has_clear = "password" in user
            has_hash = "password_hash" in user
            if has_clear == has_hash:
                raise AdminError("Each user must have exactly one VPN credential.")
            if has_clear:
                clean_password(user["password"])
            else:
                clean_password_hash(user["password_hash"])
            user.setdefault("duo_required", True)
            user.setdefault("expires_at", None)
            user.setdefault("duo_bypass_until", None)
            user.setdefault("duo_bypass_reason", "")
        return data

    def public_list(self) -> dict[str, Any]:
        data = self.load()
        auth = self.last_authentication()
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
                    "created_at",
                    "updated_at",
                )
            }
            public["effective_enabled"] = self._effective_enabled(item)
            public["effective_duo_required"] = self._effective_duo_required(item)
            public["last_auth"] = auth.get(item["username"])
            public["panel_access"] = item["username"] in panel_admins
            public["duo_enrollment_active"] = item["username"] in active_enrollments
            public["credential_scheme"] = (
                "bcrypt" if "password_hash" in item else "legacy-cleartext"
            )
            users.append(public)
        return {"users": users, "health": self.health()}

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
    ) -> dict[str, Any]:
        clean = clean_username(username)
        clean_address = clean_email(email)
        require_duo = self._clean_bool(duo_required, "authentication mode")
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
            for key in ("username", "email", "duo_required", "expires_at")
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
            data["users"].append(
                {
                    "username": username,
                    "password_hash": hash_password(clean_password_value),
                    "enabled": True,
                    "duo_required": bool(invitation["duo_required"]),
                    "expires_at": None,
                    "duo_bypass_until": None,
                    "duo_bypass_reason": (
                        "" if invitation["duo_required"] else "Invitation bootstrap"
                    ),
                    "created_at": stamp,
                    "updated_at": stamp,
                }
            )
            data["version"] = 2
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

    def _load_invitations(self) -> dict[str, Any]:
        if not self.invitation_path.exists():
            return {"version": 1, "invitations": []}
        try:
            data = json.loads(self.invitation_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise AdminError("Invitation state is unavailable.") from exc
        if data.get("version") != 1 or not isinstance(data.get("invitations"), list):
            raise AdminError("Invitation state has an unsupported format.")
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
                if not duo_required and not reason:
                    raise AdminError("A reason is required for password-only access.")
                if not duo_required and bypass_until and is_past(bypass_until):
                    raise AdminError("The Duo bypass expiry must be in the future.")
                if expires_at and is_past(expires_at):
                    raise AdminError("The account expiry must be in the future.")
                users.append(
                    {
                        "username": username,
                        "password_hash": hash_password(payload.get("password")),
                        "enabled": True,
                        "duo_required": duo_required,
                        "expires_at": expires_at,
                        "duo_bypass_until": None if duo_required else bypass_until,
                        "duo_bypass_reason": "" if duo_required else reason,
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
                    user["password_hash"] = hash_password(payload.get("password"))
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

            data["version"] = 2
            self._commit(data, admin_data=admin_data)

    def migrate_passwords(self, username: object = None) -> list[str]:
        """Replace legacy clear-text VPN credentials with bcrypt hashes."""
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
                user["password_hash"] = hash_password(user.pop("password"))
                user["updated_at"] = now()
                migrated.append(user["username"])
            if not migrated:
                return []
            data["version"] = 2
            self._commit(data)
            return migrated

    def sync(self) -> None:
        """Render managed files from the current state without changing a user."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._commit(self.load())

    def reconcile(self) -> list[str]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return self._reconcile_locked()

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
        if changes:
            self._commit(data)
        return changes

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
        lines = ["# Generated by radius-user-admin. Do not edit by hand."]
        for user in sorted(data["users"], key=lambda item: item["username"]):
            if self._effective_enabled(user):
                if "password_hash" in user:
                    password_hash = clean_password_hash(user["password_hash"])
                    lines.append(f'{user["username"]} Crypt-Password := "{password_hash}"')
                else:
                    lines.append(
                        f'{user["username"]} Cleartext-Password := '
                        f'"{encode_radius(user["password"])}"'
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
        if data.get("version") not in {1, 2} or not isinstance(data.get("users"), list):
            raise AdminError("The backup contains unsupported user data.")
        for user in data["users"]:
            clean_username(user.get("username"))
            has_clear = "password" in user
            has_hash = "password_hash" in user
            if has_clear == has_hash:
                raise AdminError("The backup contains an invalid VPN credential.")
            if has_clear:
                clean_password(user.get("password"))
            else:
                clean_password_hash(user.get("password_hash"))
            user.setdefault("duo_required", True)
            user.setdefault("expires_at", None)
            user.setdefault("duo_bypass_until", None)
            user.setdefault("duo_bypass_reason", "")
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
        destination = self.backup_dir / stamp
        destination.mkdir(parents=True, exist_ok=False)
        old_state = self.state_path.read_bytes()
        old_authorize = self.authorize_path.read_bytes()
        old_duo = self.duo_config_path.read_bytes()
        old_admin = self.admin_path.read_bytes() if self.admin_path.exists() else None
        shutil.copy2(self.state_path, destination / "users.json")
        shutil.copy2(self.authorize_path, destination / "authorize")
        shutil.copy2(self.duo_config_path, destination / "authproxy.cfg")
        if old_admin is not None:
            shutil.copy2(self.admin_path, destination / "admins.json")
        new_duo = self._render_duo(old_duo.decode(), data)
        duo_changed = new_duo.encode() != old_duo
        self._atomic_json(data)
        self._atomic_write(self.authorize_path, self._render(data), 0o640)
        if admin_data is not None:
            self._write_admin_data(admin_data)
        candidate: Path | None = None
        try:
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
        target = str(payload.get("username") or payload.get("backup") or "")
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
        elif args.operation == "migrate-passwords":
            result = {"migrated": store.migrate_passwords(payload.get("username"))}
        elif args.operation == "invite-create":
            result = {
                "invitation": store.invite_create(
                    payload.get("username"),
                    payload.get("email"),
                    payload.get("duo_required"),
                    payload.get("valid_hours", 24),
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
        else:
            store.mutate(args.operation, payload)
            result = {}
        if args.operation in {
            "create",
            "rename",
            "reset-password",
            "set-enabled",
            "set-duo",
            "set-expiry",
            "delete",
            "restore",
            "set-admin-password",
            "set-panel-access",
            "duo-enroll",
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
