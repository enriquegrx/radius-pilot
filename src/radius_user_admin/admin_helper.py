#!/usr/bin/python3
from __future__ import annotations

import argparse
import fcntl
import grp
import json
import logging
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
AUTHORIZE_LINE = re.compile(
    r'^([a-z0-9][a-z0-9._-]{0,63})\s+Cleartext-Password\s*:=\s*"((?:[^"\\]|\\.)*)"\s*$'
)
OPERATIONS = {"bootstrap", "list", "create", "rename", "reset-password", "set-enabled", "delete"}


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
    if not USERNAME.fullmatch(username):
        raise AdminError("Use 1–64 lowercase letters, numbers, dots, dashes, or underscores.")
    return username


def clean_password(value: object) -> str:
    password = str(value or "")
    if len(password) < 14 or len(password) > 128:
        raise AdminError("Passwords must contain between 14 and 128 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise AdminError("Passwords cannot contain control characters.")
    return password


class Store:
    def __init__(
        self,
        state_path: Path = Path("/var/lib/radius-user-admin/users.json"),
        authorize_path: Path = Path(
            "/etc/freeradius/3.0/mods-config/files/vpn-users/authorize"
        ),
        backup_dir: Path = Path("/var/backups/radius-user-admin"),
        lock_path: Path = Path("/run/lock/radius-user-admin.lock"),
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.state_path = state_path
        self.authorize_path = authorize_path
        self.backup_dir = backup_dir
        self.lock_path = lock_path
        self.runner = runner

    def bootstrap(self) -> None:
        if self.state_path.exists():
            return
        users = []
        for line in self.authorize_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = AUTHORIZE_LINE.fullmatch(stripped)
            if not match:
                raise AdminError("The existing authorize file contains an unmanaged entry.")
            stamp = now()
            users.append(
                {
                    "username": match.group(1),
                    "password": decode_radius(match.group(2)),
                    "enabled": True,
                    "created_at": stamp,
                    "updated_at": stamp,
                }
            )
        if not users:
            raise AdminError("The existing authorize file contains no users.")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_json({"version": 1, "users": users})

    def load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            raise AdminError("User state has not been bootstrapped.")
        data = json.loads(self.state_path.read_text())
        if data.get("version") != 1 or not isinstance(data.get("users"), list):
            raise AdminError("User state has an unsupported format.")
        return data

    def public_list(self) -> dict[str, Any]:
        data = self.load()
        users = [
            {key: item[key] for key in ("username", "enabled", "created_at", "updated_at")}
            for item in sorted(data["users"], key=lambda user: user["username"])
        ]
        return {"users": users, "health": self.health()}

    def health(self) -> dict[str, bool]:
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
        return {"active": active, "config_valid": valid}

    def mutate(self, operation: str, payload: dict[str, Any]) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self.load()
            users = data["users"]
            username = clean_username(payload.get("username"))
            matches = [item for item in users if item["username"] == username]

            if operation == "create":
                if matches:
                    raise AdminError("That username already exists.")
                stamp = now()
                users.append(
                    {
                        "username": username,
                        "password": clean_password(payload.get("password")),
                        "enabled": True,
                        "created_at": stamp,
                        "updated_at": stamp,
                    }
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
                elif operation == "reset-password":
                    user["password"] = clean_password(payload.get("password"))
                    user["updated_at"] = now()
                elif operation == "set-enabled":
                    enabled = payload.get("enabled")
                    if not isinstance(enabled, bool):
                        raise AdminError("Invalid account status.")
                    if not enabled and user["enabled"] and self._enabled_count(users) == 1:
                        raise AdminError(
                            "Add another enabled user before blocking the final account."
                        )
                    user["enabled"] = enabled
                    user["updated_at"] = now()
                elif operation == "delete":
                    if user["enabled"] and self._enabled_count(users) == 1:
                        raise AdminError(
                            "Add another enabled user before deleting the final account."
                        )
                    users.remove(user)
                else:
                    raise AdminError("Unsupported operation.")

            self._commit(data)

    @staticmethod
    def _enabled_count(users: list[dict[str, Any]]) -> int:
        return sum(bool(item["enabled"]) for item in users)

    def _render(self, data: dict[str, Any]) -> str:
        lines = ["# Generated by radius-user-admin. Do not edit by hand."]
        for user in sorted(data["users"], key=lambda item: item["username"]):
            if user["enabled"]:
                lines.append(
                    f'{user["username"]} Cleartext-Password := "{encode_radius(user["password"])}"'
                )
        return "\n".join(lines) + "\n"

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

    def _commit(self, data: dict[str, Any]) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = self.backup_dir / stamp
        destination.mkdir(parents=True, exist_ok=False)
        old_state = self.state_path.read_bytes()
        old_authorize = self.authorize_path.read_bytes()
        shutil.copy2(self.state_path, destination / "users.json")
        shutil.copy2(self.authorize_path, destination / "authorize")
        self._atomic_json(data)
        self._atomic_write(self.authorize_path, self._render(data), 0o640)
        try:
            os.chown(self.authorize_path, 0, grp.getgrnam("freerad").gr_gid)
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
        except Exception:
            self._atomic_write(self.state_path, old_state.decode(), 0o600)
            self._atomic_write(self.authorize_path, old_authorize.decode(), 0o640)
            os.chown(self.authorize_path, 0, grp.getgrnam("freerad").gr_gid)
            self.runner(["/usr/bin/systemctl", "restart", "freeradius"], check=False)
            raise

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
    try:
        ensure_caller()
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise AdminError("Invalid request.")
        store = Store()
        if args.operation == "bootstrap":
            store.bootstrap()
            result: dict[str, Any] = {}
        elif args.operation == "list":
            result = store.public_list()
        else:
            store.mutate(args.operation, payload)
            result = {}
        logging.getLogger("radius-user-admin").info("operation=%s", args.operation)
        print(json.dumps({"ok": True, **result}))
        return 0
    except (AdminError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
