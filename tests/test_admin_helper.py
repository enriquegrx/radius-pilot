from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from radius_user_admin import admin_helper
from radius_user_admin.admin_helper import AdminError, Store


class Runner:
    def __init__(self, fail_check: bool = False) -> None:
        self.commands: list[list[str]] = []
        self.fail_check = fail_check

    def __call__(self, command, **_kwargs):
        self.commands.append(command)
        failed = self.fail_check and command == [
            "/usr/sbin/freeradius",
            "-C",
            "-l",
            "stdout",
        ]
        return subprocess.CompletedProcess(command, 1 if failed else 0, "", "")


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Store:
    authorize = tmp_path / "authorize"
    authorize.write_text('vpn-test-user Cleartext-Password := "long-enough-password"\n')
    monkeypatch.setattr(admin_helper.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=0))
    monkeypatch.setattr(admin_helper.os, "chown", lambda *_args: None)
    result = Store(
        state_path=tmp_path / "state/users.json",
        authorize_path=authorize,
        backup_dir=tmp_path / "backups",
        lock_path=tmp_path / "lock",
        runner=Runner(),
    )
    result.bootstrap()
    return result


def test_bootstrap_and_list_never_expose_password(store: Store) -> None:
    response = store.public_list()
    assert response["users"][0]["username"] == "vpn-test-user"
    assert "password" not in response["users"][0]
    assert json.loads(store.state_path.read_text())["users"][0]["password"]


def test_create_then_block_updates_generated_authorize(store: Store) -> None:
    store.mutate("create", {"username": "quique", "password": "a-safe-password-2026"})
    store.mutate("set-enabled", {"username": "quique", "enabled": False})
    content = store.authorize_path.read_text()
    assert "vpn-test-user" in content
    assert "quique" not in content
    public = {item["username"]: item for item in store.public_list()["users"]}
    assert public["quique"]["enabled"] is False


def test_cannot_block_or_delete_final_enabled_user(store: Store) -> None:
    with pytest.raises(AdminError, match="final account"):
        store.mutate("set-enabled", {"username": "vpn-test-user", "enabled": False})
    with pytest.raises(AdminError, match="final account"):
        store.mutate("delete", {"username": "vpn-test-user"})


def test_validation_failure_rolls_back_both_files(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_state = store.state_path.read_bytes()
    old_authorize = store.authorize_path.read_bytes()
    store.runner = Runner(fail_check=True)
    with pytest.raises(AdminError, match="rejected"):
        store.mutate("create", {"username": "quique", "password": "a-safe-password-2026"})
    assert store.state_path.read_bytes() == old_state
    assert store.authorize_path.read_bytes() == old_authorize


@pytest.mark.parametrize("username", ["space user", "../root", "", "x" * 65])
def test_username_policy_rejects_unsafe_values(username: str) -> None:
    with pytest.raises(AdminError):
        admin_helper.clean_username(username)


def test_username_is_normalized_to_lowercase() -> None:
    assert admin_helper.clean_username("QUIQUE") == "quique"
