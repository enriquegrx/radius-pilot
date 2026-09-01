from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from radius_user_admin import admin_helper
from radius_user_admin.admin_helper import AdminError, Store


class Runner:
    def __init__(self, fail_command: str = "") -> None:
        self.commands: list[list[str]] = []
        self.fail_command = fail_command

    def __call__(self, command, **_kwargs):
        self.commands.append(command)
        failed = self.fail_command and self.fail_command in " ".join(command)
        return subprocess.CompletedProcess(command, 1 if failed else 0, "", "")


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Store:
    authorize = tmp_path / "authorize"
    authorize.write_text('vpn-test-user Cleartext-Password := "long-enough-password"\n')
    duo_config = tmp_path / "authproxy.cfg"
    duo_config.write_text(
        """[main]
log_auth_events=true

[radius_client]
host=127.0.0.1
port=18120
secret=test-client-secret

[radius_server_auto]
ikey=test-key
skey=test-secret
api_host=api.example.test
radius_ip_1=192.0.2.1
radius_secret_1=test-radius-secret
failmode=secure
client=radius_client
port=1812
"""
    )
    monkeypatch.setattr(admin_helper.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=0))
    monkeypatch.setattr(admin_helper.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=999))
    monkeypatch.setattr(admin_helper.os, "chown", lambda *_args: None)
    result = Store(
        state_path=tmp_path / "state/users.json",
        authorize_path=authorize,
        backup_dir=tmp_path / "backups",
        lock_path=tmp_path / "lock",
        duo_config_path=duo_config,
        runner=Runner(),
    )
    result.bootstrap()
    return result


def test_bootstrap_and_list_never_expose_password(store: Store) -> None:
    response = store.public_list()
    assert response["users"][0]["username"] == "vpn-test-user"
    assert "password" not in response["users"][0]
    assert response["users"][0]["duo_required"] is True
    assert json.loads(store.state_path.read_text())["users"][0]["password"]


def test_create_then_block_updates_generated_authorize(store: Store) -> None:
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-password-2026",
            "duo_required": True,
        },
    )
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
    old_duo = store.duo_config_path.read_bytes()
    store.runner = Runner(fail_command="/usr/sbin/freeradius -C")
    with pytest.raises(AdminError, match="rejected"):
        store.mutate(
            "create",
            {
                "username": "quique",
                "password": "a-safe-password-2026",
                "duo_required": False,
            },
        )
    assert store.state_path.read_bytes() == old_state
    assert store.authorize_path.read_bytes() == old_authorize
    assert store.duo_config_path.read_bytes() == old_duo


def test_password_only_user_gets_managed_duo_exemption(store: Store) -> None:
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-password-2026",
            "duo_required": False,
        },
    )
    config = store.duo_config_path.read_text()
    assert config.count(admin_helper.DUO_BEGIN) == 1
    assert "exempt_username_1=quique" in config

    store.mutate("set-duo", {"username": "quique", "duo_required": True})
    config = store.duo_config_path.read_text()
    assert "exempt_username_1=quique" not in config
    assert admin_helper.DUO_BEGIN in config


def test_blocked_user_is_not_exempted_from_duo(store: Store) -> None:
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-password-2026",
            "duo_required": False,
        },
    )
    store.mutate("set-enabled", {"username": "quique", "enabled": False})
    assert "exempt_username_1=quique" not in store.duo_config_path.read_text()


def test_unmanaged_duo_exemption_is_rejected(store: Store) -> None:
    config = store.duo_config_path.read_text().replace(
        "failmode=secure", "failmode=secure\nexempt_username_1=manual-user"
    )
    store.duo_config_path.write_text(config)
    with pytest.raises(AdminError, match="manual review"):
        store.mutate("set-duo", {"username": "vpn-test-user", "duo_required": False})


@pytest.mark.parametrize("username", ["space user", "../root", "", "x" * 65])
def test_username_policy_rejects_unsafe_values(username: str) -> None:
    with pytest.raises(AdminError):
        admin_helper.clean_username(username)


def test_username_is_normalized_to_lowercase() -> None:
    assert admin_helper.clean_username("QUIQUE") == "quique"
