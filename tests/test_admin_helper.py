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
        admin_path=tmp_path / "state/admins.json",
        audit_path=tmp_path / "state/audit.jsonl",
        auth_events_path=tmp_path / "authevents.log",
        certificate_path=tmp_path / "fullchain.pem",
        enrollment_path=tmp_path / "state/duo-enrollments.json",
        invitation_path=tmp_path / "state/invitations.json",
        duo_enroll_config_path=tmp_path / "duo-enroll-api.json",
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


def test_new_and_reset_credentials_are_bcrypt_hashes(store: Store) -> None:
    password = "a-safe-password-2026"
    store.mutate(
        "create",
        {"username": "new-user", "password": password, "duo_required": True},
    )
    user = next(item for item in store.load()["users"] if item["username"] == "new-user")
    assert "password" not in user
    assert user["password_hash"].startswith("$2b$12$")
    assert admin_helper.password_matches(user, password)
    authorize = store.authorize_path.read_text()
    assert f'new-user Crypt-Password := "{user["password_hash"]}"' in authorize
    assert password not in authorize

    replacement = "a-different-password-2026"
    store.mutate("reset-password", {"username": "new-user", "password": replacement})
    user = next(item for item in store.load()["users"] if item["username"] == "new-user")
    assert admin_helper.password_matches(user, replacement)
    assert not admin_helper.password_matches(user, password)


def test_legacy_credential_migration_is_scoped_and_reversible(store: Store) -> None:
    original = "long-enough-password"
    migrated = store.migrate_passwords("vpn-test-user")
    assert migrated == ["vpn-test-user"]
    user = store.load()["users"][0]
    assert "password" not in user
    assert admin_helper.password_matches(user, original)
    assert "Crypt-Password" in store.authorize_path.read_text()
    assert original not in store.state_path.read_text()
    assert original not in store.authorize_path.read_text()
    assert store.migrate_passwords("vpn-test-user") == []


def test_one_time_invitation_creates_bcrypt_user_without_storing_token(store: Store) -> None:
    invitation = store.invite_create(
        "invited-user", "person@example.test", False, valid_hours=24
    )
    token = invitation["token"]
    invitation_state = store.invitation_path.read_text()
    assert token not in invitation_state
    assert store.invitation_path.stat().st_mode & 0o777 == 0o600
    assert store.invite_status(token)["username"] == "invited-user"
    assert store.invitation_list()[0]["status"] == "pending"

    result = store.invite_accept(token, "a-new-invited-password-2026")
    assert result["username"] == "invited-user"
    user = next(item for item in store.load()["users"] if item["username"] == "invited-user")
    assert "password" not in user
    assert admin_helper.password_matches(user, "a-new-invited-password-2026")
    assert store.invitation_list()[0]["status"] == "accepted"
    with pytest.raises(AdminError, match="already been used"):
        store.invite_status(token)


def test_pending_invitation_can_be_revoked(store: Store) -> None:
    invitation = store.invite_create("invited-user", "", True, valid_hours=1)
    store.invite_revoke("invited-user")
    with pytest.raises(AdminError, match="invalid"):
        store.invite_status(invitation["token"])


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
                "duo_bypass_reason": "Temporary support access",
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
            "duo_bypass_reason": "Temporary support access",
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
            "duo_bypass_reason": "Temporary support access",
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
        store.mutate(
            "set-duo",
            {
                "username": "vpn-test-user",
                "duo_required": False,
                "duo_bypass_reason": "Temporary support access",
            },
        )


@pytest.mark.parametrize(
    "username", ["space user", "../root", "", "x" * 65, "bad@@your-domain.com", "bad@"]
)
def test_username_policy_rejects_unsafe_values(username: str) -> None:
    with pytest.raises(AdminError):
        admin_helper.clean_username(username)


def test_username_is_normalized_to_lowercase() -> None:
    assert admin_helper.clean_username("QUIQUE") == "quique"
    assert admin_helper.clean_username("Hola@your-domain.com") == "hola@your-domain.com"


def test_runtime_setting_prefers_explicit_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RADIUSPILOT_TEST_SETTING", "/safe/explicit/path")
    assert (
        admin_helper.runtime_setting("RADIUSPILOT_TEST_SETTING", "/fallback")
        == "/safe/explicit/path"
    )


def test_duo_enrollment_is_kept_root_only(store: Store) -> None:
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-password-2026",
            "duo_required": True,
        },
    )
    store.duo_check = lambda _username: {  # type: ignore[method-assign]
        "result": "enroll",
        "status": "Enroll an authentication device to proceed",
    }
    store._duo_enroll_credentials = lambda: {  # type: ignore[method-assign]
        "ikey": "test", "skey": "test", "api_host": "api.example.test"
    }
    store._duo_request = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
        "user_id": "DU123",
        "activation_url": "https://m-example.duosecurity.com/activate/code",
        "activation_barcode": "https://api-example.duosecurity.com/frame/qr?value=code",
        "expiration": 4102444800,
    }
    enrollment = store.duo_enroll("quique")
    assert enrollment["username"] == "quique"
    assert store.duo_enrollment("quique")["user_id"] == "DU123"
    assert store.enrollment_path.stat().st_mode & 0o777 == 0o600
    public = {user["username"]: user for user in store.public_list()["users"]}
    assert public["quique"]["duo_enrollment_active"] is True


def test_duo_enrollment_rejects_untrusted_activation_host(store: Store) -> None:
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-password-2026",
            "duo_required": True,
        },
    )
    store.duo_check = lambda _username: {  # type: ignore[method-assign]
        "result": "enroll",
        "status": "Enrollment required",
    }
    store._duo_enroll_credentials = lambda: {  # type: ignore[method-assign]
        "ikey": "test", "skey": "test", "api_host": "api.example.test"
    }
    store._duo_request = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
        "user_id": "DU123",
        "activation_url": "https://evil.example/activate/code",
        "activation_barcode": "https://api-example.duosecurity.com/frame/qr?value=code",
        "expiration": 4102444800,
    }
    with pytest.raises(AdminError, match="invalid activation URL"):
        store.duo_enroll("quique")


def test_admin_password_is_hashed_and_authenticates(store: Store) -> None:
    store.duo_authenticate = lambda _username: True  # type: ignore[method-assign]
    store.bootstrap_admin("console-admin", "a-strong-console-password-2026")
    content = store.admin_path.read_text()
    assert "a-strong-console-password-2026" not in content
    assert store.authenticate_admin("console-admin", "a-strong-console-password-2026") is True
    assert store.authenticate_admin("console-admin", "wrong-password") is False


def test_reconcile_expires_duo_bypass(store: Store) -> None:
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-password-2026",
            "duo_required": False,
            "duo_bypass_reason": "Temporary support access",
        },
    )
    data = store.load()
    target = next(user for user in data["users"] if user["username"] == "quique")
    target["duo_bypass_until"] = "2020-01-01T00:00:00+00:00"
    store._atomic_json(data)
    changes = store.reconcile()
    target = next(user for user in store.load()["users"] if user["username"] == "quique")
    assert changes == ["expired Duo bypass quique"]
    assert target["duo_required"] is True
    assert "exempt_username_1=quique" not in store.duo_config_path.read_text()


def test_audit_never_records_password(store: Store) -> None:
    store.record_audit(
        actor="admin",
        source_ip="192.0.2.10",
        action="reset-password",
        target="quique",
        detail="Password changed",
    )
    content = store.audit_path.read_text()
    assert "a-safe-password-2026" not in content
    assert store.audit_events()[0]["target"] == "quique"


def test_last_authentication_is_sanitized(store: Store) -> None:
    store.auth_events_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-09-01T05:45:29Z",
                "username": "vpn-test-user",
                "status": "Allow",
                "auth_stage": "Secondary authentication",
                "client_ip": "192.0.2.10",
                "msg": "Success. Logging you in...",
                "secret": "must-not-be-returned",
            }
        )
        + "\n"
    )
    event = store.last_authentication()["vpn-test-user"]
    assert event["status"] == "Allow"
    assert "secret" not in event


def test_panel_access_uses_separate_credential_and_preserves_final_admin(store: Store) -> None:
    store.bootstrap_admin("vpn-test-user", "initial-console-password-2026")
    store.duo_authenticate = lambda _username: True  # type: ignore[method-assign]
    store.duo_check = lambda _username: {  # type: ignore[method-assign]
        "result": "auth",
        "push_capable": True,
    }
    store.mutate(
        "create",
        {
            "username": "quique",
            "password": "a-safe-vpn-password-2026",
            "duo_required": True,
            "panel_access": True,
            "panel_password": "a-distinct-console-password-2026",
        },
    )
    public = {user["username"]: user for user in store.public_list()["users"]}
    assert public["quique"]["panel_access"] is True
    assert store.authenticate_admin("quique", "a-distinct-console-password-2026") is True
    with pytest.raises(AdminError, match="Revoke panel access"):
        store.mutate("delete", {"username": "quique"})

    store.set_panel_access("quique", False)
    assert "quique" not in store.panel_admin_usernames()
    with pytest.raises(AdminError, match="final administrator"):
        store.set_panel_access("vpn-test-user", False)


def test_panel_password_must_differ_from_vpn_password(store: Store) -> None:
    store.bootstrap_admin("vpn-test-user", "initial-console-password-2026")
    store.duo_check = lambda _username: {  # type: ignore[method-assign]
        "result": "auth",
        "push_capable": True,
    }
    with pytest.raises(AdminError, match="must differ"):
        store.mutate(
            "create",
            {
                "username": "quique",
                "password": "same-password-for-both-2026",
                "duo_required": True,
                "panel_access": True,
                "panel_password": "same-password-for-both-2026",
            },
        )
