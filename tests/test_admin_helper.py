from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from radius_user_admin import admin_helper
from radius_user_admin.access_policy import (
    AccessPolicyError,
    allowed_destinations,
    cisco_avpairs,
    clean_access_policy,
)
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


def test_new_and_reset_credentials_are_mschapv2_hashes(store: Store) -> None:
    password = "a-safe-password-2026"
    store.mutate(
        "create",
        {"username": "new-user", "password": password, "duo_required": True},
    )
    user = next(item for item in store.load()["users"] if item["username"] == "new-user")
    assert "password" not in user
    assert len(user["nt_password"]) == 32
    assert admin_helper.password_matches(user, password)
    authorize = store.authorize_path.read_text()
    assert f'new-user NT-Password := 0x{user["nt_password"]}' in authorize
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
    assert "NT-Password" in store.authorize_path.read_text()
    assert original not in store.state_path.read_text()
    assert original not in store.authorize_path.read_text()
    assert store.migrate_passwords("vpn-test-user") == []


def test_one_time_invitation_creates_nt_hash_user_without_storing_token(store: Store) -> None:
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


def test_render_failure_happens_before_any_managed_file_is_written(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_state = store.state_path.read_bytes()
    old_authorize = store.authorize_path.read_bytes()
    old_duo = store.duo_config_path.read_bytes()

    def fail_render(_data: dict[str, object]) -> str:
        raise AdminError("Policy rendering failed.")

    monkeypatch.setattr(store, "_render", fail_render)
    with pytest.raises(AdminError, match="rendering failed"):
        store._commit(store.load())

    assert store.state_path.read_bytes() == old_state
    assert store.authorize_path.read_bytes() == old_authorize
    assert store.duo_config_path.read_bytes() == old_duo


def test_version_three_state_requires_explicit_access_policy(store: Store) -> None:
    data = json.loads(store.state_path.read_text())
    data["users"][0].pop("access_policy")
    store.state_path.write_text(json.dumps(data))

    with pytest.raises(AdminError, match="missing required security fields"):
        store.load()


def test_version_three_state_rejects_null_access_policy(store: Store) -> None:
    data = json.loads(store.state_path.read_text())
    data["users"][0]["access_policy"] = None
    store.state_path.write_text(json.dumps(data))

    with pytest.raises(AdminError, match="corrupt"):
        store.load()


def test_legacy_state_migrates_missing_access_policy_to_full(store: Store) -> None:
    data = json.loads(store.state_path.read_text())
    data["version"] = 2
    data["users"][0].pop("access_policy")
    store.state_path.write_text(json.dumps(data))

    assert store.load()["users"][0]["access_policy"] == {
        "mode": "full",
        "rules": [],
    }


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


def test_store_reads_policy_destinations_from_runtime_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = admin_helper.runtime_setting

    def setting(name: str, default: str) -> str:
        if name == "RADIUS_ADMIN_POLICY_DESTINATIONS":
            return "192.0.2.0/24,198.51.100.0/24"
        return original(name, default)

    monkeypatch.setattr(admin_helper, "runtime_setting", setting)
    configured = Store(custom_dacl_enabled=False, runner=Runner())
    assert [item.with_prefixlen for item in configured.policy_destinations] == [
        "192.0.2.0/24",
        "198.51.100.0/24",
    ]


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


def custom_policy() -> dict[str, object]:
    return {
        "mode": "custom",
        "rules": [
            {
                "destination": "192.168.50.112",
                "protocol": "tcp",
                "ports": "443, 8000-8010",
            }
        ],
    }


def enable_custom_access(store: Store) -> None:
    store.custom_dacl_enabled = True
    config = store.duo_config_path.read_text().replace(
        "port=18120", "port=18120\npass_through_attr_names=Cisco-AVPair"
    )
    store.duo_config_path.write_text(config)


def test_access_policy_canonicalizes_hosts_ports_and_duplicates() -> None:
    policy = clean_access_policy(
        {
            "mode": "custom",
            "rules": [
                {"destination": "192.168.50.112", "protocol": "tcp", "ports": "443"},
                {
                    "destination": "192.168.50.112/32",
                    "protocol": "tcp",
                    "ports": [[443, 443]],
                },
            ],
        }
    )
    assert policy == {
        "mode": "custom",
        "rules": [
            {
                "destination": "192.168.50.112/32",
                "protocol": "tcp",
                "ports": [[443, 443]],
            }
        ],
    }


@pytest.mark.parametrize(
    "policy",
    [
        {"mode": "custom", "rules": []},
        {
            "mode": "custom",
            "rules": [{"destination": "0.0.0.0/0", "protocol": "ip", "ports": ""}],
        },
        {
            "mode": "custom",
            "rules": [{"destination": "203.0.113.10", "protocol": "tcp", "ports": "443"}],
        },
        {
            "mode": "custom",
            "rules": [{"destination": "192.168.50.10", "protocol": "icmp", "ports": "443"}],
        },
        {
            "mode": "custom",
            "rules": [{"destination": "192.168.50.10", "protocol": "tcp", "ports": "70000"}],
        },
        {
            "mode": "custom",
            "rules": [{"destination": "192.168.50.10", "protocol": "tcp", "ports": ""}],
        },
        {
            "mode": "custom",
            "rules": [{"destination": "2001:db8::/64", "protocol": "ip", "ports": ""}],
        },
        {
            "mode": "restricted",
            "rules": [{"destination": "192.168.50.10", "protocol": "tcp", "ports": "443"}],
        },
    ],
)
def test_access_policy_rejects_unsafe_rules(policy: dict[str, object]) -> None:
    with pytest.raises(AccessPolicyError):
        clean_access_policy(policy)


def test_access_policy_rejects_special_addresses_even_when_allowlisted() -> None:
    allowlist = allowed_destinations("224.0.0.0/4,169.254.0.0/16,127.0.0.0/8")
    for destination in ("224.0.0.5", "169.254.10.10", "127.0.0.1"):
        with pytest.raises(AccessPolicyError, match="denied"):
            clean_access_policy(
                {
                    "mode": "custom",
                    "rules": [
                        {"destination": destination, "protocol": "ip", "ports": ""}
                    ],
                },
                destination_allowlist=allowlist,
            )


def test_access_policy_rejects_more_than_max_rules() -> None:
    with pytest.raises(AccessPolicyError, match="at most 24 rules"):
        clean_access_policy(
            {
                "mode": "custom",
                "rules": [
                    {"destination": f"10.0.0.{host}/32", "protocol": "ip", "ports": ""}
                    for host in range(1, 26)
                ],
            }
        )


def test_access_policy_rejects_more_than_max_permit_entries() -> None:
    with pytest.raises(AccessPolicyError, match="at most 63 permit entries"):
        clean_access_policy(
            {
                "mode": "custom",
                "rules": [
                    {
                        "destination": f"10.0.1.{host}/32",
                        "protocol": "tcp",
                        "ports": "80,443,8443",
                    }
                    for host in range(1, 25)
                ],
            }
        )


def test_access_policy_rejects_radius_reply_larger_than_udp_budget() -> None:
    policy = clean_access_policy(
        {
            "mode": "custom",
            "rules": [
                {
                    "destination": f"10.0.0.{host}/32",
                    "protocol": "tcp",
                    "ports": "80,443,8443",
                }
                for host in range(1, 22)
            ],
        }
    )
    with pytest.raises(AccessPolicyError, match="Access-Accept"):
        cisco_avpairs(policy)


def test_access_object_lifecycle_with_nesting(store: Store) -> None:
    enable_custom_access(store)
    store.mutate_objects(
        "object-set",
        {
            "name": "web",
            "description": "Web ports",
            "rules": [{"destination": "192.168.50.20", "protocol": "tcp", "ports": "80,443"}],
        },
    )
    store.mutate_objects(
        "object-set",
        {
            "name": "stack",
            "rules": [
                {"object": "web"},
                {"destination": "192.168.50.21", "protocol": "icmp", "ports": ""},
            ],
        },
    )
    store.mutate(
        "set-access-policy",
        {
            "username": "vpn-test-user",
            "access_policy": {"mode": "custom", "rules": [{"object": "stack"}]},
        },
    )
    public = store.public_list()
    objects = {item["name"]: item for item in public["access_policy"]["objects"]}
    assert objects["web"]["used_by"] == 1
    assert objects["stack"]["used_by"] == 1
    user = next(u for u in public["users"] if u["username"] == "vpn-test-user")
    assert user["access_policy"]["rules"] == [{"object": "stack"}]
    assert user["access_avpairs"][-1].endswith("deny ip any any")
    assert any("192.168.50.20" in item for item in user["access_avpairs"])
    authorize = store.authorize_path.read_text()
    assert "192.168.50.20" in authorize
    assert "192.168.50.21" in authorize

    store.mutate_objects(
        "object-set",
        {
            "name": "web",
            "description": "Web ports",
            "rules": [{"destination": "192.168.50.30", "protocol": "tcp", "ports": "443"}],
        },
    )
    authorize = store.authorize_path.read_text()
    assert "192.168.50.30" in authorize
    assert "192.168.50.20" not in authorize


def test_access_object_cycle_is_rejected(store: Store) -> None:
    enable_custom_access(store)
    store.mutate_objects(
        "object-set",
        {
            "name": "alpha",
            "rules": [{"destination": "192.168.50.20", "protocol": "ip", "ports": ""}],
        },
    )
    store.mutate_objects(
        "object-set", {"name": "beta", "rules": [{"object": "alpha"}]}
    )
    with pytest.raises(AdminError, match="loop"):
        store.mutate_objects(
            "object-set", {"name": "alpha", "rules": [{"object": "beta"}]}
        )


def test_access_object_delete_refused_while_referenced(store: Store) -> None:
    enable_custom_access(store)
    store.mutate_objects(
        "object-set",
        {
            "name": "web",
            "rules": [{"destination": "192.168.50.20", "protocol": "tcp", "ports": "443"}],
        },
    )
    store.mutate_objects(
        "object-set", {"name": "stack", "rules": [{"object": "web"}]}
    )
    store.mutate(
        "set-access-policy",
        {
            "username": "vpn-test-user",
            "access_policy": {"mode": "custom", "rules": [{"object": "stack"}]},
        },
    )
    with pytest.raises(AdminError, match="stack"):
        store.mutate_objects("object-delete", {"name": "web"})
    with pytest.raises(AdminError, match="vpn-test-user"):
        store.mutate_objects("object-delete", {"name": "stack"})
    store.mutate(
        "set-access-policy",
        {
            "username": "vpn-test-user",
            "access_policy": {"mode": "full", "rules": []},
        },
    )
    store.mutate_objects("object-delete", {"name": "stack"})
    store.mutate_objects("object-delete", {"name": "web"})
    assert store.public_list()["access_policy"]["objects"] == []


def test_access_object_edit_that_breaks_a_user_is_rejected(store: Store) -> None:
    enable_custom_access(store)
    store.mutate_objects(
        "object-set",
        {
            "name": "small",
            "rules": [{"destination": "192.168.50.20", "protocol": "tcp", "ports": "443"}],
        },
    )
    store.mutate(
        "set-access-policy",
        {
            "username": "vpn-test-user",
            "access_policy": {"mode": "custom", "rules": [{"object": "small"}]},
        },
    )
    oversized = [
        {"destination": f"192.168.50.{host}", "protocol": "tcp", "ports": "80,443,8443"}
        for host in range(20, 41)
    ]
    with pytest.raises(AdminError, match="vpn-test-user"):
        store.mutate_objects("object-set", {"name": "small", "rules": oversized})


def test_state_with_unknown_object_reference_fails_closed(store: Store) -> None:
    data = json.loads(store.state_path.read_text())
    data["users"][0]["access_policy"] = {
        "mode": "custom",
        "rules": [{"object": "ghost"}],
    }
    store.state_path.write_text(json.dumps(data))

    with pytest.raises(AdminError, match="unknown saved object"):
        store.load()


def test_reconcile_rotates_oversized_audit_log(store: Store) -> None:
    store.audit_path.parent.mkdir(parents=True, exist_ok=True)
    store.audit_path.write_text('{"action": "test"}\n' * 10001)
    changes = store.reconcile()
    assert any("rotated audit log" in change for change in changes)
    assert not store.audit_path.exists()
    archives = list(store.audit_path.parent.glob("audit-*.jsonl.gz"))
    assert len(archives) == 1
    assert oct(archives[0].stat().st_mode & 0o777) == "0o600"
    assert store.reconcile() == []


def test_reconcile_prunes_only_helper_backups(store: Store) -> None:
    store.backup_dir.mkdir(parents=True, exist_ok=True)
    for index in range(45):
        (store.backup_dir / f"20260101T0000000000{index:02d}Z").mkdir()
    (store.backup_dir / "deploy-20260901-165942").mkdir()
    changes = store.reconcile()
    # The first reconcile rewrites the bootstrapped authorize file, which adds
    # one more helper backup before pruning runs: 46 snapshots, 40 kept.
    assert any("pruned 6 old configuration backups" in change for change in changes)
    remaining = sorted(entry.name for entry in store.backup_dir.iterdir())
    assert len(remaining) == 41
    assert "deploy-20260901-165942" in remaining
    assert "20260101T000000000000Z" not in remaining
    assert "20260101T000000000044Z" in remaining


def test_import_objects_upserts_and_validates(store: Store) -> None:
    enable_custom_access(store)
    store.mutate_objects(
        "object-set",
        {
            "name": "web",
            "rules": [{"destination": "192.168.50.20", "protocol": "tcp", "ports": "80"}],
        },
    )
    count = store.import_objects(
        {
            "objects": [
                {
                    "name": "web",
                    "description": "updated",
                    "rules": [
                        {"destination": "192.168.50.20", "protocol": "tcp", "ports": "443"}
                    ],
                },
                {
                    "name": "dns",
                    "rules": [
                        {"destination": "192.168.50.53", "protocol": "udp", "ports": "53"}
                    ],
                },
            ]
        }
    )
    assert count == 2
    objects = {o["name"]: o for o in store.public_list()["access_policy"]["objects"]}
    assert set(objects) == {"web", "dns"}
    assert objects["web"]["description"] == "updated"


def test_import_objects_rejected_when_it_breaks_a_user(store: Store) -> None:
    enable_custom_access(store)
    store.mutate_objects(
        "object-set",
        {
            "name": "svc",
            "rules": [{"destination": "192.168.50.20", "protocol": "tcp", "ports": "443"}],
        },
    )
    store.mutate(
        "set-access-policy",
        {
            "username": "vpn-test-user",
            "access_policy": {"mode": "custom", "rules": [{"object": "svc"}]},
        },
    )
    oversized = [
        {"destination": f"192.168.50.{host}", "protocol": "tcp", "ports": "80,443,8443"}
        for host in range(20, 41)
    ]
    with pytest.raises(AdminError, match="vpn-test-user"):
        store.import_objects({"objects": [{"name": "svc", "rules": oversized}]})


def test_reconcile_emails_expiring_accounts_once(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RADIUS_ADMIN_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("RADIUS_ADMIN_ADMIN_EMAIL", "ops@example.test")
    monkeypatch.setenv("RADIUS_ADMIN_EXPIRY_WARNING_DAYS", "7")
    sent = []
    store._send_admin_email = (  # type: ignore[method-assign]
        lambda recipient, subject, body: sent.append((recipient, subject, body))
    )
    data = json.loads(store.state_path.read_text())
    soon = (datetime.now(UTC) + timedelta(days=3)).isoformat(timespec="seconds")
    data["users"][0]["expires_at"] = soon
    store.state_path.write_text(json.dumps(data))

    changes = store.reconcile()
    assert any("warned about 1 expiring account" in c for c in changes)
    assert len(sent) == 1
    assert sent[0][0] == "ops@example.test"
    assert "vpn-test-user" in sent[0][2]
    # A second reconcile must not re-warn the same expiry.
    assert not any("warned about" in c for c in store.reconcile())
    assert len(sent) == 1


def test_public_list_reports_readiness_flags(store: Store) -> None:
    policy = store.public_list()["access_policy"]
    assert policy["avpair_forwarding"] is False
    assert policy["gate_enabled"] is False
    enable_custom_access(store)
    policy = store.public_list()["access_policy"]
    assert policy["avpair_forwarding"] is True
    assert policy["gate_enabled"] is True


def test_set_duo_enroll_api_validates_and_writes_root_only(store: Store) -> None:
    calls = []
    store._duo_request = (  # type: ignore[method-assign]
        lambda path, params, **kwargs: calls.append((path, kwargs.get("credentials")))
        or {}
    )
    store.set_duo_enroll_api(
        {
            "ikey": " DIABCDEFABCDEFABCDEF ",
            "skey": "s" * 40,
            "api_host": "API-12345678.DUOSECURITY.COM",
        }
    )
    saved = json.loads(store.duo_enroll_config_path.read_text())
    assert saved == {
        "ikey": "DIABCDEFABCDEFABCDEF",
        "skey": "s" * 40,
        "api_host": "api-12345678.duosecurity.com",
    }
    assert oct(store.duo_enroll_config_path.stat().st_mode & 0o777) == "0o600"
    assert calls[0][0] == "/auth/v2/check"
    assert calls[0][1]["api_host"] == "api-12345678.duosecurity.com"
    assert store.duo_enroll_api_status() == {
        "configured": True,
        "api_host": "api-12345678.duosecurity.com",
        "ikey_hint": "DIAB",
    }


def test_set_duo_enroll_api_rejects_non_duo_hostname(store: Store) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Duo must not be contacted for an invalid hostname")

    store._duo_request = fail  # type: ignore[method-assign]
    with pytest.raises(AdminError, match="hostname"):
        store.set_duo_enroll_api(
            {"ikey": "DIABCDEF", "skey": "s" * 40, "api_host": "evil.example.com"}
        )
    assert not store.duo_enroll_config_path.exists()


def test_public_list_includes_compiled_avpairs(store: Store) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "acl-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    public = {user["username"]: user for user in store.public_list()["users"]}
    avpairs = public["acl-user"]["access_avpairs"]
    assert avpairs[0].startswith("ipsec:route-set=prefix ")
    assert avpairs[-1].endswith("deny ip any any")
    assert public["vpn-test-user"]["access_avpairs"] == []


def test_custom_access_requires_feature_gate_and_duo_forwarding(store: Store) -> None:
    with pytest.raises(AdminError, match="disabled"):
        store.mutate(
            "create",
            {
                "username": "restricted-user",
                "password": "a-safe-password-2026",
                "duo_required": True,
                "access_policy": custom_policy(),
            },
        )
    store.custom_dacl_enabled = True
    with pytest.raises(AdminError, match="disabled"):
        store.mutate(
            "create",
            {
                "username": "restricted-user",
                "password": "a-safe-password-2026",
                "duo_required": True,
                "access_policy": custom_policy(),
            },
        )


def test_router_local_fallback_username_cannot_receive_custom_access(
    store: Store,
) -> None:
    enable_custom_access(store)
    store.local_fallback_users = frozenset({"restricted-user"})
    with pytest.raises(AdminError, match="router-local fallback"):
        store.mutate(
            "create",
            {
                "username": "restricted-user",
                "password": "a-safe-password-2026",
                "duo_required": True,
                "access_policy": custom_policy(),
            },
        )

    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": {"mode": "full", "rules": []},
        },
    )
    user = next(
        item for item in store.public_list()["users"] if item["username"] == "restricted-user"
    )
    assert user["custom_access_eligible"] is False


def test_custom_user_cannot_be_renamed_to_router_local_fallback(store: Store) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    store.local_fallback_users = frozenset({"router-break-glass"})

    with pytest.raises(AdminError, match="router-local fallback"):
        store.mutate(
            "rename",
            {"username": "restricted-user", "new_username": "router-break-glass"},
        )

    assert any(
        item["username"] == "restricted-user" for item in store.load()["users"]
    )


def test_custom_access_renders_routes_and_downloadable_acl(store: Store) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    authorize = store.authorize_path.read_text()
    assert 'Cisco-AVPair += "ipsec:route-set=prefix 192.168.50.112/32",' in authorize
    assert (
        'Cisco-AVPair += "ip:inacl#1=permit tcp any host 192.168.50.112 eq 443",'
        in authorize
    )
    assert (
        'Cisco-AVPair += "ip:inacl#2=permit tcp any host 192.168.50.112 range 8000 8010",'
        in authorize
    )
    assert 'Cisco-AVPair += "ip:inacl#3=deny ip any any"' in authorize
    public = {user["username"]: user for user in store.public_list()["users"]}
    assert public["restricted-user"]["access_summary"] == (
        "Custom · 1 destination · 2 services"
    )
    assert public["restricted-user"]["access_policy"]["mode"] == "custom"


def test_blocking_custom_user_removes_all_radius_attributes(store: Store) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    store.mutate("set-enabled", {"username": "restricted-user", "enabled": False})
    assert "restricted-user" not in store.authorize_path.read_text()


def test_reconcile_fails_custom_access_closed_if_duo_stops_forwarding(
    store: Store,
) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    healthy_config = store.duo_config_path.read_text()
    store.duo_config_path.write_text(
        healthy_config.replace("\npass_through_attr_names=Cisco-AVPair", "")
    )

    changes = store.reconcile()
    assert "reconciled managed RADIUS authorization" in changes
    assert "restricted-user" not in store.authorize_path.read_text()
    restricted = next(
        user for user in store.load()["users"] if user["username"] == "restricted-user"
    )
    assert restricted["enabled"] is True

    store.duo_config_path.write_text(healthy_config)
    store.reconcile()
    assert "restricted-user" in store.authorize_path.read_text()


def test_bootstrap_reconciles_custom_access_if_duo_stops_forwarding(store: Store) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    store.duo_config_path.write_text(
        store.duo_config_path.read_text().replace(
            "\npass_through_attr_names=Cisco-AVPair", ""
        )
    )

    store.bootstrap()

    authorize = store.authorize_path.read_text()
    assert "restricted-user" not in authorize
    assert "vpn-test-user" in authorize


def test_bootstrap_empties_authorize_if_state_json_is_invalid(store: Store) -> None:
    store.state_path.write_text("{")

    with pytest.raises(json.JSONDecodeError):
        store.bootstrap()

    authorize = store.authorize_path.read_text()
    assert "Emergency fail-closed" in authorize
    assert "vpn-test-user" not in authorize


def test_reconcile_empties_authorize_if_policy_state_is_invalid(store: Store) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    healthy_state = store.state_path.read_bytes()
    data = json.loads(healthy_state)
    restricted = next(
        user for user in data["users"] if user["username"] == "restricted-user"
    )
    restricted["access_policy"]["rules"][0]["destination"] = "203.0.113.10/32"
    store.state_path.write_text(json.dumps(data))

    with pytest.raises(AdminError, match="outside"):
        store.reconcile()
    authorize = store.authorize_path.read_text()
    assert "Emergency fail-closed" in authorize
    assert "restricted-user" not in authorize
    assert "vpn-test-user" not in authorize

    store.state_path.write_bytes(healthy_state)
    store.reconcile()
    assert "restricted-user" in store.authorize_path.read_text()


def test_bootstrap_recovers_generated_custom_policy(store: Store, tmp_path: Path) -> None:
    enable_custom_access(store)
    store.mutate(
        "create",
        {
            "username": "restricted-user",
            "password": "a-safe-password-2026",
            "duo_required": True,
            "access_policy": custom_policy(),
        },
    )
    recovered = Store(
        state_path=tmp_path / "recovered/users.json",
        authorize_path=store.authorize_path,
        backup_dir=tmp_path / "recovered-backups",
        lock_path=tmp_path / "recovered-lock",
        duo_config_path=store.duo_config_path,
        admin_path=store.admin_path,
        audit_path=store.audit_path,
        auth_events_path=store.auth_events_path,
        certificate_path=store.certificate_path,
        enrollment_path=store.enrollment_path,
        invitation_path=store.invitation_path,
        duo_enroll_config_path=store.duo_enroll_config_path,
        custom_dacl_enabled=True,
        runner=Runner(),
    )
    recovered.bootstrap()
    users = {user["username"]: user for user in recovered.load()["users"]}
    assert users["restricted-user"]["access_policy"] == clean_access_policy(custom_policy())


def test_invitation_keeps_custom_access_policy(store: Store) -> None:
    enable_custom_access(store)
    invitation = store.invite_create(
        "invited-user",
        "person@example.test",
        False,
        valid_hours=24,
        access_policy=custom_policy(),
    )
    status = store.invite_status(invitation["token"])
    assert status["access_policy"]["mode"] == "custom"
    store.invite_accept(invitation["token"], "a-new-invited-password-2026")
    user = next(user for user in store.load()["users"] if user["username"] == "invited-user")
    assert user["access_policy"]["mode"] == "custom"


def test_version_two_invitation_requires_explicit_access_policy(store: Store) -> None:
    invitation = store.invite_create(
        "invited-user", "person@example.test", True, valid_hours=24
    )
    data = json.loads(store.invitation_path.read_text())
    assert data["version"] == 2
    data["invitations"][0].pop("access_policy")
    store.invitation_path.write_text(json.dumps(data))

    with pytest.raises(AdminError, match="missing its access policy"):
        store.invite_status(invitation["token"])


def test_legacy_invitation_migrates_to_full_access(store: Store) -> None:
    invitation = store.invite_create(
        "invited-user", "person@example.test", True, valid_hours=24
    )
    data = json.loads(store.invitation_path.read_text())
    data["version"] = 1
    data["invitations"][0].pop("access_policy")
    store.invitation_path.write_text(json.dumps(data))

    status = store.invite_status(invitation["token"])
    assert status["access_policy"] == {"mode": "full", "rules": []}
