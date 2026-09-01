# Radius User Admin

🛡️ A deliberately small web console for managing the VPN users authenticated by
FreeRADIUS at Example Organization. It is built for the handful of jobs that matter day to day:
see who has access, add an account, rename it, reset its password, block it, or
remove it.

The application runs on `radius01` behind Nginx. FastAPI listens only on
loopback; Nginx publishes HTTPS to the approved internal and VPN networks. There
is no WAN NAT, Cloudflare Tunnel, or public admin path.

## What it does

- Lists enabled and blocked users without exposing passwords.
- Creates, renames, blocks, unblocks, and deletes accounts.
- Resets a password without ever showing the previous one.
- Refuses to block or delete the final enabled account.
- Validates the full FreeRADIUS configuration before restarting the service.
- Restores the previous files automatically if validation or restart fails.
- Keeps a root-owned state file and generates the existing `authorize` file.

The username entered here must match the username enrolled in Duo. Blocking a
user removes it from the generated FreeRADIUS file, so neither the primary
password nor Duo Push is reached.

## Open the console

From a device on an approved LAN or connected through the Example Organization VPN, open
<https://radius.your-domain.com>. Nginx and nftables both enforce the source-network
allowlist.

## Architecture

The FastAPI process runs as the unprivileged `radiusui` account. It cannot read
the password store or the generated FreeRADIUS file. Mutations are sent as JSON
over stdin to a narrowly scoped root helper through `sudo`; passwords therefore
do not appear in process lists.

The helper maintains:

- `/var/lib/radius-user-admin/users.json` — root-only source of truth.
- `/etc/freeradius/3.0/mods-config/files/vpn-users/authorize` — generated
  active users consumed by FreeRADIUS.
- `/var/backups/radius-user-admin/` — dated snapshots before every mutation.

The interface uses the open-source [Tabler](https://tabler.io/) design system,
vendored locally under its MIT license.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check .
```

For a local UI run that does not touch FreeRADIUS, provide a fake helper:

```bash
RADIUS_ADMIN_HELPER=tests/fake_helper.py \
RADIUS_ADMIN_SESSION_SECRET=development-only \
.venv/bin/uvicorn radius_user_admin.app:app --reload
```

## Production notes

Deployment is intentionally Debian-native: packaged Python modules, a hardened
systemd unit, a dedicated service user, Nginx with a Let's Encrypt certificate,
and a single sudoers entry. Do not bind Uvicorn to a LAN address or add public
NAT. Certificate issuance and renewal use DNS-01 on `pki01`; the deploy hook
copies the renewed files to `radius01`, tests Nginx, and reloads it.
