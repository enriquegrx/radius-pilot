# Radius User Admin

🛡️ A deliberately small web console for managing the VPN users authenticated by
FreeRADIUS at Example Organization. It is built for the handful of jobs that matter day to day:
see who has access, add an account, choose whether it requires Duo Push, rename
it, reset its password, block it, or remove it.

The application runs on `radius01` behind Nginx. FastAPI listens only on
loopback; Nginx publishes HTTPS to the approved internal and VPN networks. There
is no WAN NAT, Cloudflare Tunnel, or public admin path.

## What it does

- Lists enabled and blocked users without exposing passwords.
- Creates, renames, blocks, unblocks, and deletes accounts.
- Switches each enabled account between password plus Duo Push and password only.
- Protects the console with a separate scrypt-hashed administrator password,
  Duo Push, a 30-minute idle timeout, CSRF protection, and login rate limiting.
- Assigns panel access as an explicit per-user role. A panel administrator keeps
  a separate console password, must be Duo-ready, and may not reuse the VPN
  password. The final panel administrator cannot be revoked or deleted.
- Records administrative changes and recent VPN authentication results without
  storing passwords in the audit trail.
- Supports account expirations and time-limited password-only exceptions; a
  systemd timer enforces both automatically every five minutes.
- Checks Duo enrollment and Push capability before enabling Duo for an account.
- Creates seven-day Duo Mobile activations through the Auth API and presents the
  QR code or mobile activation link only to a signed-in panel administrator.
- Shows service, certificate, disk, and backup health, and exports redacted
  diagnostics and audit CSV files.
- Lists configuration backups and restores them through the same validation and
  rollback path used for ordinary changes.
- Resets a password without ever showing the previous one.
- Refuses to block or delete the final enabled account.
- Validates the full FreeRADIUS configuration before restarting the service.
- Validates both FreeRADIUS and Duo Authentication Proxy before restarting them.
- Restores all previous files automatically if validation or restart fails.
- Keeps a root-owned state file and generates the existing `authorize` file.

The username entered here must match the username enrolled in Duo when Duo Push
is required. Password-only mode uses Duo Authentication Proxy's
`exempt_username_N` setting for this VPN integration; FreeRADIUS still checks the
primary password. It does not place the user in global Duo bypass. Blocking a
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
- `/opt/duoauthproxy/conf/authproxy.cfg` — retains its hand-written settings and
  receives only a marked, generated username-exemption block.
- `/var/lib/radius-user-admin/admins.json` — root-only scrypt verifier for the
  console administrator; it does not contain the clear-text password.
- `/var/lib/radius-user-admin/audit.jsonl` — append-only administrative audit
  events with actor and source address, never credentials.
- `/var/lib/radius-user-admin/duo-enrollments.json` — root-only temporary Duo
  activation links and expiry times.
- `/etc/radius-user-admin/duo-enroll-api.json` — root-only credentials for the
  dedicated Auth API enrollment integration; this file must never enter Git.
- `/var/backups/radius-user-admin/` — dated snapshots before every mutation.

Authentication history is read from Duo Authentication Proxy's structured
`authevents.log`. Only the timestamp, username, source address, stage, and result
are returned to the web process.

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

`radius-user-admin-reconcile.timer` runs every five minutes. It blocks expired
accounts and restores Duo enforcement when a temporary password-only exception
expires. No service restart occurs when there is nothing to change.
