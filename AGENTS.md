# AGENTS.md

## Purpose

This repository contains the small, local-only administration console for the
Example Organization FreeRADIUS user file. Keep its scope narrow: list users, create users,
choose per-user Duo enforcement, rename users, reset passwords, block/unblock
users, create one-time account invitations, migrate legacy VPN credentials to
MS-CHAPv2-compatible NT hashes, create time-limited Duo Mobile enrollments through the Auth API, and
delete users.

## Security boundaries

- Never expose passwords in HTML, logs, command-line arguments, or helper output.
- Treat Duo activation URLs and QR codes as temporary credentials. Keep them in
  the root-only enrollment state, never place them in query strings or audit
  entries, and accept activation URLs only from HTTPS Duo Security hosts.
- Treat invitation links as bearer credentials. Persist only a SHA-256 digest,
  never include tokens in audit records, disable request logging for invitation
  routes, and consume each token after the first successful password setup.
- Console administrators use a separate scrypt-hashed secret and Duo Push. Do
  not accept VPN primary passwords as console passwords.
- Panel access is an explicit role attached to a VPN username. Enforce Duo
  readiness before granting it, prevent VPN/console password reuse, and prevent
  revoking or deleting the final panel administrator.
- All browser mutations require an authenticated, unexpired session and CSRF
  token. Preserve login rate limiting and the 30-minute idle timeout.
- The web process must run as `radiusui`, never as root.
- Privileged writes must go through `radius-user-admin-helper` and its exact
  sudoers rule.
- The FastAPI service must remain bound to `127.0.0.1`. Nginx is the only HTTPS
  listener and must restrict access to the documented internal/VPN networks.
- Never add WAN NAT, a public reverse proxy, or a Cloudflare Tunnel for this app.
- Keep the state file root-only and the generated FreeRADIUS file `root:freerad`
  mode `0640`.
- Every mutation must validate FreeRADIUS and any changed Duo Authentication
  Proxy configuration, then roll back all managed files if validation or restart
  fails.
- Manage Duo exceptions only inside the marked `radius_server_auto` block. Never
  change keys, secrets, hosts, ports, or Cisco router configuration here.
- Audit actor, source address, action, target, and outcome, but never payloads or
  credentials. CSV exports must neutralize spreadsheet formulas.

## Product rules

- Common tasks must take no more than three clicks from the user list.
- Never display an existing password. Password reset accepts a new value only.
- The FreeRADIUS username must exactly match the corresponding Duo username.
- Email-style usernames are supported. Keep the single-`@`, 64-character and
  safe-character validation aligned in the helper, HTML forms, and tests.
- Use a separate Auth API integration for enrollment. Never replace or reuse the
  Authentication Proxy configuration as enrollment configuration.
- Existing and newly created users default to requiring Duo. Password-only mode
  is an explicit per-user choice and must remain scoped to this VPN integration.
- Password-only mode requires a reason. Support a UTC expiry and automatically
  return to Duo when it elapses.
- Invitation pages stay behind the existing LAN/VPN source allowlist. Do not
  make onboarding a reason to publish the application to the WAN.
- New and reset VPN credentials use NT hashes because Cisco IKEv2 authenticates
  with MS-CHAPv2. Legacy clear-text credentials may
  be migrated individually, with the existing backup, validation and rollback
  path preserved.
- Account expirations must be enforced by the reconciliation timer, not only by
  browser rendering.
- Restores may only use exact helper-created backup identifiers. Always create a
  new backup and validate both authentication services before accepting one.
- Prevent blocking or deleting the final enabled user.
- Keep static assets local. Production must not depend on a CDN.

## Development

Run the checks before deployment:

```bash
python -m pytest
ruff check .
```

Tests must use temporary files and fake service commands. They must never touch
the live FreeRADIUS configuration.

## Deployment

Use the files under `deploy/` together with the Example Organization site runbook. Pin the
existing `radius01` SSH host key, create a dated remote backup, upload files
with explicit ownership and permissions, bootstrap state from the current
`authorize` file, validate FreeRADIUS, and only then enable the web service.
