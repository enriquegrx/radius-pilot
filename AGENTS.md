# AGENTS.md

## Purpose

This repository contains the small, local-only administration console for the
Example Organization FreeRADIUS user file. Keep its scope narrow: list users, create users,
rename users, reset passwords, block/unblock users, and delete users.

## Security boundaries

- Never expose passwords in HTML, logs, command-line arguments, or helper output.
- The web process must run as `radiusui`, never as root.
- Privileged writes must go through `radius-user-admin-helper` and its exact
  sudoers rule.
- The FastAPI service must remain bound to `127.0.0.1`. Nginx is the only HTTPS
  listener and must restrict access to the documented internal/VPN networks.
- Never add WAN NAT, a public reverse proxy, or a Cloudflare Tunnel for this app.
- Keep the state file root-only and the generated FreeRADIUS file `root:freerad`
  mode `0640`.
- Every mutation must validate the complete FreeRADIUS configuration and roll
  back both files if validation or restart fails.
- Do not change the Cisco router or the Duo integration from this repository.

## Product rules

- Common tasks must take no more than three clicks from the user list.
- Never display an existing password. Password reset accepts a new value only.
- The FreeRADIUS username must exactly match the corresponding Duo username.
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
