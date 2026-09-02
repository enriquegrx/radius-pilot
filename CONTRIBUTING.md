# Contributing to RadiusPilot

Thanks for your interest. RadiusPilot is deliberately small and security-focused,
so contributions are held to a few clear rules.

## Scope

RadiusPilot administers the VPN accounts that a Cisco ISR authenticates through
FreeRADIUS and Duo. Keep changes within that scope: listing, creating, renaming,
blocking, deleting and enrolling accounts; per-user Duo enforcement; validated
custom IPv4 access policies and reusable access objects; live-session views from
RADIUS accounting; and the console's own security. It is not a general-purpose
identity platform, and it must stay deployable on plain Debian without a
database.

Please read [AGENTS.md](AGENTS.md) before proposing a change — it states the
security boundaries the project will not cross.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/pytest --cov=radius_user_admin --cov-fail-under=65
.venv/bin/ruff check .
```

Run the console locally against a fake helper (never the live FreeRADIUS):

```bash
RADIUS_ADMIN_HELPER=tests/fake_helper.py \
RADIUS_ADMIN_SESSION_SECRET=development-only \
.venv/bin/uvicorn radius_user_admin.app:app --reload
```

## Ground rules

- **Never expose secrets.** No passwords, RADIUS shared secrets, Duo keys,
  activation links or invitation tokens in HTML, logs, command-line arguments,
  helper output, audit records or tests.
- **Privileged writes go through the helper.** The web process runs as
  `radiusui` and can only reach state through `radius-user-admin-helper` over
  `sudo`. Do not widen that boundary.
- **Every mutation validates and rolls back.** Validate FreeRADIUS (and any
  changed Duo config) and restore all managed files if validation or restart
  fails.
- **Fail closed.** Unknown or corrupt state must never silently become
  full access or an enabled account.
- **Tests use temporary files and fake service commands.** They must never touch
  a live FreeRADIUS, Duo, or the network.
- **Keep static assets local.** No CDN dependency in production.

## Pull requests

- Keep changes focused and covered by tests. CI runs Ruff, the test suite with a
  coverage floor, dependency auditing and CodeQL; all must pass.
- Describe the security impact of the change, if any.
- Report vulnerabilities privately through the Security tab, not in a public
  issue or pull request (see [SECURITY.md](SECURITY.md)).
