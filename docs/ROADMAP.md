# Roadmap

Tracked ideas for RadiusPilot, grouped by theme. Not a commitment — a backlog.
Items are checked off as they ship.

## Operations and reliability

1. [ ] **Off-host backups.** Everything lives on the application host's disk:
   state, the generated `authorize` file and `/var/backups`. A nightly job
   should replicate the backups, encrypted, to a separate host with a
   write-only key so a disk failure does not lose data and its snapshots at
   once.
2. [x] **Monitoring and alerting.** The reconciler emails the administrator when
   the service degrades (a service down, invalid configuration, the certificate
   within the warning window, or low disk) and when it recovers, once per state
   change. External box-down monitoring can still be layered on separately.
3. [x] **Template render smoke test in CI.** The dashboard is rendered with a
   varied, edge-case context so a bad template change cannot ship a 500.
4. [x] **Versioned release script.** `deploy/release.sh` gates on the tests and
   linter, then backs up, installs, records the version, validates, reconciles,
   restarts and health-checks the running host, rolling back on any failure.
5. [x] **Show the deployed version in the panel.** A footer shows the running
   version, from `RADIUS_ADMIN_VERSION` or the `VERSION` file the installer and
   release script write with the git commit.
6. [ ] **Key-based management access.** Replace password SSH for deployment
   with a dedicated deploy key and a source allowlist.

## Security and robustness

7. [x] **Require an explicit destination allowlist when custom access is
   enabled.** Custom access stays gated until `RADIUS_ADMIN_POLICY_DESTINATIONS`
   is set explicitly, so it never compiles against all of RFC1918.
8. [x] **Restore-path tests.** The restore flow now has tests for revert,
   invalid names, empty snapshots and corrupt policies.
9. [ ] **Assisted RADIUS shared-secret rotation.** Rotating the secret across
   the router, proxy and FreeRADIUS is manual and easy to get wrong.

## Live-session features (built on RADIUS accounting)

- [x] **Disconnect a session (RADIUS CoA).** A Disconnect button on each online
   user asks the gateway to drop the session via CoA Disconnect-Request. Needs
   dynamic-author on the gateway and the CoA env settings.
- [x] **Connection history per user.** Recent connections (start, end, duration,
   IP, usage) reconstructed from accounting, shown in the user's row.
- [x] **Data usage per session.** Upload/download totals in the live-session
   block, from the accounting octet counters.
- [x] **Concurrent-session warning.** Users with multiple simultaneous sessions
   are flagged with a badge, a dashboard metric, and a note.
- [x] **Auto-refreshing online status.** The console polls a lightweight
   sessions endpoint and updates the online count and badges without a reload.

## Features

10. [x] **Live "online now".** RADIUS accounting feeds an "online now" count, an
    Online badge per connected user, and the assigned IP and session duration
    on the user record. Ships the RadiusPilot side plus the gateway, firewall
    and FreeRADIUS configuration to enable it.
11. [x] **Activity filtered by user.** Jump from a user's row to the audit and
    authentication history scoped to that account.
12. [x] **Expiry warning emails.** Reuse the optional SMTP integration to warn
    a set number of days before an account expires.
13. [x] **QR codes for invitations.** Show the one-time invitation link as a QR
    code for direct scanning, rendered locally with segno (no CDN).
14. [ ] **Side-drawer user management.** An alternative to the inline
    contextual actions once the user count grows. (Deferred: the inline
    contextual actions already cover this well.)
15. [x] **Export and import access objects.** Move the saved-object library
    between deployments.
16. [x] **Dark mode.** A theme toggle that persists per browser.
17. [x] **Search and pagination.** For the user list and the activity tables as
    they grow.

## Adoption

18. [x] **Debian-native installer.** `deploy/install.sh` installs the app, the
    service account, the helper and its sudoers rule, the systemd unit and
    timer, and the state directory, idempotently and with validation.
19. [x] **Screenshots in the README.** The console and the sign-in page.
20. [x] **Contributor guide and higher coverage gate.** `CONTRIBUTING.md` and a
    coverage floor raised to 65% (actual ~69%).

## Resilience, security and self-service (proposed 2026-09-02)

21. [ ] **Break-glass for a Duo outage.** Duo is the only second factor, so a
    Duo cloud or Authentication Proxy outage locks everyone out of the VPN. Add
    a sealed, single-use break-glass credential (email alert when used,
    auto-expiring) and/or an explicit, time-boxed fail-open toggle for one
    administrator during an incident. Highest operational risk today.
22. [ ] **End-to-end synthetic auth canary.** The monitor proves the service is
    up, not that the whole chain works. Have the reconcile timer run a full
    `radclient` Access-Request against a dedicated test principal and surface
    "last real authentication OK: N min ago" in the System card, so a silent
    break in router → Duo proxy → FreeRADIUS → hash is caught before a user hits
    it.
23. [ ] **Self-service user portal.** A minimal, self-scoped page where a VPN
    user can re-enroll in Duo (QR), change their own password (with the current
    one), see their own sessions and usage, and download the AnyConnect profile
    — cutting the administrator out of routine requests.
24. [ ] **Tamper-evident audit log.** Chain a rolling hash per audit line
    (append-only, verifiable with one command) and optionally forward to syslog,
    so entries cannot be silently altered — without needing a database.
25. [ ] **Access anomaly alerts.** Email when a user connects from a new IP or
    country (from the `Calling-Station-Id` already parsed plus an offline GeoIP
    database), or on impossible travel.
26. [ ] **Brute-force lockout.** Count rejects in the FreeRADIUS auth log and
    auto-disable an account after N failures, with unlock from the panel.
27. [ ] **Router config-drift detection.** Using the existing SSH access,
    periodically compare the ISR `aaa` / `radius` / accounting configuration
    against the expected baseline and alert on drift.
28. [ ] **Periodic usage report.** A weekly or monthly email/CSV: who connected,
    how much data, and session counts.

## Visual dashboard (shipped 2026-09-02)

An Overview tab and a full-screen `/wall` NOC display, all rendered as
dependency-free inline SVG from a single accounting-derived `dashboard` payload
(no database, no CDN, no charting library):

29. [x] **Live connection map.** Sessions geolocated from their client IP
    (offline resolver in `geoip.py`; optional GeoLite2 CSV) and plotted with
    pulsing dots and arcs to the gateway. Private/LAN clients are not plotted.
30. [x] **NOC wall display.** `/wall` — a dark, auto-refreshing operations board
    with big KPIs, the map, the auth-path diagram and a live session list.
31. [x] **Usage and session charts.** Concurrent-sessions-over-24h area,
    connections-by-hour and last-14-days bars, top talkers, and metric-card
    sparklines with day-over-day trend arrows.
32. [x] **Activity heatmap.** Weekday × hour grid of connection starts.
33. [x] **Today's session timeline.** A Gantt of who was connected and when,
    with live sessions highlighted.
34. [x] **Live architecture diagram.** Cisco ISR → Duo Proxy → FreeRADIUS → Duo
    Cloud with per-component health and an animated flow.

## Country-based access policy (geo-fencing)

Restrict logins by the country of the client's public IP — a global default with
per-user overrides, region presets (EU/EEA, Schengen, Spain) plus per-country
allow/remove, and a fail-open/closed choice. A compliance control, not a hard
boundary (a VPN/proxy in an allowed country bypasses it); worldwide accuracy
needs a GeoLite2 database.

35. [x] **Monitor mode.** The console evaluates what the policy *would* decide for
    recent authentications and live sessions, entirely from the Duo proxy's auth
    log — no change to the auth path, zero lock-out risk. Shows a "would block"
    feed and a per-user country policy tile.
36. [x] **Enforcement (FreeRADIUS hook).** `deploy/radius-pilot-geo-check`, a
    fail-safe rlm_exec hook, rejects disallowed countries before the Duo push,
    driven by the per-user allow-lists RadiusPilot compiles to
    `radius-pilot-geo-policy.json` on every change. It logs in monitor mode and
    only rejects in enforce mode; any error, timeout or non-enforce mode allows
    the login. Worldwide country resolution uses an optional GeoLite2 mmdb
    (`RADIUS_ADMIN_GEOIP_MMDB`). Wiring it into a site stays a deliberate manual
    step (`deploy/freeradius-geo-check.conf`).
