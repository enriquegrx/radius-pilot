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
