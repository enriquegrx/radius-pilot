# Roadmap

Tracked ideas for RadiusPilot, grouped by theme. Not a commitment — a backlog.
Items are checked off as they ship.

## Operations and reliability

1. [ ] **Off-host backups.** Everything lives on the application host's disk:
   state, the generated `authorize` file and `/var/backups`. A nightly job
   should replicate the backups, encrypted, to a separate host with a
   write-only key so a disk failure does not lose data and its snapshots at
   once.
2. [ ] **Monitoring and alerting.** Nothing watches `/healthz`, the
   reconciliation timer or the certificate lifetime. Add external monitoring
   (health endpoint, cert expiry, reconcile result) with a notification path.
3. [ ] **Template render smoke test in CI.** Render the dashboard with a
   representative context so a bad template change cannot ship a 500.
4. [ ] **Versioned release script.** Automate the controlled deployment
   sequence (dated backup, install, compile, validate, restart, health check)
   as a reviewable script instead of manual steps.
5. [ ] **Show the deployed version in the panel.** A footer with the running
   commit so operators can see what is live without inspecting the host.
6. [ ] **Key-based management access.** Replace password SSH for deployment
   with a dedicated deploy key and a source allowlist.

## Security and robustness

7. [ ] **Require an explicit destination allowlist when custom access is
   enabled.** Today an unset `RADIUS_ADMIN_POLICY_DESTINATIONS` falls back to
   all of RFC1918; couple the feature gate to a narrowed scope.
8. [ ] **Restore-path tests.** The backup restore flow has the least coverage
   of the critical paths.
9. [ ] **Assisted RADIUS shared-secret rotation.** Rotating the secret across
   the router, proxy and FreeRADIUS is manual and easy to get wrong.

## Features

10. [ ] **Live "online now".** RADIUS accounting (router `aaa accounting`,
    firewall rule, FreeRADIUS listener) feeding a dashboard count plus assigned
    IP and session duration on the user record.
11. [x] **Activity filtered by user.** Jump from a user's row to the audit and
    authentication history scoped to that account.
12. [x] **Expiry warning emails.** Reuse the optional SMTP integration to warn
    a set number of days before an account expires.
13. [ ] **QR codes for invitations.** Show the one-time invitation link as a QR
    code for direct scanning, rendered locally with no CDN. (Needs a QR
    encoder — a small vendored JS library or a pure-Python dependency.)
14. [ ] **Side-drawer user management.** An alternative to the inline
    contextual actions once the user count grows. (Deferred: the inline
    contextual actions already cover this well.)
15. [x] **Export and import access objects.** Move the saved-object library
    between deployments.
16. [x] **Dark mode.** A theme toggle that persists per browser.
17. [x] **Search and pagination.** For the user list and the activity tables as
    they grow.

## Adoption

18. [ ] **Debian-native installer.** Automate the runbook with the same
    validations so the public repository is straightforward to deploy.
19. [ ] **Screenshots in the README.** A picture of the console alongside the
    feature list.
20. [ ] **Contributor guide and higher coverage gate.** A `CONTRIBUTING.md`
    and a raised coverage floor (currently 55%, actual is higher).
