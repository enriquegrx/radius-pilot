#!/bin/sh
# RadiusPilot installer — Debian-native, idempotent.
#
# Installs the application, its unprivileged service account, the root helper
# and its exact sudoers rule, the systemd unit and reconciliation timer, and a
# root-only state directory. It never overwrites an existing environment file or
# state, validates FreeRADIUS before enabling the service, and rolls nothing out
# to the WAN.
#
# Run as root from a checkout of the repository:
#     sudo deploy/install.sh
#
# It deliberately does NOT touch the site-specific pieces — Nginx, the TLS
# certificate, nftables, FreeRADIUS listeners, the Duo Authentication Proxy, or
# the router. Those stay manual (see README.md and docs/cisco-isr-freeradius.md);
# the matching example files live next to this script.

set -eu

APP_DIR=/opt/radius-user-admin
SRC_DIR="$APP_DIR/src"
STATE_DIR=/var/lib/radius-user-admin
BACKUP_DIR=/var/backups/radius-user-admin
CONF_DIR=/etc/radius-user-admin
HELPER=/usr/local/sbin/radius-user-admin-helper
SERVICE_USER=radiusui
RADACCT_DIR=/var/log/freeradius/radacct

say() { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$1" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this installer as root (sudo)."
command -v systemctl >/dev/null 2>&1 || die "systemd is required."
command -v python3 >/dev/null 2>&1 || die "python3 is required."

# Locate the repository root from this script's location.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
[ -f "$REPO_DIR/src/radius_user_admin/app.py" ] || die "Run from the repository checkout."

say "Installing Python dependencies (Debian packages)"
DEPS="python3-fastapi python3-uvicorn python3-jinja2 python3-multipart python3-itsdangerous python3-segno"
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y $DEPS >/dev/null 2>&1 \
        || warn "Could not apt-get all of: $DEPS — install them before starting the service."
else
    warn "apt-get not found; ensure these Python modules are importable: $DEPS"
fi

say "Creating the service account and directories"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g root -m 755 "$APP_DIR"
install -d -o root -g root -m 700 "$STATE_DIR"
install -d -o root -g root -m 700 "$BACKUP_DIR"
install -d -o root -g "$SERVICE_USER" -m 750 "$CONF_DIR"
install -d -o freerad -g freerad -m 750 "$RADACCT_DIR" 2>/dev/null \
    || install -d -o root -g root -m 750 "$RADACCT_DIR"

say "Installing the application source to $SRC_DIR"
rm -rf "$SRC_DIR.new"
cp -a "$REPO_DIR/src" "$SRC_DIR.new"
find "$SRC_DIR.new" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$SRC_DIR"
mv "$SRC_DIR.new" "$SRC_DIR"
chown -R root:root "$SRC_DIR"
find "$SRC_DIR" -type d -exec chmod 755 {} +
find "$SRC_DIR" -type f -exec chmod 644 {} +
python3 -m compileall -q "$SRC_DIR" || die "The application source failed to compile."

# Record the deployed version so the console can show what is running.
if git -C "$REPO_DIR" rev-parse HEAD >/dev/null 2>&1; then
    git -C "$REPO_DIR" describe --tags --always --dirty 2>/dev/null \
        > "$APP_DIR/VERSION" 2>/dev/null \
        || git -C "$REPO_DIR" rev-parse --short HEAD > "$APP_DIR/VERSION"
    chmod 644 "$APP_DIR/VERSION"
fi

say "Installing the privileged helper and its sudoers rule"
install -o root -g root -m 750 "$SCRIPT_DIR/radius-user-admin-helper" "$HELPER"
install -o root -g root -m 440 "$SCRIPT_DIR/radius-user-admin.sudoers" \
    /etc/sudoers.d/radius-user-admin
visudo -cf /etc/sudoers.d/radius-user-admin >/dev/null \
    || die "The installed sudoers rule is invalid."

say "Installing the systemd unit and reconciliation timer"
install -o root -g root -m 644 "$SCRIPT_DIR/radius-user-admin.service" \
    /etc/systemd/system/radius-user-admin.service
install -o root -g root -m 644 "$SCRIPT_DIR/radius-user-admin-reconcile.service" \
    /etc/systemd/system/radius-user-admin-reconcile.service
install -o root -g root -m 644 "$SCRIPT_DIR/radius-user-admin-reconcile.timer" \
    /etc/systemd/system/radius-user-admin-reconcile.timer
systemctl daemon-reload

if [ ! -f "$CONF_DIR/environment" ]; then
    say "Creating $CONF_DIR/environment from the example"
    install -o root -g "$SERVICE_USER" -m 640 "$SCRIPT_DIR/environment.example" \
        "$CONF_DIR/environment"
    SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    if grep -q '^RADIUS_ADMIN_SESSION_SECRET=' "$CONF_DIR/environment"; then
        sed -i "s|^RADIUS_ADMIN_SESSION_SECRET=.*|RADIUS_ADMIN_SESSION_SECRET=$SECRET|" \
            "$CONF_DIR/environment"
    else
        printf 'RADIUS_ADMIN_SESSION_SECRET=%s\n' "$SECRET" >> "$CONF_DIR/environment"
    fi
    warn "Edit $CONF_DIR/environment: set the real HTTPS URL, allowed hosts and"
    warn "  RADIUS_ADMIN_AUTHORIZE_PATH before starting the service."
else
    say "Keeping the existing $CONF_DIR/environment"
fi

say "Reference (site-specific, not applied automatically):"
cat <<EOF
  - Nginx:     $SCRIPT_DIR/nginx-radius-user-admin.conf   (restrict source networks, add TLS)
  - Firewall:  $SCRIPT_DIR/nftables.conf                  (loopback app, HTTPS + RADIUS allowlist)
  - FreeRADIUS/Duo/accounting/CoA and the certificate: see docs/cisco-isr-freeradius.md
EOF

cat <<EOF

Next steps:
  1. Finish $CONF_DIR/environment (HTTPS URL, allowed hosts, authorize path).
  2. Bootstrap state from the live authorize file:
       printf '{}\\n' | sudo -u $SERVICE_USER sudo -n $HELPER bootstrap
  3. Create the first panel administrator:
       printf '{"username":"you","password":"a-long-console-password"}\\n' \\
         | sudo $HELPER bootstrap-admin
  4. Validate FreeRADIUS, then enable the service and timer:
       freeradius -C
       systemctl enable --now radius-user-admin.service radius-user-admin-reconcile.timer
       curl -sf http://127.0.0.1:8080/healthz && echo OK

RadiusPilot is installed. It will not answer until Nginx publishes it over HTTPS
to the approved networks — never bind Uvicorn to a LAN address or add public NAT.
EOF
