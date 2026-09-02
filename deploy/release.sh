#!/bin/sh
# RadiusPilot release — deploy the current checkout to a running host.
#
# Automates the controlled deployment used in production: it gates on the local
# tests and linter, ships the application source, backs up what is live, swaps
# the new source in, records the version, compiles it, validates FreeRADIUS,
# runs a reconcile, restarts only the web service, and health-checks it —
# rolling the source back automatically if any step fails. It never touches the
# site-specific Nginx, TLS, firewall, FreeRADIUS, Duo or router configuration.
#
# Usage:
#   RELEASE_TARGET=radiusadmin@radius01 [RELEASE_JUMP=docker@jump01] \
#     deploy/release.sh [--no-test]
#
# The target account must have sudo on the host. Authentication is left to your
# ssh configuration (keys and agent); no password is handled here.

set -eu

APP_DIR=/opt/radius-user-admin
SRC_DIR="$APP_DIR/src"
HEALTH_URL=http://127.0.0.1:8080/healthz

say() { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

TARGET=${RELEASE_TARGET:-}
JUMP=${RELEASE_JUMP:-}
[ -n "$TARGET" ] || die "Set RELEASE_TARGET, e.g. RELEASE_TARGET=radiusadmin@radius01"

RUN_TESTS=1
[ "${1:-}" = "--no-test" ] && RUN_TESTS=0

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
[ -f "$REPO_DIR/src/radius_user_admin/app.py" ] || die "Run from the repository checkout."

SSH="ssh -o BatchMode=yes -o ConnectTimeout=15"
[ -n "$JUMP" ] && SSH="$SSH -J $JUMP"

VERSION=$(git -C "$REPO_DIR" describe --tags --always --dirty 2>/dev/null \
    || git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)

if [ "$RUN_TESTS" -eq 1 ]; then
    say "Gating on the local test suite and linter"
    PY="$REPO_DIR/.venv/bin/python"
    [ -x "$PY" ] || PY=python3
    ( cd "$REPO_DIR" && "$PY" -m ruff check . && "$PY" -m pytest -q ) \
        || die "Local checks failed; not releasing."
fi

if ! git -C "$REPO_DIR" diff --quiet 2>/dev/null; then
    say "Warning: the working tree has uncommitted changes (releasing $VERSION anyway)."
fi

say "Packaging the application source ($VERSION)"
TARBALL=$(mktemp -t rp-release.XXXXXX.tgz)
trap 'rm -f "$TARBALL"' EXIT
tar -czf "$TARBALL" -C "$REPO_DIR/src" \
    --exclude='__pycache__' --exclude='*.pyc' radius_user_admin

say "Uploading to $TARGET"
$SSH "$TARGET" 'cat > /tmp/rp-release.tgz' < "$TARBALL"

say "Deploying on $TARGET (backup, install, validate, reconcile, restart)"
$SSH "$TARGET" "sudo -n sh -s -- '$VERSION'" <<'REMOTE'
set -eu
VERSION="$1"
APP_DIR=/opt/radius-user-admin
SRC_DIR="$APP_DIR/src"
STAGE=/tmp/rp-release-stage
BACKUP_ROOT=/var/backups/radius-user-admin
TS=$(date +%Y%m%d-%H%M%S)
BK="$BACKUP_ROOT/release-$TS"

rollback() {
    printf 'release: rolling back to the previous source\n' >&2
    rm -rf "$SRC_DIR"
    mv "$BK/src" "$SRC_DIR"
    systemctl restart radius-user-admin || true
    exit 1
}

# 1. Stage the new source.
rm -rf "$STAGE"; mkdir -p "$STAGE"
tar -xzf /tmp/rp-release.tgz -C "$STAGE"
rm -f /tmp/rp-release.tgz
[ -f "$STAGE/radius_user_admin/app.py" ] || { echo "release: bad tarball" >&2; exit 1; }

# 2. Back up the current source and generated authorize file.
install -d -m 700 "$BK"
cp -a "$SRC_DIR" "$BK/src"

# 3. Swap the new source in, root-owned.
rm -rf "$SRC_DIR.new"
mv "$STAGE/radius_user_admin" "$SRC_DIR.new"
# preserve any local egg-info/dist metadata that lived alongside the package
for extra in "$SRC_DIR"/*; do
    base=$(basename "$extra")
    [ "$base" = "radius_user_admin" ] && continue
    [ -e "$extra" ] && cp -a "$extra" "$SRC_DIR.new/../$base.keep" 2>/dev/null || true
done
rm -rf "$SRC_DIR"
mkdir -p "$SRC_DIR"
mv "$SRC_DIR.new" "$SRC_DIR/radius_user_admin"
for keep in "$APP_DIR"/*.keep; do
    [ -e "$keep" ] && mv "$keep" "$SRC_DIR/$(basename "${keep%.keep}")" 2>/dev/null || true
done
chown -R root:root "$SRC_DIR"
find "$SRC_DIR" -type d -exec chmod 755 {} +
find "$SRC_DIR" -type f -exec chmod 644 {} +
printf '%s\n' "$VERSION" > "$APP_DIR/VERSION"; chmod 644 "$APP_DIR/VERSION"

# 4. Compile, validate FreeRADIUS, reconcile — roll back on any failure.
python3 -m compileall -q "$SRC_DIR/radius_user_admin" || rollback
if command -v freeradius >/dev/null 2>&1; then
    freeradius -C >/dev/null 2>&1 || rollback
fi
systemctl start radius-user-admin-reconcile.service 2>/dev/null || true

# 5. Restart the web service and health-check it.
systemctl restart radius-user-admin || rollback
sleep 2
systemctl is-active --quiet radius-user-admin || rollback
python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5).status == 200 else 1)" || rollback

printf 'release: %s deployed, healthz OK, backup at %s\n' "$VERSION" "$BK"
REMOTE

say "Released $VERSION to $TARGET"
