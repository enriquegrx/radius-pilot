#!/bin/sh
set -eu

[ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/radius.your-domain.com" ] || exit 0

destination="radiusadmin@192.0.2.112"
known_hosts="/etc/letsencrypt/deploy-targets/radius01_known_hosts"
ssh_key="/etc/letsencrypt/deploy-targets/radius01_ed25519"
stage="/var/tmp/radius-user-admin-cert"

cleanup() {
  ssh -i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$known_hosts" "$destination" "rm -rf '$stage'" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ssh -i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$known_hosts" "$destination" "install -d -m 700 '$stage'"
scp -i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$known_hosts" \
  "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" "$destination:$stage/"
ssh -i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$known_hosts" "$destination" \
  "sudo -n /usr/local/sbin/install-radius-user-admin-certificate"
