#!/bin/sh
set -eu

certificate=/var/tmp/radius-user-admin-cert/fullchain.pem
private_key_file=/var/tmp/radius-user-admin-cert/privkey.pem
[ "$#" -eq 0 ] || exit 64
[ -f "$certificate" ] && [ -f "$private_key_file" ] || exit 65

openssl x509 -in "$certificate" -noout -checkend 86400 >/dev/null
openssl x509 -in "$certificate" -noout -ext subjectAltName | grep -Fq 'DNS:radius.your-domain.com'
certificate_key=$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum)
private_key=$(openssl pkey -in "$private_key_file" -pubout -outform DER 2>/dev/null | sha256sum)
[ "$certificate_key" = "$private_key" ]

install -d -o root -g root -m 700 /etc/ssl/radius-user-admin
install -o root -g root -m 644 "$certificate" /etc/ssl/radius-user-admin/fullchain.pem.new
install -o root -g root -m 600 "$private_key_file" /etc/ssl/radius-user-admin/privkey.pem.new
mv /etc/ssl/radius-user-admin/fullchain.pem.new /etc/ssl/radius-user-admin/fullchain.pem
mv /etc/ssl/radius-user-admin/privkey.pem.new /etc/ssl/radius-user-admin/privkey.pem
nginx -t
systemctl reload nginx
rm -rf /var/tmp/radius-user-admin-cert
