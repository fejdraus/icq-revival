#!/bin/bash
# Renews the Tailscale TLS certificate for OSCAR.
# tailscale cert decides by itself whether to reissue: if more than a month
# is left before expiry, it just hands back the existing one and exits 0.
#
# The certificate is served by nginx in the oscar-nginx container (port 5193,
# modern clients). The copy goes next to its config via cp: the file is
# mounted into the container on its own, and replacing it with a new inode
# would not be visible to the container.
set -euo pipefail

DOMAIN="${OSCAR_TLS_DOMAIN:?set OSCAR_TLS_DOMAIN to the server's host name}"
CERT="/etc/oscar-tls/ts-cert.pem"
KEY="/etc/oscar-tls/ts-key.pem"
NGINX_CERTS="/etc/oscar-nginx/certs"

before=""
if [ -f "$CERT" ]; then
  before=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null || true)
fi

/usr/bin/tailscale cert --cert-file "$CERT" --key-file "$KEY" "$DOMAIN"

chown oscar:oscar "$CERT" "$KEY"
chmod 644 "$CERT"
chmod 600 "$KEY"

after=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null || true)

if [ "$before" = "$after" ]; then
  echo "certificate unchanged ($after), no reload needed"
  exit 0
fi

echo "certificate renewed: $after"

cp "$CERT" "$NGINX_CERTS/ts-cert.pem"
cp "$KEY" "$NGINX_CERTS/ts-key.pem"
chown root:root "$NGINX_CERTS/ts-cert.pem" "$NGINX_CERTS/ts-key.pem"
chmod 644 "$NGINX_CERTS/ts-cert.pem"
chmod 600 "$NGINX_CERTS/ts-key.pem"

if docker exec oscar-nginx nginx -s reload; then
  echo "nginx reloaded the certificate"
else
  echo "failed to reload the nginx config; check the oscar-nginx container" >&2
  exit 1
fi
