#!/bin/bash
# Обновление TLS-сертификата Tailscale для OSCAR.
# tailscale cert сам понимает, нужно ли перевыпускать: если до истечения
# больше месяца, он просто отдаёт существующий и выходит с кодом 0.
#
# Сертификат отдаёт nginx в контейнере oscar-nginx (порт 5193 — современные
# клиенты). Копию кладём рядом с его конфигом через cp: файл примонтирован
# в контейнер по отдельности, и замена его новым inode контейнеру не видна.
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
  echo "сертификат не менялся ($after), перезапуск не нужен"
  exit 0
fi

echo "сертификат обновлён: $after"

cp "$CERT" "$NGINX_CERTS/ts-cert.pem"
cp "$KEY" "$NGINX_CERTS/ts-key.pem"
chown root:root "$NGINX_CERTS/ts-cert.pem" "$NGINX_CERTS/ts-key.pem"
chmod 644 "$NGINX_CERTS/ts-cert.pem"
chmod 600 "$NGINX_CERTS/ts-key.pem"

if docker exec oscar-nginx nginx -s reload; then
  echo "nginx перечитал сертификат"
else
  echo "не удалось перечитать конфиг nginx — проверьте контейнер oscar-nginx" >&2
  exit 1
fi
