#!/bin/bash
# Makes the private certificate authority and the server certificate that AIM
# needs, into /certs:
#
#   server.pem  certificate and key in one file, what nginx serves on the ports
#               AIM connects to (1443 Kerberos, 8443 web API, 3143 OSCAR)
#   ca.crt      the authority, to be trusted on the client side
#   nss/        a certificate database in the legacy dbm format AIM 6 reads,
#               with the authority in it - copied into the client's profile
#
# AIM checks the server against its own NSS store and knows nothing about
# Let's Encrypt, and its library of 2011 cannot read the ECDSA certificates
# Let's Encrypt issues today, hence a private RSA authority. Everything else -
# Miranda, browsers - gets the public certificate instead.
#
# Runs in the image built from Dockerfile.certgen. Leaves existing files alone,
# so rerunning it never invalidates what clients already trust.
set -euo pipefail

: "${PUBLIC_HOST:?set PUBLIC_HOST to the server name clients connect to}"
BITS="${CERT_KEY_BITS:-2048}"
DAYS="${CERT_DAYS:-3650}"
cd /certs

if [ -f server.pem ]; then
    echo "server.pem already exists, nothing to do"
    exit 0
fi

openssl req -x509 -newkey "rsa:$BITS" -keyout ca-key.pem -out ca.crt \
    -sha256 -days "$DAYS" -nodes -subj "/CN=ICQ Revival Root CA"

openssl req -newkey "rsa:$BITS" -keyout key.pem -out server.csr \
    -sha256 -nodes -subj "/CN=$PUBLIC_HOST"

# The AOL names are what AIM asks for when it has not been pointed anywhere
# else; they cost nothing to include.
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$PUBLIC_HOST,DNS:api.oscar.aol.com,DNS:api.screenname.aol.com,DNS:login.oscar.aol.com,DNS:my.screenname.aol.com,DNS:api.aim.net,DNS:api.icq.net,DNS:api.login.icq.net
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca-key.pem -CAcreateserial \
    -out cert.pem -sha256 -days "$DAYS" -extfile server.ext

cat cert.pem key.pem > server.pem
chmod 600 server.pem

rm -rf nss && mkdir nss
certutil -N -d nss --empty-password
certutil -A -n "ICQ Revival Root CA" -t "CT,,C" -i ca.crt -d nss

# The authority's key is not needed again until the server certificate expires
# in ten years; keeping it next to the certificates it signs is a risk for no
# gain.
rm -f cert.pem key.pem ca-key.pem server.csr server.ext ca.srl
echo "made server.pem, ca.crt and nss/ for $PUBLIC_HOST"
