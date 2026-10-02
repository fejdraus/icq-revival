#!/bin/sh
# Installs the auditor of an ICQ Revival server's key transparency log on a
# Linux machine with systemd (docs/e2e/KEY-TRANSPARENCY.md, stage 2; README.md
# next to this script). Run as root, from a folder holding this script,
# e2e-kt-auditor.service and the auditor binary for this machine
# (e2e-kt-auditor-linux-amd64 or -arm64, or just e2e-kt-auditor):
#
#   sudo sh install.sh <server domain> <auditor name>
#   sudo sh install.sh icq.example.org auditor-2.example.net/icq
#
# It puts the binary in /usr/local/bin, makes the system user e2e-kt-auditor,
# writes /etc/e2e-kt-auditor.env, makes the auditor's key on the first run
# (/var/lib/e2e-kt-auditor/auditor.key), prints its verifier key for the
# server's E2E_KT_AUDITORS, and enables and starts the unit. Running it again
# updates the binary and the unit and keeps the key.
set -eu

die() { echo "install.sh: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: sudo sh install.sh <server domain> <auditor name>"
DOMAIN=$1
NAME=$2
HERE=$(cd "$(dirname "$0")" && pwd)
USER_NAME=e2e-kt-auditor
STATE=/var/lib/e2e-kt-auditor
ENV_FILE=/etc/e2e-kt-auditor.env
UNIT=/etc/systemd/system/e2e-kt-auditor.service
BIN=/usr/local/bin/e2e-kt-auditor

[ "$(id -u)" -eq 0 ] || die "run it as root (sudo)"
command -v systemctl >/dev/null || die "systemd is needed"
case $DOMAIN in
    ''|*/*|*:*|*' '*) die "give the server's domain only, such as icq.example.org" ;;
esac
case $NAME in
    ''|*' '*|*+*) die "the auditor's name must have no spaces or plus signs, such as auditor-2.example.net/icq" ;;
esac

case $(uname -m) in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "no auditor binary is built for $(uname -m)" ;;
esac
SRC=
for f in "$HERE/e2e-kt-auditor-linux-$ARCH" "$HERE/e2e-kt-auditor"; do
    if [ -f "$f" ]; then SRC=$f; break; fi
done
[ -n "$SRC" ] || die "e2e-kt-auditor-linux-$ARCH is not next to this script"
[ -f "$HERE/e2e-kt-auditor.service" ] || die "e2e-kt-auditor.service is not next to this script"

# The key ID depends on the name: another name would be another key for the
# server, so a name once given stays.
if [ -f "$ENV_FILE" ]; then
    OLD_NAME=$(sed -n 's/^E2E_KT_AUDITOR_NAME=//p' "$ENV_FILE")
    if [ -n "$OLD_NAME" ] && [ "$OLD_NAME" != "$NAME" ]; then
        die "this machine's auditor is named $OLD_NAME already; its key is known under that name. Remove $ENV_FILE first to rename it (the server then needs the new key)."
    fi
fi

if systemctl is-active --quiet e2e-kt-auditor.service; then
    systemctl stop e2e-kt-auditor.service
fi
install -m 0755 "$SRC" "$BIN"

if ! id "$USER_NAME" >/dev/null 2>&1; then
    NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" "$USER_NAME"
fi
install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$STATE"

umask 022
cat >"$ENV_FILE" <<EOF
# Written by install.sh. The server's key directory, and this auditor's name.
E2E_KT_LOG=https://$DOMAIN:8102/e2e/v1/
E2E_KT_AUDITOR_NAME=$NAME
EOF
install -m 0644 "$HERE/e2e-kt-auditor.service" "$UNIT"

# Made on the first run, as the user the unit runs as, so it can read it.
KEY=$(runuser -u "$USER_NAME" -- "$BIN" -name "$NAME" -key "$STATE/auditor.key" -print-key)

# Whether the server is in reach: only a warning, the unit retries anyway.
if command -v curl >/dev/null; then
    if ! curl -fsS --max-time 15 -o /dev/null "https://$DOMAIN:8102/e2e/v1/log/checkpoint"; then
        echo "install.sh: warning: https://$DOMAIN:8102/e2e/v1/log/checkpoint could not be read from here" >&2
    fi
fi

systemctl daemon-reload
systemctl enable --now e2e-kt-auditor.service

cat <<EOF

The auditor runs (journalctl -u e2e-kt-auditor -f). Its verifier key, for the
server's E2E_KT_AUDITORS (comma-separated, next to the keys already there):

$KEY

Until the server has it, each look ends in "not cosigned this time ... 403";
that is expected.

Back up $STATE/auditor.key now, somewhere off this machine: it is
this auditor's identity. Lost, the auditor needs a new key, and every client
that pinned the old one sees it silent from then on.
EOF
