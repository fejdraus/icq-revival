#!/bin/bash
# Backs up the Open OSCAR Server database.
# Uses SQLite's VACUUM INTO (through node:sqlite, below): it makes a consistent
# copy of a running server without stopping the service.
#
#   oscar-backup.sh             the daily copy into $OSCAR_BACKUP_DEST, rotated
#   oscar-backup.sh --stdout    a fresh gzipped copy to stdout, nothing kept;
#                               for icq-backup-stream, which encrypts it later
#   oscar-backup.sh --encrypt   encrypts stdin to stdout for the recipients
#                               below; refuses when there are none
#
# Encryption at rest: OSCAR_BACKUP_AGE_RECIPIENTS holds one or more age public
# keys (age1..., made with age-keygen), separated by commas or spaces. With it
# set, the daily copy is written only as oscar-<date>.sqlite.gz.age; if the
# encryption fails, nothing is kept and the script fails. Without it, the copy
# is a plain oscar-<date>.sqlite.gz, as before, with a warning. The private
# key never comes near the server: see deploy/docker/README.md, "Backups".
set -euo pipefail

# These can be overridden, which is how the container runs it; the defaults
# are the paths of a systemd installation.
DB="${OSCAR_BACKUP_DB:-/var/lib/open-oscar-server/oscar.sqlite}"
DEST="${OSCAR_BACKUP_DEST:-/var/backups/open-oscar-server}"
KEEP_DAYS="${OSCAR_BACKUP_KEEP_DAYS:-14}"
RECIPIENTS="${OSCAR_BACKUP_AGE_RECIPIENTS:-}"

# Builds the age arguments: -r <key> for every recipient.
age_args=()
for r in ${RECIPIENTS//,/ }; do
    age_args+=(-r "$r")
done

# Encrypts stdin to stdout; fails without recipients or when age does.
encrypt() {
    if [ "${#age_args[@]}" -eq 0 ]; then
        echo "oscar-backup: no OSCAR_BACKUP_AGE_RECIPIENTS, refusing to encrypt" >&2
        return 1
    fi
    if ! command -v age >/dev/null 2>&1; then
        echo "oscar-backup: age is not installed" >&2
        return 1
    fi
    age "${age_args[@]}"
}

if [ "${1:-}" = --encrypt ]; then
    encrypt
    exit
fi

# The plain copy is made in a private directory and removed on any exit, so
# an unencrypted database never sits among the backups.
umask 077
mkdir -p "$DEST"
work=$(mktemp -d "$DEST/.oscar-backup.XXXXXX")
trap 'rm -rf "$work"' EXIT
stamp=$(date +%Y%m%d-%H%M)
copy="$work/oscar-$stamp.sqlite"

# node:sqlite can do VACUUM INTO: a consistent copy without blocking writes
node -e "
const {DatabaseSync} = require('node:sqlite');
const db = new DatabaseSync('$DB', {readOnly: true});
db.exec(\"VACUUM INTO '$copy'\");
db.close();
"

if [ "${1:-}" = --stdout ]; then
    gzip -c "$copy"
    exit
fi

if [ "${#age_args[@]}" -gt 0 ]; then
    out="$DEST/oscar-$stamp.sqlite.gz.age"
    if ! gzip -c "$copy" | encrypt > "$work/out"; then
        echo "oscar-backup: encryption failed, no backup written" >&2
        exit 1
    fi
else
    echo "oscar-backup: WARNING: OSCAR_BACKUP_AGE_RECIPIENTS is not set," \
         "writing an unencrypted backup (see deploy/docker/README.md, Backups)" >&2
    out="$DEST/oscar-$stamp.sqlite.gz"
    gzip -c "$copy" > "$work/out"
fi
# Backups are readable by their owner only, like the database itself.
chmod 600 "$work/out"
mv -f "$work/out" "$out"

# On a systemd host the copies belong to the service user; in a container the
# script already runs as the user that owns the volume.
if id oscar >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    chown -R oscar:oscar "$DEST"
fi

# Rotation: delete copies older than KEEP_DAYS days, encrypted or not
find "$DEST" -maxdepth 1 -type f \( -name 'oscar-*.sqlite.gz' -o -name 'oscar-*.sqlite.gz.age' \) \
    -mtime +"$KEEP_DAYS" -delete

count=$(find "$DEST" -maxdepth 1 -type f \( -name 'oscar-*.sqlite.gz' -o -name 'oscar-*.sqlite.gz.age' \) | wc -l)
size=$(du -sh "$DEST" | cut -f1)
echo "backup written: $out (copies kept: $count, space used: $size)"
