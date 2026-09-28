#!/bin/bash
# Backs up the Open OSCAR Server database.
# Uses SQLite's VACUUM INTO (through node:sqlite, below): it makes a consistent
# copy of a running server without stopping the service.
set -euo pipefail

# Both can be overridden, which is how the container runs it; the defaults are
# the paths of a systemd installation.
DB="${OSCAR_BACKUP_DB:-/var/lib/open-oscar-server/oscar.sqlite}"
DEST="${OSCAR_BACKUP_DEST:-/var/backups/open-oscar-server}"
KEEP_DAYS="${OSCAR_BACKUP_KEEP_DAYS:-14}"

mkdir -p "$DEST"
stamp=$(date +%Y%m%d-%H%M)
out="$DEST/oscar-$stamp.sqlite"

# node:sqlite can do VACUUM INTO: a consistent copy without blocking writes
node -e "
const {DatabaseSync} = require('node:sqlite');
const db = new DatabaseSync('$DB', {readOnly: true});
db.exec(\"VACUUM INTO '$out'\");
db.close();
"

gzip -f "$out"
# On a systemd host the copies belong to the service user; in a container the
# script already runs as the user that owns the volume.
if id oscar >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    chown -R oscar:oscar "$DEST"
fi

# Rotation: delete copies older than KEEP_DAYS days
find "$DEST" -name 'oscar-*.sqlite.gz' -type f -mtime +"$KEEP_DAYS" -delete

count=$(find "$DEST" -name 'oscar-*.sqlite.gz' -type f | wc -l)
size=$(du -sh "$DEST" | cut -f1)
echo "backup written: $out.gz (copies kept: $count, space used: $size)"
