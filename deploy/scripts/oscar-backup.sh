#!/bin/bash
# Резервное копирование базы Open OSCAR Server.
# Используется команда SQLite .backup — она делает согласованную копию
# на работающем сервере, без остановки сервиса.
set -euo pipefail

# Both can be overridden, which is how the container runs it; the defaults are
# the paths of a systemd installation.
DB="${OSCAR_BACKUP_DB:-/var/lib/open-oscar-server/oscar.sqlite}"
DEST="${OSCAR_BACKUP_DEST:-/var/backups/open-oscar-server}"
KEEP_DAYS="${OSCAR_BACKUP_KEEP_DAYS:-14}"

mkdir -p "$DEST"
stamp=$(date +%Y%m%d-%H%M)
out="$DEST/oscar-$stamp.sqlite"

# node:sqlite умеет VACUUM INTO — согласованная копия без блокировки записи
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

# Ротация: удаляем копии старше KEEP_DAYS дней
find "$DEST" -name 'oscar-*.sqlite.gz' -type f -mtime +"$KEEP_DAYS" -delete

count=$(find "$DEST" -name 'oscar-*.sqlite.gz' -type f | wc -l)
size=$(du -sh "$DEST" | cut -f1)
echo "backup written: $out.gz (copies kept: $count, space used: $size)"
