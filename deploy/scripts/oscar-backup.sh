#!/bin/bash
# Резервное копирование базы Open OSCAR Server.
# Используется команда SQLite .backup — она делает согласованную копию
# на работающем сервере, без остановки сервиса.
set -euo pipefail

DB="/var/lib/open-oscar-server/oscar.sqlite"
DEST="/var/backups/open-oscar-server"
KEEP_DAYS="${OSCAR_BACKUP_KEEP_DAYS:-14}"

mkdir -p "$DEST"
stamp=$(date +%Y%m%d-%H%M)
out="$DEST/oscar-$stamp.sqlite"

# node:sqlite умеет VACUUM INTO — согласованная копия без блокировки записи
/usr/bin/node -e "
const {DatabaseSync} = require('node:sqlite');
const db = new DatabaseSync('$DB', {readOnly: true});
db.exec(\"VACUUM INTO '$out'\");
db.close();
"

gzip -f "$out"
chown -R oscar:oscar "$DEST"

# Ротация: удаляем копии старше KEEP_DAYS дней
find "$DEST" -name 'oscar-*.sqlite.gz' -type f -mtime +"$KEEP_DAYS" -delete

count=$(find "$DEST" -name 'oscar-*.sqlite.gz' -type f | wc -l)
size=$(du -sh "$DEST" | cut -f1)
echo "бэкап готов: $out.gz (всего копий: $count, занято: $size)"
