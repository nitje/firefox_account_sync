#!/bin/sh
set -eu
umask 077

BACKUP_DIR=/backups
STATUS_DIR=/backup-status
RESTORE_LOCK=/restore-status/restore.lock
mkdir -p "$BACKUP_DIR" "$STATUS_DIR"
chmod 700 "$BACKUP_DIR"
chmod 755 "$STATUS_DIR"

write_status() {
  kind="$1"
  moment="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # backup name is always an internal timestamp, never arbitrary user input.
  bname="${2:-}"
  printf '{"status":"%s","timestamp":"%s","backup":"%s","detail":"%s"}\n' \
    "$kind" "$moment" "$bname" 'MySQL + FxA key/config snapshots (Mailpit/Redis excluded)' > "$STATUS_DIR/.last.tmp"
  chmod 644 "$STATUS_DIR/.last.tmp"
  mv -f "$STATUS_DIR/.last.tmp" "$STATUS_DIR/last.json"
}

backup_once() {
  if [ -e "$RESTORE_LOCK" ]; then
    echo "Backup pausiert: Wiederherstellung aktiv"
    return 75
  fi
  work=''
  trap 'write_status failed; if [ -n "$work" ]; then rm -rf "$work"; fi' EXIT
  work="$(mktemp -d "$BACKUP_DIR/.pending-XXXXXXXX")"
  chmod 700 "$work"
  # Close the small race between the first lock check and .pending creation.
  if [ -e "$RESTORE_LOCK" ]; then
    rm -rf "$work"
    work=''
    trap - EXIT HUP INT TERM
    echo "Backup pausiert: Restore-Lock wurde gesetzt"
    return 75
  fi
  echo "Backup: mysql dump (FxA, syncstorage, tokenserver)"
  # Do not pipe mysqldump directly into gzip: POSIX sh has no pipefail.
  # Each dump MUST succeed before the backup can be marked complete.
  MYSQL_PWD="$FXA_DB_PASSWORD" mysqldump --single-transaction --quick \
    --routines --triggers --events --hex-blob --set-gtid-purged=OFF --no-tablespaces \
    -h fxa-db -ufxa --databases fxa fxa_oauth fxa_profile pushbox > "$work/fxa.sql"
  gzip "$work/fxa.sql"
  MYSQL_PWD="$SYNC_DB_PASSWORD" mysqldump --single-transaction --quick \
    --routines --triggers --events --hex-blob --set-gtid-purged=OFF --no-tablespaces \
    -h sync-db -usync --databases syncstorage > "$work/syncstorage.sql"
  gzip "$work/syncstorage.sql"
  MYSQL_PWD="$TOKEN_DB_PASSWORD" mysqldump --single-transaction --quick \
    --routines --triggers --events --hex-blob --set-gtid-purged=OFF --no-tablespaces \
    -h token-db -utoken --databases tokenserver > "$work/tokenserver.sql"
  gzip "$work/tokenserver.sql"
  # Do not include live Redis/AOF or Mailpit SQLite files as a consistency claim.
  tar -C /data/volumes -czf "$work/fxa-volumes.tar.gz" \
    fxa-keys fxa-generated fxa-profile-images manager-state
  cp /project/.env "$work/dot-env.restore"
  chmod 600 "$work/dot-env.restore"
  for archived in fxa.sql.gz syncstorage.sql.gz tokenserver.sql.gz fxa-volumes.tar.gz; do
    gzip -t "$work/$archived"
  done
  tar -tzf "$work/fxa-volumes.tar.gz" >/dev/null
  (cd "$work" && sha256sum fxa.sql.gz syncstorage.sql.gz tokenserver.sql.gz \
    fxa-volumes.tar.gz dot-env.restore > SHA256SUMS && sha256sum -c SHA256SUMS >/dev/null)
  final="backup-$(date -u +%Y%m%dT%H%M%SZ)"
  # Should two backups be started in one second, choose a distinct suffix.
  n=0
  while [ -e "$BACKUP_DIR/$final" ]; do n=$((n+1)); final="backup-$(date -u +%Y%m%dT%H%M%SZ)-$n"; done
  mv "$work" "$BACKUP_DIR/$final"
  work=''
  trap - EXIT HUP INT TERM
  write_status success "$final"
  echo "Backup abgeschlossen: $final"
  # Retention only affects our timestamped backup directories after success.
  find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' \
    -mtime "+$BACKUP_RETENTION_DAYS" -exec rm -rf -- '{}' +
}

case "${BACKUP_INTERVAL_HOURS:-24}" in *[!0-9]*|'') echo 'BACKUP_INTERVAL_HOURS muss Ganzzahl sein' >&2; exit 1;; esac
case "${BACKUP_RETENTION_DAYS:-14}" in *[!0-9]*|'') echo 'BACKUP_RETENTION_DAYS muss Ganzzahl sein' >&2; exit 1;; esac
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
[ "$BACKUP_RETENTION_DAYS" -gt 0 ] || { echo 'BACKUP_RETENTION_DAYS muss > 0 sein' >&2; exit 1; }
[ "${BACKUP_INTERVAL_HOURS:-24}" -gt 0 ] || { echo 'BACKUP_INTERVAL_HOURS muss > 0 sein' >&2; exit 1; }
for cmd in mysqldump gzip tar sha256sum mktemp find; do
  command -v "$cmd" >/dev/null || { echo "Backup: benoetigt $cmd im mysql:8.4 Image" >&2; exit 1; }
done
if [ "${1:-daemon}" = once ]; then
  if backup_once; then exit 0; else exit "$?"; fi
fi
if [ "${1:-daemon}" != daemon ]; then echo 'Usage: run.sh [daemon|once]' >&2; exit 2; fi
case "${BACKUP_ENABLED:-true}" in true|TRUE|1|yes|YES) ;; *)
  write_status disabled
  echo 'Backup deaktiviert durch BACKUP_ENABLED'
  exec sleep infinity
;; esac
while :; do
  while [ -e "$RESTORE_LOCK" ]; do
    echo "Backup-Daemon pausiert waehrend Restore"
    sleep 10
  done
  if backup_once; then
    sleep "$((BACKUP_INTERVAL_HOURS * 3600))"
  else
    rc="$?"
    if [ "$rc" -eq 75 ]; then sleep 10; else exit "$rc"; fi
  fi
done
