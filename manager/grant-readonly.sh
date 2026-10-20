#!/bin/sh
set -eu
# Hex-only password: safe as SQL literal even if ADMIN_PASSWORD contains punctuation.
RO_PASSWORD="$(printf 'fxa-manager-ro-v1\000%s' "$ADMIN_PASSWORD" | sha256sum | cut -d ' ' -f 1)"
export MYSQL_PWD="$FXA_DB_ROOT_PASSWORD"
mysql --connect-timeout=15 -h fxa-db -uroot --batch -N -e "
CREATE USER IF NOT EXISTS 'fxa_manager_ro'@'%' IDENTIFIED BY '$RO_PASSWORD';
ALTER USER 'fxa_manager_ro'@'%' IDENTIFIED BY '$RO_PASSWORD';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'fxa_manager_ro'@'%';
GRANT SELECT ON \`fxa\`.\`accounts\` TO 'fxa_manager_ro'@'%';
"
echo 'FxA Manager: SELECT auf fxa.accounts eingerichtet. Keine weiteren Rechte.'
