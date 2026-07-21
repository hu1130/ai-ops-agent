#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${OPS_AGENT_DATA_DIR:-/opt/ops-agent/data}"
EXPECTED_DIR="/opt/ops-agent/data"

if [ "$(id -u)" -ne 0 ]; then
  echo "cleanup must run as root" >&2
  exit 2
fi

resolved="$(readlink -f "$DATA_DIR")"
if [ "$resolved" != "$EXPECTED_DIR" ]; then
  echo "refusing cleanup outside ${EXPECTED_DIR}: ${resolved}" >&2
  exit 3
fi
if [ ! -f "$DATA_DIR/ops_agent.db" ]; then
  echo "active SQLite rollback database is missing" >&2
  exit 4
fi

latest_snapshot="$(find "$DATA_DIR" -maxdepth 1 -type f -name 'ops_agent-before-mysql-*.sqlite' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
if [ -z "$latest_snapshot" ] || [ ! -f "$latest_snapshot" ]; then
  echo "latest pre-migration snapshot is missing" >&2
  exit 5
fi

before_bytes="$(du -sb "$DATA_DIR" | cut -f1)"
while IFS= read -r path; do
  [ -z "$path" ] && continue
  candidate="$(readlink -f "$path")"
  case "$candidate" in
    "$EXPECTED_DIR"/*) ;;
    *) echo "refusing unexpected path: ${candidate}" >&2; exit 6 ;;
  esac
  if [ "$candidate" != "$(readlink -f "$latest_snapshot")" ]; then
    rm -f -- "$candidate"
  fi
done < <(
  find "$DATA_DIR" -maxdepth 1 -type f \
    \( -name 'ops_agent-before-mysql-*.sqlite' -o -name 'mysql-migration-*.sql' -o -name 'mysql_migration.sql' \) \
    -print
)

find "$DATA_DIR" -maxdepth 1 -type f -name 'ops_agent.db.bak-*' -mtime +7 -delete
disabled_sqlite_backups="${DATA_DIR}/backups/ops-agent-sqlite"
if [ -d "$disabled_sqlite_backups" ] && [ "$(readlink -f "$disabled_sqlite_backups")" = "${EXPECTED_DIR}/backups/ops-agent-sqlite" ]; then
  find "$disabled_sqlite_backups" -maxdepth 1 -type f -delete
fi
docker image rm sales-ai-backend:ops-repair-test >/dev/null 2>&1 || true
docker image prune -f >/dev/null

after_bytes="$(du -sb "$DATA_DIR" | cut -f1)"
echo "Migration cleanup complete: freed=$((before_bytes - after_bytes)) bytes"
echo "Preserved rollback database: ${DATA_DIR}/ops_agent.db"
echo "Preserved migration snapshot: ${latest_snapshot}"
