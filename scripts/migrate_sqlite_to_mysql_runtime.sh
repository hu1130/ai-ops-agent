#!/usr/bin/env bash
set -euo pipefail

ROOT="${OPS_AGENT_ROOT:-/opt/ops-agent}"
CONFIG="${OPS_AGENT_CONFIG:-${ROOT}/config.json}"
APP_ENV="${OPS_AGENT_ENV_FILE:-/etc/ops-agent/ops-agent.env}"
CONTAINER="${OPS_AGENT_MYSQL_CONTAINER:-ops-agent-mysql}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SQLITE="${ROOT}/data/ops_agent.db"
SNAPSHOT="${ROOT}/data/ops_agent-before-mysql-${STAMP}.sqlite"
EXPORT="${ROOT}/data/mysql-migration-${STAMP}.sql"
CONFIG_BACKUP="${CONFIG}.before-mysql-${STAMP}"

if [ "$(id -u)" -ne 0 ]; then
  echo "migration must run as root" >&2
  exit 2
fi
if [ ! -f "$SQLITE" ] || [ ! -f "$CONFIG" ] || [ ! -f "$APP_ENV" ]; then
  echo "required SQLite, config, or environment file is missing" >&2
  exit 3
fi

rollback() {
  cp -a "$CONFIG_BACKUP" "$CONFIG"
  systemctl restart ops-agent || true
  echo "Migration rolled back to SQLite configuration" >&2
}
trap rollback ERR

cp -a "$CONFIG" "$CONFIG_BACKUP"
systemctl stop ops-agent

python3 - "$SQLITE" "$SNAPSHOT" <<'PY'
import sqlite3, sys
source = sqlite3.connect(sys.argv[1])
target = sqlite3.connect(sys.argv[2])
try:
    source.backup(target)
    target.commit()
    result = target.execute("pragma integrity_check").fetchone()[0]
    if str(result).lower() != "ok":
        raise SystemExit(f"SQLite snapshot integrity failed: {result}")
finally:
    target.close()
    source.close()
PY

cd "$ROOT"
python3 -m ops_agent.cli --config "$CONFIG" mysql-export \
  --sqlite "$SNAPSHOT" --output "$EXPORT" --database-name ops_agent >/dev/null

docker exec -i "$CONTAINER" sh -lc \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -h127.0.0.1 -uroot' < "$EXPORT"

OPS_AGENT_MYSQL_PASSWORD="$(sed -n 's/^OPS_AGENT_MYSQL_PASSWORD=//p' "$APP_ENV" | tail -1)"
export OPS_AGENT_MYSQL_PASSWORD
python3 - "$SNAPSHOT" <<'PY'
import os, sqlite3, sys
import pymysql

sqlite = sqlite3.connect(sys.argv[1])
tables = [row[0] for row in sqlite.execute(
    "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name"
)]
expected = {table: sqlite.execute(f'select count(*) from "{table}"').fetchone()[0] for table in tables}
sqlite.close()
mysql = pymysql.connect(
    host="127.0.0.1", port=3307, user="ops_agent",
    password=os.environ["OPS_AGENT_MYSQL_PASSWORD"], database="ops_agent",
)
try:
    with mysql.cursor() as cursor:
        actual = {}
        for table in tables:
            cursor.execute(f"select count(*) from `{table}`")
            actual[table] = cursor.fetchone()[0]
finally:
    mysql.close()
mismatches = {table: (expected[table], actual.get(table)) for table in tables if expected[table] != actual.get(table)}
if mismatches:
    raise SystemExit(f"row-count mismatch: {mismatches}")
print(f"row parity verified: tables={len(tables)} rows={sum(expected.values())}")
PY

python3 - "$CONFIG" <<'PY'
import json, os, sys, tempfile

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    config = json.load(handle)
app = config.setdefault("app", {})
app["storage_backend"] = "mysql"
app["api_auth_required_for_reads"] = True
config["mysql"] = {
    "host": "127.0.0.1",
    "port": 3307,
    "database": "ops_agent",
    "user": "ops_agent",
    "password_env": "OPS_AGENT_MYSQL_PASSWORD",
    "connect_timeout_seconds": 5,
    "read_timeout_seconds": 30,
    "write_timeout_seconds": 30,
}
repair = config.setdefault("ai", {}).setdefault("repair", {})
repair.setdefault("auto_trigger", {})["run_sandbox"] = True
repair["queue_worker"] = {
    "enabled": True,
    "interval_seconds": 300,
    "max_actions_per_cycle": 3,
    "auto_prepare_branch_after_approval": True,
    "auto_create_pr_after_approval": True,
    "auto_deploy_after_merge": True,
}
targets = config.setdefault("backups", {}).setdefault("targets", [])
for target in targets:
    if target.get("id") == "ops-agent-sqlite":
        target["enabled"] = False
if not any(target.get("id") == "ops-agent-mysql" for target in targets):
    targets.append({
        "id": "ops-agent-mysql",
        "name": "Ops Agent MySQL backup",
        "enabled": True,
        "engine": "mysql_docker",
        "container": "ops-agent-mysql",
        "interval_hours": 24,
        "max_age_hours": 48,
        "retention_days": 14,
        "minimum_backups": 3,
        "minimum_backup_bytes": 1000,
        "alert_after_failures": 2,
        "recovery_after_successes": 2,
        "restore_drill": {"enabled": True, "interval_days": 7, "max_age_days": 14, "minimum_tables": 10},
    })
checks = config.setdefault("database_checks", [])
if not any(check.get("name") == "Ops Agent MySQL" for check in checks):
    checks.append({
        "name": "Ops Agent MySQL",
        "enabled": True,
        "engine": "mysql_docker",
        "container": "ops-agent-mysql",
        "interval_seconds": 60,
        "timeout_seconds": 10,
        "max_query_latency_ms": 3000,
        "max_connection_usage_percent": 80,
        "max_running_threads": 20,
        "alert_after_failures": 2,
        "recovery_after_successes": 2,
    })
fd, temporary = tempfile.mkstemp(prefix=".config.", dir=os.path.dirname(path), text=True)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY

systemctl restart ops-agent
sleep 8
systemctl is-active --quiet ops-agent

python3 - "$CONFIG" <<'PY'
import json, socket, time, urllib.error, urllib.request, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
tokens = [item for item in config.get("app", {}).get("api_tokens", []) if item.get("token")]
viewer = next((item for item in tokens if item.get("role") in ("viewer", "operator", "admin")), None)
if not viewer:
    raise SystemExit("no API token available for post-migration verification")
deadline = time.monotonic() + 90
last_error = "dashboard did not become ready"
while time.monotonic() < deadline:
    try:
        try:
            urllib.request.urlopen("http://127.0.0.1:8765/api/summary", timeout=10)
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
        else:
            raise SystemExit("unauthenticated read API did not return 401")
        request = urllib.request.Request(
            "http://127.0.0.1:8765/api/summary",
            headers={"Authorization": "Bearer " + viewer["token"]},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"authenticated API returned {response.status}")
        break
    except (OSError, socket.timeout, TimeoutError, urllib.error.URLError) as exc:
        last_error = str(exc)
        time.sleep(2)
else:
    raise SystemExit(f"dashboard verification timed out: {last_error}")
print("authenticated API verification passed")
PY

trap - ERR
echo "MySQL runtime migration completed; rollback config: ${CONFIG_BACKUP}; SQLite snapshot: ${SNAPSHOT}"
