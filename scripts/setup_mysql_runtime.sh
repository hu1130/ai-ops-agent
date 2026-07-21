#!/usr/bin/env bash
set -euo pipefail

APP_ENV="${OPS_AGENT_ENV_FILE:-/etc/ops-agent/ops-agent.env}"
CONTAINER_ENV="${OPS_AGENT_MYSQL_CONTAINER_ENV:-/etc/ops-agent/mysql-container.env}"
CONTAINER="${OPS_AGENT_MYSQL_CONTAINER:-ops-agent-mysql}"
IMAGE="${OPS_AGENT_MYSQL_IMAGE:-mysql:8.4}"
PORT="${OPS_AGENT_MYSQL_PORT:-3307}"

if [ "$(id -u)" -ne 0 ]; then
  echo "setup must run as root" >&2
  exit 2
fi

umask 077
mkdir -p "$(dirname "$APP_ENV")"
touch "$APP_ENV"

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    python3 -c 'import secrets; print(secrets.token_hex(24))'
  fi
}

if ! grep -q '^OPS_AGENT_MYSQL_PASSWORD=' "$APP_ENV"; then
  printf 'OPS_AGENT_MYSQL_PASSWORD=%s\n' "$(random_secret)" >> "$APP_ENV"
fi
chmod 600 "$APP_ENV"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  app_password="$(sed -n 's/^OPS_AGENT_MYSQL_PASSWORD=//p' "$APP_ENV" | tail -1)"
  root_password="$(random_secret)"
  printf 'MYSQL_ROOT_PASSWORD=%s\nMYSQL_DATABASE=ops_agent\nMYSQL_USER=ops_agent\nMYSQL_PASSWORD=%s\n' \
    "$root_password" "$app_password" > "$CONTAINER_ENV"
  chmod 600 "$CONTAINER_ENV"
  docker run -d \
    --name "$CONTAINER" \
    --restart unless-stopped \
    --env-file "$CONTAINER_ENV" \
    -p "127.0.0.1:${PORT}:3306" \
    -v ops-agent-mysql-data:/var/lib/mysql \
    "$IMAGE" >/dev/null
fi

ready=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -lc \
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqladmin ping -h127.0.0.1 -uroot --silent' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" != 1 ]; then
  echo "MySQL container did not become ready" >&2
  exit 3
fi

echo "MySQL runtime ready: container=${CONTAINER} bind=127.0.0.1:${PORT}"
