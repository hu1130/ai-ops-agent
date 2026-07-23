#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "install must run as root" >&2
  exit 2
fi

CENTRAL_URL="${1:-${OPS_AGENT_FLEET_SERVER_URL:-}}"
NODE_ID="${2:-$(hostname -s)}"
NODE_NAME="${3:-$NODE_ID}"
RELEASE_URL="${4:-${OPS_AGENT_FLEET_RELEASE_URL:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="${OPS_AGENT_FLEET_APP_DIR:-/opt/ops-agent-fleet}"
ENV_FILE="${OPS_AGENT_FLEET_ENV_FILE:-/etc/ops-agent/fleet-agent.env}"
CONFIG_FILE="${APP_DIR}/config.json"
RELEASE_ROOT="${APP_DIR}/releases"
CURRENT_LINK="${APP_DIR}/current"
SERVICE_FILE="/etc/systemd/system/ops-agent-fleet.service"
STAGING_ROOT=""
PREVIOUS_RELEASE=""

cleanup() {
  if [ -n "$STAGING_ROOT" ] && [ -d "$STAGING_ROOT" ]; then
    rm -rf -- "$STAGING_ROOT"
  fi
}

rollback() {
  if [ -n "$PREVIOUS_RELEASE" ] && [ -d "$PREVIOUS_RELEASE" ]; then
    ln -sfn "$PREVIOUS_RELEASE" "${CURRENT_LINK}.rollback"
    mv -Tf "${CURRENT_LINK}.rollback" "$CURRENT_LINK"
    systemctl daemon-reload || true
    systemctl restart ops-agent-fleet.service || true
  elif [ -L "$CURRENT_LINK" ]; then
    rm -f -- "$CURRENT_LINK"
  fi
}

trap cleanup EXIT
trap 'rollback' ERR

if [ -z "$CENTRAL_URL" ]; then
  echo "central URL is required: install_fleet_agent.sh https://ops.example.com server-1" >&2
  exit 2
fi
if ! [[ "$CENTRAL_URL" =~ ^https:// ]] && ! [[ "$CENTRAL_URL" =~ ^http://(127\.0\.0\.1|localhost)(:|/|$) ]] && [ "${OPS_AGENT_ALLOW_INSECURE_HTTP:-0}" != "1" ]; then
  echo "central URL must use HTTPS; set OPS_AGENT_ALLOW_INSECURE_HTTP=1 only for a trusted private network" >&2
  exit 2
fi
if ! [[ "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "node id must use letters, numbers, dot, underscore, or dash" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 2
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required")
PY

TOKEN="${OPS_AGENT_FLEET_ENROLLMENT_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -t 0 ]; then
  read -r -s -p "Fleet enrollment token: " TOKEN
  printf '\n'
fi
if [ -z "$TOKEN" ]; then
  echo "set OPS_AGENT_FLEET_ENROLLMENT_TOKEN before installation" >&2
  exit 2
fi

install -d -m 0755 "$APP_DIR" "$RELEASE_ROOT" "$(dirname "$ENV_FILE")"

if [ ! -d "$SOURCE_DIR/ops_agent" ]; then
  if [ -z "$RELEASE_URL" ]; then
    echo "release URL is required when the installer is downloaded by itself" >&2
    exit 2
  fi
  if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    echo "curl and tar are required for release installation" >&2
    exit 2
  fi
  STAGING_ROOT="$(mktemp -d "${APP_DIR}/download.XXXXXX")"
  curl --fail --silent --show-error --location "$RELEASE_URL" -o "${STAGING_ROOT}/release.tar.gz"
  if [ -n "${OPS_AGENT_FLEET_RELEASE_SHA256:-}" ]; then
    printf '%s  %s\n' "$OPS_AGENT_FLEET_RELEASE_SHA256" "${STAGING_ROOT}/release.tar.gz" | sha256sum -c -
  fi
  tar -xzf "${STAGING_ROOT}/release.tar.gz" -C "$STAGING_ROOT"
  SOURCE_DIR="$(find "$STAGING_ROOT" -mindepth 1 -maxdepth 2 -type d -name ops_agent -print -quit | xargs -r dirname)"
  if [ -z "$SOURCE_DIR" ] || [ ! -d "$SOURCE_DIR/ops_agent" ]; then
    echo "release archive does not contain ops_agent" >&2
    exit 2
  fi
fi

RELEASE_ID="$(date -u +%Y%m%d%H%M%S)-$(python3 - <<'PY'
import secrets
print(secrets.token_hex(3))
PY
)"
RELEASE_DIR="${RELEASE_ROOT}/${RELEASE_ID}"
install -d -m 0755 "$RELEASE_DIR"
cp -a "$SOURCE_DIR/ops_agent" "$RELEASE_DIR/"
python3 -m compileall -q "$RELEASE_DIR/ops_agent"

if [ -L "$CURRENT_LINK" ]; then
  PREVIOUS_RELEASE="$(readlink -f "$CURRENT_LINK")"
fi
ln -sfn "$RELEASE_DIR" "${CURRENT_LINK}.next"
mv -Tf "${CURRENT_LINK}.next" "$CURRENT_LINK"

if [ ! -f "$CONFIG_FILE" ]; then
  cat > "$CONFIG_FILE" <<'JSON'
{
  "app": {
    "name": "ops-agent-fleet-node",
    "environment": "prod",
    "interval_seconds": 60,
    "database_path": "data/fleet-node.db"
  },
  "asset_discovery": {
    "enabled": true,
    "timeout_seconds": 8
  }
}
JSON
  chmod 640 "$CONFIG_FILE"
fi

umask 077
cat > "$ENV_FILE" <<EOF
OPS_AGENT_FLEET_SERVER_URL=$CENTRAL_URL
OPS_AGENT_FLEET_ENROLLMENT_TOKEN=$TOKEN
EOF
chmod 600 "$ENV_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=AI Ops Agent remote fleet collector
After=network-online.target docker.service
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=10

[Service]
Type=simple
WorkingDirectory=$CURRENT_LINK
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/python3 -m ops_agent.cli --config $CONFIG_FILE fleet-agent --node-id $NODE_ID --name "$NODE_NAME" --interval-seconds 60
Restart=always
RestartSec=5
TimeoutStopSec=20
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ops-agent-fleet.service
sleep 3
systemctl is-active --quiet ops-agent-fleet.service

PREVIOUS_RELEASE=""
find "$RELEASE_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
  | sort -nr \
  | tail -n +6 \
  | cut -d' ' -f2- \
  | while IFS= read -r old_release; do
      [ -z "$old_release" ] || rm -rf -- "$old_release"
    done
echo "Fleet collector installed: node=$NODE_ID central=$CENTRAL_URL release=$RELEASE_ID"
