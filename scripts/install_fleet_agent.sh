#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "install must run as root" >&2
  exit 2
fi

CENTRAL_URL="${1:-${OPS_AGENT_FLEET_SERVER_URL:-}}"
NODE_ID="${2:-$(hostname -s)}"
NODE_NAME="${3:-$NODE_ID}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${OPS_AGENT_FLEET_APP_DIR:-/opt/ops-agent-fleet}"
ENV_FILE="${OPS_AGENT_FLEET_ENV_FILE:-/etc/ops-agent/fleet-agent.env}"
CONFIG_FILE="${APP_DIR}/config.json"

if [ -z "$CENTRAL_URL" ]; then
  echo "central URL is required: install_fleet_agent.sh https://ops.example.com server-1" >&2
  exit 2
fi
if ! [[ "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "node id must use letters, numbers, dot, underscore, or dash" >&2
  exit 2
fi

TOKEN="${OPS_AGENT_FLEET_ENROLLMENT_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -t 0 ]; then
  read -r -s -p "Fleet enrollment token: " TOKEN
  printf '\n'
fi
if [ -z "$TOKEN" ]; then
  echo "set OPS_AGENT_FLEET_ENROLLMENT_TOKEN before installation" >&2
  exit 2
fi

install -d -m 0755 "$APP_DIR" "$(dirname "$ENV_FILE")"
if [ "$SOURCE_DIR" != "$APP_DIR" ]; then
  cp -a "$SOURCE_DIR/ops_agent" "$APP_DIR/"
fi

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

umask 077
cat > "$ENV_FILE" <<EOF
OPS_AGENT_FLEET_SERVER_URL=$CENTRAL_URL
OPS_AGENT_FLEET_ENROLLMENT_TOKEN=$TOKEN
EOF
chmod 600 "$ENV_FILE"

cat > /etc/systemd/system/ops-agent-fleet.service <<EOF
[Unit]
Description=AI Ops Agent remote fleet collector
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/python3 -m ops_agent.cli --config $CONFIG_FILE fleet-agent --node-id $NODE_ID --name "$NODE_NAME" --interval-seconds 60
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ops-agent-fleet.service
sleep 2
systemctl is-active --quiet ops-agent-fleet.service
echo "Fleet collector installed: node=$NODE_ID central=$CENTRAL_URL"
