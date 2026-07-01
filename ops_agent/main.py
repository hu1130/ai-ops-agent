from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import load_config
from ops_agent.dashboard import start_dashboard
from ops_agent.scheduler import OpsScheduler
from ops_agent.storage import Storage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Ops Agent MVP")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    parser.add_argument("--once", action="store_true", help="Run one check and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    database_path = config.resolve_path(str(config.app.get("database_path", "data/ops_agent.db")))
    storage = Storage(database_path)
    notifier = Notifier(
        webhook_url=str(config.alerts.get("webhook_url", "")),
        cooldown_seconds=int(config.alerts.get("cooldown_seconds", 300)),
        email=dict(config.alerts.get("email", {})),
    )
    scheduler = OpsScheduler(config, storage, notifier)

    if args.once:
        results = scheduler.run_once()
        for result in results:
            print(f"[{result.status}] {result.source}/{result.name}: {result.summary}")
        return 0

    host = str(config.app.get("dashboard_host", "127.0.0.1"))
    port = int(config.app.get("dashboard_port", 8765))
    start_dashboard(storage, host, port, config=config, notifier=notifier)
    scheduler.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
