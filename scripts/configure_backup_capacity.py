#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Set per-target backup capacity limits")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--target", action="append", required=True, help="TARGET_ID=MAX_BYTES")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    limits: dict[str, int] = {}
    for item in args.target:
        target_id, separator, raw_limit = item.partition("=")
        if not separator or not target_id.strip():
            raise SystemExit(f"invalid target limit: {item}")
        limit = int(raw_limit)
        if limit <= 0:
            raise SystemExit(f"capacity must be positive: {item}")
        limits[target_id.strip()] = limit

    path = Path(args.config).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    targets = config.setdefault("backups", {}).setdefault("targets", [])
    found: set[str] = set()
    for target in targets:
        target_id = str(target.get("id") or "")
        if target_id in limits:
            target["max_total_bytes"] = limits[target_id]
            found.add(target_id)
    missing = sorted(set(limits) - found)
    if missing:
        raise SystemExit("backup target not found: " + ", ".join(missing))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    shutil.copy2(path, path.with_name(f"{path.name}.before-backup-capacity-{stamp}"))
    fd, temporary = tempfile.mkstemp(prefix=".config.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise
    print("Backup capacity updated: " + ", ".join(sorted(found)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
