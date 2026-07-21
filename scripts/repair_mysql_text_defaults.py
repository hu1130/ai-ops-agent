#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ops_agent.config import load_config
from ops_agent.mysql_migration import mysql_column_default, mysql_column_type, mysql_identifier
from ops_agent.storage_factory import mysql_settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Restore SQLite text defaults in the MySQL runtime schema")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--sqlite-schema", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    settings = mysql_settings(config)
    if args.sqlite_schema:
        sqlite_path = Path(args.sqlite_schema)
    else:
        snapshots = sorted(
            (config.base_dir / "data").glob("ops_agent-before-mysql-*.sqlite"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not snapshots:
            raise SystemExit("no pre-migration SQLite snapshot found")
        sqlite_path = snapshots[0]
    import pymysql

    sqlite = sqlite3.connect(sqlite_path)
    sqlite.row_factory = sqlite3.Row
    mysql = pymysql.connect(
        host=settings["host"],
        port=settings["port"],
        user=settings["user"],
        password=settings["password"],
        database=settings["database"],
        charset="utf8mb4",
        autocommit=True,
    )
    changed = 0
    try:
        with mysql.cursor() as cursor:
            cursor.execute("create temporary table ops_agent_default_probe (value longtext not null default (''))")
            cursor.execute("insert into ops_agent_default_probe () values ()")
            cursor.execute("select value from ops_agent_default_probe")
            if cursor.fetchone()[0] != "":
                raise RuntimeError("MySQL LONGTEXT expression defaults are unavailable")

            tables = [
                str(row[0])
                for row in sqlite.execute(
                    "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name"
                )
            ]
            for table in tables:
                columns = sqlite.execute(f"pragma table_info({mysql_identifier(table)})").fetchall()
                for column in columns:
                    column_type = mysql_column_type(column)
                    default = mysql_column_default(column_type, column["dflt_value"])
                    if "TEXT" not in column_type.upper() or not default:
                        continue
                    nullable = " NOT NULL" if int(column["notnull"] or 0) else ""
                    cursor.execute(
                        f"alter table {mysql_identifier(table)} modify column "
                        f"{mysql_identifier(str(column['name']))} {column_type}{nullable}{default}"
                    )
                    changed += 1
    finally:
        mysql.close()
        sqlite.close()
    print(f"MySQL text defaults repaired: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
