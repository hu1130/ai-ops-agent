import gzip
import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ops_agent.backups import (
    backup_status_payload,
    cleanup_old_backup_files,
    run_backup_health_checks,
    run_backup_now,
    run_due_backups,
    run_restore_drill_now,
)
from ops_agent.ai.classifier import classify_incident
from ops_agent.cli import validate_config
from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.storage import Storage


def sqlite_config(tmp: str) -> AppConfig:
    return AppConfig(
        raw={
            "app": {"database_path": "ops.db"},
            "backups": {
                "enabled": True,
                "base_dir": "backups",
                "targets": [
                    {
                        "id": "ops-db",
                        "name": "Ops database",
                        "engine": "sqlite",
                        "path": "ops.db",
                        "interval_hours": 24,
                        "retention_days": 7,
                        "minimum_backups": 1,
                        "restore_drill": {"enabled": True, "interval_days": 7, "minimum_tables": 1},
                    }
                ],
            },
        },
        base_dir=Path(tmp),
    )


class FakeMySQLRunner:
    def __init__(self) -> None:
        self.actions: list[str] = []
        self.restored_sql = b""

    def __call__(self, command, **kwargs):
        joined = " ".join(str(item) for item in command)
        if "mysqldump" in joined:
            self.actions.append("backup")
            kwargs["stdout"].write(b"CREATE TABLE sample (id int);\nINSERT INTO sample VALUES (1);\n")
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        if "OPS_DRILL_ACTION=create" in joined:
            self.actions.append("create")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "OPS_DRILL_ACTION=verify" in joined:
            self.actions.append("verify")
            return subprocess.CompletedProcess(command, 0, stdout="2\n", stderr="")
        if "OPS_DRILL_ACTION=drop" in joined:
            self.actions.append("drop")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "mysql -h 127.0.0.1" in joined:
            self.actions.append("restore")
            self.restored_sql = kwargs["stdin"].read()
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        raise AssertionError(f"unexpected command: {joined}")


class BackupWorkflowTest(unittest.TestCase):
    def test_backup_cleanup_enforces_capacity_while_preserving_minimum_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sqlite_config(tmp)
            target = config.raw["backups"]["targets"][0]
            target["retention_days"] = 365
            target["minimum_backups"] = 2
            target["max_total_bytes"] = 12
            directory = Path(tmp) / "backups" / "ops-db"
            directory.mkdir(parents=True)
            for index in range(4):
                path = directory / f"backup-{index}.sqlite"
                path.write_bytes(b"123456")
                os.utime(path, (100 + index, 100 + index))

            deleted = cleanup_old_backup_files(config, target, datetime.now(timezone.utc))
            remaining = sorted(path.name for path in directory.iterdir())

        self.assertEqual(2, deleted)
        self.assertEqual(["backup-2.sqlite", "backup-3.sqlite"], remaining)

    def test_sqlite_backup_and_isolated_restore_drill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sqlite_config(tmp)
            storage = Storage(Path(tmp) / "ops.db")
            backups = run_backup_now(storage, config, "ops-db")
            drill = run_restore_drill_now(storage, config, "ops-db")
            status = backup_status_payload(storage, config)
            source_integrity = storage.connection.execute("pragma integrity_check").fetchone()[0]
            storage.close()

            backup_path = Path(backups[0]["path"])
            backup_exists = backup_path.is_file()
            hidden_restore_files = list(backup_path.parent.glob(".*restore-drill*"))

        self.assertEqual("success", backups[0]["status"])
        self.assertTrue(backup_exists)
        self.assertEqual("success", drill["status"])
        self.assertTrue(drill["metadata"]["isolated_restore"])
        self.assertEqual("ok", source_integrity)
        self.assertEqual([], hidden_restore_files)
        self.assertEqual("success", status["runs"][0]["status"])
        self.assertNotIn(str(backup_path.parent), status["runs"][0]["file_name"])

    def test_due_scheduler_creates_backup_and_restore_drill_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sqlite_config(tmp)
            storage = Storage(Path(tmp) / "ops.db")
            first = run_due_backups(storage, config)
            second = run_due_backups(storage, config)
            storage.close()

        self.assertEqual({"backup", "restore_drill"}, {run["kind"] for run in first})
        self.assertEqual([], second)

    def test_backup_health_warns_when_missing_and_is_ok_after_drill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sqlite_config(tmp)
            storage = Storage(Path(tmp) / "ops.db")
            before = run_backup_health_checks(storage, config)
            run_due_backups(storage, config)
            after = run_backup_health_checks(storage, config)
            storage.close()

        self.assertEqual("warning", before[0].status)
        self.assertEqual("ok", after[0].status)

    def test_mysql_docker_backup_and_restore_drill_use_isolated_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "backups": {
                        "enabled": True,
                        "base_dir": "backups",
                        "targets": [
                            {
                                "id": "app-mysql",
                                "engine": "mysql_docker",
                                "container": "app-mysql",
                                "minimum_backup_bytes": 10,
                                "restore_drill": {"enabled": True, "minimum_tables": 1},
                            }
                        ],
                    }
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            runner = FakeMySQLRunner()
            backup = run_backup_now(storage, config, "app-mysql", runner=runner)[0]
            drill = run_restore_drill_now(storage, config, "app-mysql", runner=runner)
            storage.close()

            with gzip.open(backup["path"], "rb") as handle:
                dump = handle.read()

        self.assertEqual("success", backup["status"])
        self.assertEqual("success", drill["status"])
        self.assertEqual(["backup", "create", "restore", "verify", "drop"], runner.actions)
        self.assertIn(b"CREATE TABLE sample", dump)
        self.assertEqual(dump, runner.restored_sql)
        self.assertTrue(drill["metadata"]["temporary_database_removed"])

    def test_backup_api_runs_backup_and_restore_drill_with_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sqlite_config(tmp)
            config.raw["app"].update(
                {
                    "api_auth_required_for_reads": True,
                    "api_tokens": [
                        {"name": "owner", "token": "owner-token", "role": "operator"},
                        {"name": "viewer", "token": "viewer-token", "role": "viewer"},
                    ],
                }
            )
            storage = Storage(Path(tmp) / "ops.db")
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            headers = {"Authorization": "Bearer owner-token", "Content-Type": "application/json"}
            try:
                backup_request = urllib.request.Request(
                    f"http://{host}:{port}/api/backups/run",
                    data=json.dumps({"target_id": "ops-db"}).encode("utf-8"),
                    method="POST",
                    headers=headers,
                )
                with urllib.request.urlopen(backup_request, timeout=10) as response:
                    backup = json.loads(response.read().decode("utf-8"))
                drill_request = urllib.request.Request(
                    f"http://{host}:{port}/api/backups/drill",
                    data=json.dumps({"target_id": "ops-db"}).encode("utf-8"),
                    method="POST",
                    headers=headers,
                )
                with urllib.request.urlopen(drill_request, timeout=10) as response:
                    drill = json.loads(response.read().decode("utf-8"))
                status_request = urllib.request.Request(f"http://{host}:{port}/api/backups", headers=headers)
                with urllib.request.urlopen(status_request, timeout=10) as response:
                    status = json.loads(response.read().decode("utf-8"))
                audits = storage.latest_api_audit_logs()
                viewer_request = urllib.request.Request(
                    f"http://{host}:{port}/api/backups",
                    headers={"Authorization": "Bearer viewer-token"},
                )
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(viewer_request, timeout=10)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("success", backup["status"])
        self.assertEqual("success", drill["status"])
        self.assertEqual(2, len(status["runs"]))
        self.assertEqual(403, denied.exception.code)
        self.assertEqual(["backup.drill", "backup.run"], [row["operation"] for row in audits[:2]])

    def test_backup_warning_has_dedicated_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sqlite_config(tmp)
            storage = Storage(Path(tmp) / "ops.db")
            result = run_backup_health_checks(storage, config)[0]
            storage.close()
        classification = classify_incident([result])

        self.assertEqual("backup_failure", classification.category)
        self.assertGreater(classification.confidence, 0.9)

    def test_backup_config_rejects_duplicate_target_and_unknown_engine(self) -> None:
        config = AppConfig(
            raw={
                "backups": {
                    "enabled": True,
                    "targets": [
                        {"id": "same", "engine": "unknown"},
                        {"id": "same", "engine": "sqlite", "path": "ops.db"},
                    ],
                }
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)

        self.assertTrue(any("engine" in error for error in errors))
        self.assertTrue(any("重复" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
