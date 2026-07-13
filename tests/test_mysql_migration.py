import tempfile
import unittest
from pathlib import Path

from ops_agent.events import CheckResult
from ops_agent.mysql_migration import MysqlExportOptions, export_sqlite_to_mysql
from ops_agent.storage import Storage


class MysqlMigrationTest(unittest.TestCase):
    def test_export_sqlite_database_to_mysql_sql(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "ops.db"
            output_path = Path(tmp) / "mysql.sql"
            storage = Storage(db_path)
            incident_id = storage.save_incident(
                "critical",
                "Site down",
                "analysis with 中文",
                [
                    CheckResult(
                        source="http",
                        name="Site",
                        status="critical",
                        summary="HTTP 500",
                        details={"url": "https://example.com", "status_code": 500},
                    )
                ],
            )
            storage.save_ai_repair_proposal(
                incident_id,
                {
                    "title": "Repair",
                    "summary": "Review code",
                    "risk": "low",
                    "root_cause": "HTTP 500",
                    "model_provider": "rules",
                    "model_name": "rule-based-repair-v1",
                    "prompt": {"source": "unit-test"},
                    "proposal": {"repair_plan": ["review"]},
                    "patch": {"patch_type": "manual_code_review", "apply_mode": "proposal_only"},
                    "test_plan": {"commands": ["python -m unittest"]},
                },
            )
            storage.close()

            result = export_sqlite_to_mysql(
                MysqlExportOptions(
                    sqlite_path=db_path,
                    output_path=output_path,
                    database_name="ops_agent_test",
                    batch_size=1,
                )
            )
            sql = output_path.read_text(encoding="utf-8")

        self.assertEqual("exported", result["status"])
        self.assertGreaterEqual(result["row_counts"]["incidents"], 1)
        self.assertGreaterEqual(result["row_counts"]["ai_repair_proposals"], 1)
        self.assertIn("CREATE DATABASE IF NOT EXISTS `ops_agent_test`", sql)
        self.assertIn("CREATE TABLE `incidents`", sql)
        self.assertIn("`id` BIGINT NOT NULL AUTO_INCREMENT", sql)
        self.assertNotIn("LONGTEXT NOT NULL DEFAULT", sql)
        self.assertIn("CREATE INDEX `idx_ai_repair_proposals_status`", sql)
        self.assertIn("INSERT INTO `incidents`", sql)
        self.assertIn("analysis with 中文", sql)
        self.assertIn("INSERT INTO `ai_repair_proposals`", sql)

    def test_schema_only_export_omits_inserts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "ops.db"
            output_path = Path(tmp) / "schema.sql"
            Storage(db_path).close()

            result = export_sqlite_to_mysql(
                MysqlExportOptions(sqlite_path=db_path, output_path=output_path, schema_only=True)
            )
            sql = output_path.read_text(encoding="utf-8")

        self.assertEqual("exported", result["status"])
        self.assertIn("CREATE TABLE `incidents`", sql)
        self.assertNotIn("INSERT INTO", sql)


if __name__ == "__main__":
    unittest.main()
