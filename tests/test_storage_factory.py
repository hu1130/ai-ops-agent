import os
import tempfile
import unittest
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.storage import Storage
from ops_agent.storage_factory import (
    BufferedCursor,
    MySQLConnectionAdapter,
    mysql_placeholders,
    mysql_settings,
    open_configured_storage,
)


class FakeCursor:
    def __init__(self) -> None:
        self.description = None
        self.lastrowid = 0
        self.rowcount = 0

    def execute(self, sql: str, params: tuple) -> None:
        self.description = (("id",),) if sql.strip().lower().startswith("select") else None

    def fetchall(self) -> list[dict]:
        return []

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.rollbacks = 0
        self.commits = 0
        self.pings = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor()

    def rollback(self) -> None:
        self.rollbacks += 1

    def commit(self) -> None:
        self.commits += 1

    def ping(self, reconnect: bool = False) -> None:
        self.pings += 1


class StorageFactoryTest(unittest.TestCase):
    def test_sqlite_remains_default_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(raw={"app": {"database_path": "data/ops.db"}}, base_dir=Path(tmp))
            storage = open_configured_storage(config)
            try:
                self.assertIsInstance(storage, Storage)
                self.assertTrue((Path(tmp) / "data" / "ops.db").exists())
            finally:
                storage.close()

    def test_mysql_settings_load_password_from_environment(self) -> None:
        config = AppConfig(
            raw={
                "app": {"storage_backend": "mysql"},
                "mysql": {"database": "ops", "user": "agent", "password_env": "TEST_OPS_MYSQL_PASSWORD"},
            },
            base_dir=Path("."),
        )
        previous = os.environ.get("TEST_OPS_MYSQL_PASSWORD")
        os.environ["TEST_OPS_MYSQL_PASSWORD"] = "secret"
        try:
            settings = mysql_settings(config)
        finally:
            if previous is None:
                os.environ.pop("TEST_OPS_MYSQL_PASSWORD", None)
            else:
                os.environ["TEST_OPS_MYSQL_PASSWORD"] = previous

        self.assertEqual("ops", settings["database"])
        self.assertEqual("agent", settings["user"])
        self.assertEqual("secret", settings["password"])

    def test_mysql_placeholder_and_buffered_cursor_compatibility(self) -> None:
        cursor = BufferedCursor([{"id": 1}, {"id": 2}], lastrowid=7, rowcount=2)

        self.assertEqual("select * from incidents where id = %s", mysql_placeholders("select * from incidents where id = ?"))
        self.assertEqual({"id": 1}, cursor.fetchone())
        self.assertEqual([{"id": 2}], cursor.fetchall())
        self.assertEqual(7, cursor.lastrowid)

    def test_mysql_read_only_query_ends_transaction_without_committing_pending_writes(self) -> None:
        connection = FakeConnection()
        adapter = MySQLConnectionAdapter(connection)

        adapter.execute("select * from incidents")
        self.assertEqual(1, connection.rollbacks)
        self.assertEqual(1, connection.pings)

        adapter.execute("update incidents set status = ?", ("closed",))
        adapter.execute("select * from incidents")
        self.assertEqual(1, connection.rollbacks)
        self.assertEqual(2, connection.pings)
        adapter.commit()
        self.assertEqual(1, connection.commits)


if __name__ == "__main__":
    unittest.main()
