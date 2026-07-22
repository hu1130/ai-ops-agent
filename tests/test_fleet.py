import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ops_agent.config import AppConfig, load_config
from ops_agent.dashboard import start_dashboard
from ops_agent.fleet import (
    authenticate_fleet_token,
    bind_fleet_project_candidate,
    collect_local_node_payload,
    fleet_project_candidates,
    fleet_snapshot,
    register_fleet_node,
    run_fleet_node_checks,
)
from ops_agent.storage import Storage


class FleetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.storage = Storage(self.root / "ops.db")

    def tearDown(self) -> None:
        self.storage.close()
        self.temp.cleanup()

    def config(self, **fleet: object) -> AppConfig:
        return AppConfig(
            raw={
                "app": {},
                "fleet": {"enabled": True, "enrollment_token": "fleet-secret", **fleet},
            },
            base_dir=self.root,
        )

    def test_fleet_token_is_separate_from_admin_auth(self) -> None:
        config = self.config()
        self.assertEqual("config", authenticate_fleet_token("fleet-secret", config))
        self.assertEqual("", authenticate_fleet_token("admin-secret", config))

    def test_node_registration_and_offline_snapshot(self) -> None:
        config = self.config(offline_after_seconds=60)
        node = register_fleet_node(
            self.storage,
            config,
            {
                "node_id": "server-1",
                "name": "Production 1",
                "projects": [{"candidate_id": "compose--sales", "name": "sales", "asset_count": 2}],
                "discovery": {"status": "ok"},
            },
            source_ip="10.0.0.8",
        )
        self.assertEqual("online", node["status"])
        self.assertEqual("10.0.0.8", node["address"])

        stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        self.storage.connection.execute(
            "update fleet_nodes set last_seen_at = ? where node_id = ?",
            (stale, "server-1"),
        )
        self.storage.connection.commit()
        snapshot = fleet_snapshot(self.storage, config)

        self.assertEqual(1, snapshot["summary"]["offline"])
        checks = run_fleet_node_checks(self.storage, config)
        self.assertEqual("critical", checks[0].status)
        self.assertIn("失联", checks[0].summary)

    def test_remote_project_missing_only_when_discovery_is_healthy(self) -> None:
        config = AppConfig(
            raw={
                "fleet": {"enabled": True, "enrollment_token": "fleet-secret"},
                "projects": [
                    {
                        "id": "sales",
                        "name": "Sales",
                        "enabled": True,
                        "management_mode": "managed",
                        "discovery_bindings": {
                            "source": "fleet",
                            "node_id": "server-1",
                            "candidate_id": "compose--sales",
                        },
                    }
                ],
            },
            base_dir=self.root,
        )
        register_fleet_node(
            self.storage,
            config,
            {"node_id": "server-1", "projects": [], "discovery": {"status": "ok"}},
        )
        checks = run_fleet_node_checks(self.storage, config)
        project_check = next(row for row in checks if row.source == "fleet_project")
        self.assertEqual("critical", project_check.status)

        register_fleet_node(
            self.storage,
            config,
            {
                "node_id": "server-1",
                "projects": [],
                "discovery": {"status": "warning", "error": "docker timeout"},
            },
        )
        checks = run_fleet_node_checks(self.storage, config)
        self.assertFalse(any(row.source == "fleet_project" for row in checks))
        self.assertEqual("warning", checks[0].status)

    def test_remote_resource_thresholds_are_checked(self) -> None:
        config = self.config(resource_thresholds={"disk_warning": 80, "disk_critical": 95})
        register_fleet_node(
            self.storage,
            config,
            {
                "node_id": "server-1",
                "metrics": {"disk_percent": 88.5},
                "projects": [],
                "discovery": {"status": "ok"},
            },
        )

        checks = run_fleet_node_checks(self.storage, config)
        disk = next(row for row in checks if row.source == "fleet_resource" and "Disk" in row.name)

        self.assertEqual("warning", disk.status)
        self.assertEqual(88.5, disk.details["used_percent"])

    def test_remote_project_can_be_bound_to_config(self) -> None:
        config_path = self.root / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "app": {"database_path": "ops.db"},
                    "fleet": {"enabled": True, "enrollment_token": "fleet-secret"},
                    "projects": [],
                }
            ),
            encoding="utf-8",
        )
        config = load_config(config_path)
        register_fleet_node(
            self.storage,
            config,
            {
                "node_id": "server-1",
                "name": "Server 1",
                "projects": [
                    {
                        "candidate_id": "compose--sales",
                        "suggested_project_id": "sales",
                        "name": "Sales",
                        "asset_names": ["sales-api-1", "sales-db-1"],
                    }
                ],
                "discovery": {"status": "ok"},
            },
        )
        candidate = fleet_project_candidates(self.storage, config)[0]
        result = bind_fleet_project_candidate(
            self.storage,
            config,
            candidate["id"],
            {"management_mode": "observe_only", "automation_level": "monitor_only"},
        )

        self.assertEqual("created", result["action"])
        saved = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual("fleet", saved["projects"][0]["discovery_bindings"]["source"])
        self.assertEqual("server-1", saved["projects"][0]["discovery_bindings"]["node_id"])

    @patch("ops_agent.project_onboarding.discover_project_candidates")
    def test_local_payload_includes_discovery_evidence(self, discover) -> None:
        discover.return_value = {
            "status": "ok",
            "summary": {"detected_projects": 1},
            "error": "",
            "candidates": [
                {
                    "id": "compose--app",
                    "suggested_project_id": "app",
                    "name": "App",
                    "source": "docker_compose",
                    "confidence": 0.98,
                    "asset_count": 1,
                    "asset_names": ["app-1"],
                }
            ],
        }
        payload = collect_local_node_payload(self.config(), "server-1")

        self.assertEqual("ok", payload["discovery"]["status"])
        self.assertEqual("compose--app", payload["projects"][0]["candidate_id"])


class FleetApiTest(unittest.TestCase):
    def test_registration_auth_and_admin_disable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"api_token": "admin-secret", "api_auth_required_for_reads": True},
                    "fleet": {"enabled": True, "enrollment_token": "fleet-secret"},
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            base = f"http://{host}:{port}"
            try:
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    post_json(f"{base}/api/fleet/heartbeat", {"node_id": "server-1"}, "wrong")
                self.assertEqual(401, caught.exception.code)

                accepted = post_json(
                    f"{base}/api/fleet/heartbeat",
                    {"node_id": "server-1", "projects": [], "discovery": {"status": "ok"}},
                    "fleet-secret",
                )
                self.assertEqual("online", accepted["status"])

                listed = get_json(f"{base}/api/fleet/nodes", "admin-secret")
                self.assertEqual(1, listed["summary"]["online"])

                disabled = post_json(f"{base}/api/fleet/nodes/server-1/disable", {}, "admin-secret")
                self.assertEqual("disabled", disabled["status"])
                self.assertFalse(storage.get_fleet_node("server-1")["enabled"])
            finally:
                server.shutdown()
                server.server_close()
                storage.close()


def post_json(url: str, payload: dict, token: str) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str, token: str) -> dict:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
