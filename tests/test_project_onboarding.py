import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.project_onboarding import bind_project_candidate, discover_project_candidates


def docker_result(rows: list[dict]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, stdout="\n".join(json.dumps(row) for row in rows), stderr="")


def compose_rows() -> list[dict]:
    return [
        {
            "Names": "sales-api-1",
            "Image": "sales-api:latest",
            "State": "running",
            "Status": "Up 2 hours",
            "Ports": "0.0.0.0:8080->8080/tcp",
            "Labels": "com.docker.compose.project=sales,com.docker.compose.service=api",
        },
        {
            "Names": "sales-mysql-1",
            "Image": "mysql:8.4",
            "State": "running",
            "Status": "Up 2 hours",
            "Ports": "3306/tcp",
            "Labels": "com.docker.compose.project=sales,com.docker.compose.service=mysql",
        },
    ]


class ProjectOnboardingTest(unittest.TestCase):
    def test_disabled_legacy_project_is_reported_as_ignored(self) -> None:
        result = discover_project_candidates(
            {"projects": [{"id": "sales", "enabled": False}]},
            runner=lambda *_args, **_kwargs: docker_result(compose_rows()),
        )

        self.assertEqual("bound", result["candidates"][0]["binding_status"])
        self.assertEqual("ignored", result["candidates"][0]["management_mode"])

    def test_disabled_legacy_project_with_enabled_target_is_observe_only(self) -> None:
        result = discover_project_candidates(
            {
                "projects": [{"id": "sales", "enabled": False}],
                "docker_checks": [{"container": "sales-api-1", "enabled": True}],
            },
            runner=lambda *_args, **_kwargs: docker_result(compose_rows()),
        )

        self.assertEqual("observe_only", result["candidates"][0]["management_mode"])

    def test_groups_compose_application_and_database_as_one_project(self) -> None:
        result = discover_project_candidates({}, runner=lambda *_args, **_kwargs: docker_result(compose_rows()))

        self.assertEqual(1, result["summary"]["detected_projects"])
        self.assertEqual("sales", result["candidates"][0]["suggested_project_id"])
        self.assertEqual(2, result["candidates"][0]["asset_count"])
        self.assertEqual("docker_compose", result["candidates"][0]["source"])

    def test_binding_persists_project_and_monitor_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            raw = {
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "projects": [],
            }
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            config = AppConfig(raw=raw, base_dir=Path(tmp), config_path=config_path)

            result = bind_project_candidate(
                config,
                "compose--sales",
                {"management_mode": "managed", "automation_level": "runtime_self_heal"},
                runner=lambda *_args, **_kwargs: docker_result(compose_rows()),
            )

            stored = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual("created", result["action"])
            self.assertEqual("managed", stored["projects"][0]["management_mode"])
            self.assertEqual("runtime_self_heal", stored["projects"][0]["automation_level"])
            self.assertEqual(2, len(stored["docker_checks"]))
            self.assertEqual({"api", "mysql"}, {row["compose_service"] for row in stored["docker_checks"]})
            self.assertTrue(all(row["project_id"] == "sales" for row in stored["docker_checks"]))

    def test_observe_only_forces_monitor_only_and_ignore_disables_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            raw = {
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            }
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            config = AppConfig(raw=raw, base_dir=Path(tmp), config_path=config_path)
            runner = lambda *_args, **_kwargs: docker_result(compose_rows())

            observe = bind_project_candidate(
                config,
                "compose--sales",
                {"management_mode": "observe_only"},
                runner=runner,
            )
            ignored = bind_project_candidate(
                config,
                "compose--sales",
                {"management_mode": "ignored"},
                runner=runner,
            )

            self.assertEqual("monitor_only", observe["project"]["automation_level"])
            self.assertEqual("ignored", ignored["project"]["management_mode"])
            self.assertTrue(all(not row["enabled"] for row in config.raw["docker_checks"]))


if __name__ == "__main__":
    unittest.main()
