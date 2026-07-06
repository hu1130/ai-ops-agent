import json
import os
import subprocess
import tempfile
import unittest
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from ops_agent.ai.repair import (
    build_ai_repair_proposal,
    dry_run_ai_repair_proposal,
    prepare_ai_repair_branch,
    publish_ai_repair_pull_request,
    record_ai_repair_test_result,
    sandbox_test_ai_repair_proposal,
    validate_patch_dry_run,
)
from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class AiRepairTest(unittest.TestCase):
    def test_rule_based_repair_proposal_tracks_dry_run_and_test_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={"ai": {"repair": {"provider": "rules", "model": "rule-based-repair-v1"}}},
                base_dir=Path(tmp),
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [
                    CheckResult(
                        source="http",
                        name="DuanShiping health",
                        status="critical",
                        summary="HTTP 404 from https://duanshiping.setdx.com/healthz",
                    )
                ],
                classification={"category": "route_or_healthcheck_config_mismatch", "confidence": 0.91},
            )
            storage.save_incident_diagnosis(
                incident_id,
                {
                    "context": {"environment": "prod", "run_type": "normal"},
                    "probable_causes": [
                        {"category": "route_or_healthcheck_config_mismatch", "confidence": 0.91}
                    ],
                    "next_decision": {"action": "review_monitor_target"},
                    "evidence": {"http_status": 404},
                },
            )

            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            dry_run = dry_run_ai_repair_proposal(storage, proposal["id"], actor="tester")
            tested = record_ai_repair_test_result(
                storage,
                proposal["id"],
                result={"status": "passed", "output": "unit tests passed"},
                actor="tester",
            )
            rows = storage.latest_ai_repair_proposals(incident_id=incident_id)
            storage.close()

        self.assertEqual("proposed", proposal["status"])
        self.assertEqual("low", proposal["risk"])
        self.assertEqual("config_or_route_review", proposal["patch"]["patch_type"])
        self.assertEqual("dry_run_passed", dry_run["status"])
        self.assertTrue(dry_run["dry_run"]["valid"])
        self.assertFalse(dry_run["dry_run"]["mutates_files"])
        self.assertEqual("test_passed", tested["status"])
        self.assertEqual("passed", tested["test_result"]["status"])
        self.assertEqual([proposal["id"]], [row["id"] for row in rows])

    def test_ai_repair_dashboard_api_runs_proposal_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"name": "ops"},
                    "ai": {"repair": {"provider": "rules", "model": "rule-based-repair-v1"}},
                },
                base_dir=Path(tmp),
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [
                    CheckResult(
                        source="http",
                        name="DuanShiping health",
                        status="critical",
                        summary="HTTP 404 from https://duanshiping.setdx.com/healthz",
                    )
                ],
                classification={"category": "route_or_healthcheck_config_mismatch", "confidence": 0.91},
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                proposal = post_json(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ai-repair/propose",
                    {"actor": "tester"},
                )
                repair_id = proposal["id"]
                listed = get_json(f"http://{host}:{port}/api/ai-repairs?incident_id={incident_id}")
                dry_run = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{repair_id}/dry-run",
                    {"actor": "tester"},
                )
                tested = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{repair_id}/test",
                    {"actor": "tester", "status": "passed", "output": "ok"},
                )
                approved = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{repair_id}/approve",
                    {"actor": "tester", "note": "reviewed"},
                )
                detail = get_json(f"http://{host}:{port}/api/ai-repairs/{repair_id}")
                audit = storage.latest_api_audit_logs(20)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(repair_id, listed[0]["id"])
        self.assertEqual("dry_run_passed", dry_run["status"])
        self.assertEqual("test_passed", tested["status"])
        self.assertEqual("approved", approved["status"])
        self.assertEqual("approved", detail["status"])
        self.assertIn("ai_repair.propose", {row["operation"] for row in audit})
        self.assertIn("ai_repair.dry_run", {row["operation"] for row in audit})
        self.assertIn("ai_repair.approve", {row["operation"] for row in audit})

    def test_model_repair_uses_openai_compatible_mock_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": {
                                "title": "Patch HTTP timeout handling",
                                "summary": "Model generated a small source diff.",
                                "risk": "medium",
                                "root_cause": "Request timeout handling is too broad.",
                                "repair_plan": ["Narrow the timeout branch.", "Run unit tests."],
                                "patch": {
                                    "schema_version": 1,
                                    "patch_type": "unified_diff",
                                    "apply_mode": "auto_apply",
                                    "diff": (
                                        "diff --git a/ops_agent/http_monitor.py b/ops_agent/http_monitor.py\n"
                                        "--- a/ops_agent/http_monitor.py\n"
                                        "+++ b/ops_agent/http_monitor.py\n"
                                        "@@ -1 +1 @@\n"
                                        "-old\n"
                                        "+new\n"
                                    ),
                                    "files": [
                                        {
                                            "path": "ops_agent/http_monitor.py",
                                            "change_type": "modify",
                                            "reason": "tighten timeout branch",
                                        }
                                    ],
                                },
                                "test_plan": {"commands": ["python -m unittest tests.test_http_monitor"]},
                            },
                        }
                    }
                },
                base_dir=Path(tmp),
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
                classification={"category": "service_unavailable", "confidence": 0.88},
            )

            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            dry_run = dry_run_ai_repair_proposal(storage, proposal["id"], actor="tester")
            storage.close()

        self.assertEqual("openai_compatible", proposal["model_provider"])
        self.assertEqual("mock-repair-model", proposal["model_name"])
        self.assertEqual("model_repair_proposal", proposal["prompt"]["mode"])
        self.assertEqual("proposal_only", proposal["patch"]["apply_mode"])
        self.assertEqual("unified_diff", proposal["patch"]["patch_type"])
        self.assertEqual(["python -m unittest tests.test_http_monitor"], proposal["test_plan"]["commands"])
        self.assertEqual("dry_run_passed", dry_run["status"])
        self.assertTrue(dry_run["dry_run"]["mutates_files"])
        self.assertIn("ops_agent/http_monitor.py", dry_run["dry_run"]["checked_files"])

    def test_dry_run_blocks_unsafe_model_patch_paths(self) -> None:
        result = validate_patch_dry_run(
            {
                "schema_version": 1,
                "patch_type": "unified_diff",
                "apply_mode": "auto_apply",
                "diff": (
                    "diff --git a/.env b/.env\n"
                    "--- a/.env\n"
                    "+++ b/.env\n"
                    "@@ -1 +1 @@\n"
                    "-TOKEN=old\n"
                    "+TOKEN=new\n"
                ),
                "files": [{"path": "../outside.py", "change_type": "modify"}],
            }
        )

        self.assertFalse(result["valid"])
        self.assertTrue(any("apply_mode" in error for error in result["errors"]))
        self.assertTrue(any("unsafe file path" in error for error in result["errors"]))
        self.assertTrue(any("unsafe diff path" in error for error in result["errors"]))

    def test_sandbox_test_applies_patch_to_copy_and_builds_approval_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    }
                },
                base_dir=repo,
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})

            tested = sandbox_test_ai_repair_proposal(storage, proposal["id"], repo, actor="tester")
            original_content = (repo / "sample.txt").read_text(encoding="utf-8")
            storage.close()

        self.assertEqual("test_passed", tested["status"])
        self.assertTrue(tested["test_result"]["sandbox"]["patch_applied"])
        self.assertEqual("passed", tested["test_result"]["sandbox"]["status"])
        self.assertTrue(tested["test_result"]["approval_report"]["ready_to_approve"])
        self.assertEqual("old\n", original_content)

    def test_prepare_branch_creates_auditable_worktree_commit_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    }
                },
                base_dir=repo,
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            tested = sandbox_test_ai_repair_proposal(storage, proposal["id"], repo, actor="tester")
            approved = storage.update_ai_repair_proposal_status(proposal["id"], "approved", actor="tester")

            prepared = prepare_ai_repair_branch(storage, proposal["id"], repo, actor="tester")
            controlled_apply = prepared["test_result"]["controlled_apply"]
            worktree = Path(controlled_apply["worktree_path"])
            original_content = (repo / "sample.txt").read_text(encoding="utf-8")
            worktree_content = (worktree / "sample.txt").read_text(encoding="utf-8")
            main_status = run_git_fixture(repo, ["status", "--porcelain"])
            branch_list = run_git_fixture(repo, ["branch", "--list", controlled_apply["branch_name"]])
            storage.close()

        self.assertEqual("test_passed", tested["status"])
        self.assertTrue(tested["test_result"]["approval_report"]["ready_to_approve"])
        self.assertEqual("approved", approved["status"])
        self.assertEqual("branch_prepared", prepared["status"])
        self.assertTrue(controlled_apply["ready_for_pr"])
        self.assertTrue(controlled_apply["patch_applied"])
        self.assertTrue(controlled_apply["commit_created"])
        self.assertTrue(controlled_apply["commit"])
        self.assertTrue(controlled_apply["branch_name"].startswith("ai-repair-"))
        self.assertIn("sample.txt", controlled_apply["changed_files"])
        self.assertEqual("old\n", original_content)
        self.assertEqual("new\n", worktree_content)
        self.assertEqual("", main_status)
        self.assertIn(controlled_apply["branch_name"], branch_list)

    def test_publish_pull_request_pushes_branch_and_records_pr_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            remote = create_bare_remote(Path(tmp) / "remote.git")
            run_git_fixture(repo, ["remote", "add", "origin", str(remote)])
            fake_bin = create_fake_gh(Path(tmp) / "fake-bin", "https://github.com/example/repo/pull/7")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    }
                },
                base_dir=repo,
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            sandbox_test_ai_repair_proposal(storage, proposal["id"], repo, actor="tester")
            storage.update_ai_repair_proposal_status(proposal["id"], "approved", actor="tester")
            prepared = prepare_ai_repair_branch(storage, proposal["id"], repo, actor="tester")

            with patched_path(fake_bin):
                published = publish_ai_repair_pull_request(storage, proposal["id"], repo, actor="tester")
            branch_name = published["test_result"]["pull_request"]["branch_name"]
            remote_branches = run_git_fixture(remote, ["branch", "--list", branch_name])
            storage.close()

        self.assertEqual("branch_prepared", prepared["status"])
        self.assertEqual("pr_created", published["status"])
        self.assertEqual("https://github.com/example/repo/pull/7", published["test_result"]["pull_request"]["pr_url"])
        self.assertEqual(7, published["test_result"]["pull_request"]["pr_number"])
        self.assertEqual("gh", published["test_result"]["pull_request"]["method"])
        self.assertTrue(published["test_result"]["pull_request"]["pushed"])
        self.assertIn(branch_name, remote_branches)

    def test_ai_repair_dashboard_api_runs_sandbox_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"name": "ops"},
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    },
                },
                base_dir=repo,
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                proposal = post_json(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ai-repair/propose",
                    {"actor": "tester"},
                )
                tested = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/sandbox-test",
                    {"actor": "tester"},
                )
                audit = storage.latest_api_audit_logs(20)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("test_passed", tested["status"])
        self.assertTrue(tested["test_result"]["approval_report"]["ready_to_approve"])
        self.assertIn("ai_repair.sandbox_test", {row["operation"] for row in audit})

    def test_ai_repair_dashboard_api_prepares_branch_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"name": "ops"},
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    },
                },
                base_dir=repo,
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                proposal = post_json(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ai-repair/propose",
                    {"actor": "tester"},
                )
                tested = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/sandbox-test",
                    {"actor": "tester"},
                )
                approved = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/approve",
                    {"actor": "tester"},
                )
                prepared = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/prepare-branch",
                    {"actor": "tester"},
                )
                audit = storage.latest_api_audit_logs(30)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("test_passed", tested["status"])
        self.assertEqual("approved", approved["status"])
        self.assertEqual("branch_prepared", prepared["status"])
        self.assertTrue(prepared["test_result"]["controlled_apply"]["ready_for_pr"])
        self.assertIn("ai_repair.prepare_branch", {row["operation"] for row in audit})

    def test_ai_repair_dashboard_api_creates_pr_after_branch_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            remote = create_bare_remote(Path(tmp) / "remote.git")
            run_git_fixture(repo, ["remote", "add", "origin", str(remote)])
            fake_bin = create_fake_gh(Path(tmp) / "fake-bin", "https://github.com/example/repo/pull/8")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"name": "ops"},
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    },
                },
                base_dir=repo,
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                proposal = post_json(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ai-repair/propose",
                    {"actor": "tester"},
                )
                post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/sandbox-test",
                    {"actor": "tester"},
                )
                post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/approve",
                    {"actor": "tester"},
                )
                prepared = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/prepare-branch",
                    {"actor": "tester"},
                )
                with patched_path(fake_bin):
                    published = post_json(
                        f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/create-pr",
                        {"actor": "tester"},
                    )
                audit = storage.latest_api_audit_logs(40)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("branch_prepared", prepared["status"])
        self.assertEqual("pr_created", published["status"])
        self.assertEqual("https://github.com/example/repo/pull/8", published["test_result"]["pull_request"]["pr_url"])
        self.assertIn("ai_repair.create_pr", {row["operation"] for row in audit})


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str) -> dict | list:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def create_sandbox_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    tests_dir = root / "tests"
    tests_dir.mkdir()
    (root / "sample.txt").write_text("old\n", encoding="utf-8")
    (tests_dir / "test_sample.py").write_text(
        "\n".join(
            [
                "import unittest",
                "from pathlib import Path",
                "",
                "class SampleTest(unittest.TestCase):",
                "    def test_patch_was_applied(self):",
                "        self.assertEqual('new', Path('sample.txt').read_text(encoding='utf-8').strip())",
                "",
                "if __name__ == '__main__':",
                "    unittest.main()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return root


def create_git_sandbox_repo(root: Path) -> Path:
    repo = create_sandbox_repo(root)
    run_git_fixture(repo, ["init"])
    run_git_fixture(repo, ["add", "."])
    run_git_fixture(
        repo,
        [
            "-c",
            "user.name=Tester",
            "-c",
            "user.email=tester@example.local",
            "commit",
            "-m",
            "Initial fixture",
        ],
    )
    return repo


def create_bare_remote(root: Path) -> Path:
    run_git_fixture(root.parent, ["init", "--bare", str(root)])
    return root


def create_fake_gh(root: Path, pr_url: str) -> Path:
    root.mkdir(parents=True)
    if os.name == "nt":
        script = root / "gh.cmd"
        script.write_text(f"@echo off\necho {pr_url}\n", encoding="utf-8")
    else:
        script = root / "gh"
        script.write_text(f"#!/bin/sh\necho {pr_url}\n", encoding="utf-8")
        script.chmod(0o755)
    return root


@contextmanager
def patched_path(prefix: Path):
    original = os.environ.get("PATH", "")
    os.environ["PATH"] = str(prefix) + os.pathsep + original
    try:
        yield
    finally:
        os.environ["PATH"] = original


def run_git_fixture(cwd: Path, args: list[str]) -> str:
    cwd.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def sandbox_patch_response() -> dict:
    return {
        "title": "Patch sample file",
        "summary": "Model generated a sandbox-testable diff.",
        "risk": "low",
        "root_cause": "sample file needs update",
        "repair_plan": ["Update sample.txt", "Run unit tests"],
        "patch": {
            "schema_version": 1,
            "patch_type": "unified_diff",
            "apply_mode": "proposal_only",
            "diff": (
                "diff --git a/sample.txt b/sample.txt\n"
                "--- a/sample.txt\n"
                "+++ b/sample.txt\n"
                "@@ -1 +1 @@\n"
                "-old\n"
                "+new\n"
            ),
            "files": [{"path": "sample.txt", "change_type": "modify", "reason": "unit test fixture"}],
        },
        "test_plan": {"commands": ["python -m unittest discover -s tests"]},
    }


if __name__ == "__main__":
    unittest.main()
