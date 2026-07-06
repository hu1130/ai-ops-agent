import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ops_agent.ai.repair import (
    ai_repair_approval_queue,
    build_ai_repair_proposal,
    deploy_ai_repair_after_merge,
    dry_run_ai_repair_proposal,
    normalize_model_endpoint_url,
    prepare_ai_repair_branch,
    publish_ai_repair_pull_request,
    record_ai_repair_test_result,
    run_ai_repair_pipeline_for_incident,
    run_project_ai_repair_drill,
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

    def test_ai_repair_dashboard_api_returns_approval_queue(self) -> None:
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
            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            dry_run_ai_repair_proposal(storage, proposal["id"], actor="tester")
            sandbox_test_ai_repair_proposal(storage, proposal["id"], repo, actor="tester")
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                queue = get_json(f"http://{host}:{port}/api/ai-repairs/approval-queue")
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("ai_repair_approval_queue", queue["mode"])
        self.assertEqual(1, queue["summary"]["ready_for_approval"])
        self.assertEqual("ready_for_approval", queue["items"][0]["queue_state"])
        self.assertEqual("approve", queue["items"][0]["next_action"]["type"])
        self.assertEqual(incident_id, queue["items"][0]["incident"]["id"])

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

    def test_deepseek_repair_provider_uses_openai_compatible_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "ai": {
                        "repair": {
                            "provider": "deepseek",
                            "enabled": True,
                            "mock_response": sandbox_patch_response(),
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
            )

            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            endpoint = normalize_model_endpoint_url(
                {"provider": "deepseek", "endpoint_url": "https://api.deepseek.com"}
            )
            storage.close()

        self.assertEqual("deepseek", proposal["model_provider"])
        self.assertEqual("deepseek-v4-flash", proposal["model_name"])
        self.assertEqual("https://api.deepseek.com/chat/completions", endpoint)
        self.assertEqual("proposal_only", proposal["patch"]["apply_mode"])

    def test_model_repair_prompt_includes_bounded_repository_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_sandbox_repo(Path(tmp) / "repo")
            (repo / ".env").write_text("TOKEN=super-secret\n", encoding="utf-8")
            (repo / "settings.py").write_text(
                "API_KEY = 'super-secret'\nTIMEOUT_SECONDS = 10\n",
                encoding="utf-8",
            )
            (repo / "large_module.py").write_text(
                "def marker():\n    return 'large-context-file'\n" + "# filler\n" * 3000,
                encoding="utf-8",
            )
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "projects": [
                        {
                            "id": "prod",
                            "environment": "prod",
                            "run_types": ["normal"],
                            "repo_root": str(repo),
                            "repair_context_files": ["sample.txt", ".env", "settings.py", "large_module.py"],
                        }
                    ],
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                            "repository_context": {"enabled": True, "max_files": 4, "max_file_chars": 2000},
                        }
                    },
                },
                base_dir=Path(tmp),
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )

            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            prompt_payload = json.loads(proposal["prompt"]["user"])
            repository_context = prompt_payload["repository_context"]
            storage.close()

        file_paths = [item["path"] for item in repository_context["files"]]
        combined_content = "\n".join(item["content"] for item in repository_context["files"])
        self.assertEqual("prod", prompt_payload["project"]["id"])
        self.assertIn("sample.txt", file_paths)
        self.assertIn("settings.py", file_paths)
        self.assertIn("large_module.py", file_paths)
        self.assertNotIn(".env", file_paths)
        large_file = next(item for item in repository_context["files"] if item["path"] == "large_module.py")
        self.assertTrue(large_file["truncated"])
        self.assertIn("large-context-file", large_file["content"])
        self.assertIn("[redacted sensitive line]", combined_content)
        self.assertNotIn("super-secret", combined_content)

    def test_incident_pipeline_uses_project_repo_commands_and_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "projects": [
                        {
                            "id": "prod",
                            "environment": "prod",
                            "run_types": ["normal"],
                            "repo_root": str(repo),
                            "test_commands": ["python -m py_compile tests/test_sample.py"],
                            "repair_policy": {
                                "auto_approve": True,
                                "auto_approve_risks": ["low"],
                                "prepare_branch": True,
                            },
                        }
                    ],
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                        }
                    },
                },
                base_dir=Path(tmp) / "not-the-project",
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )

            repaired = run_ai_repair_pipeline_for_incident(storage, config, incident_id, Path(tmp), actor="tester")
            controlled_apply = repaired["test_result"]["controlled_apply"]
            main_status = run_git_fixture(repo, ["status", "--porcelain"])
            storage.close()

        pipeline = repaired["test_result"]["pipeline"]
        self.assertEqual("branch_prepared", repaired["status"])
        self.assertEqual("completed", pipeline["status"])
        self.assertTrue(pipeline["policy"]["auto_approve"])
        self.assertTrue(pipeline["policy"]["prepare_branch"])
        self.assertEqual(["python -m py_compile tests/test_sample.py"], controlled_apply["commands"])
        self.assertEqual("", main_status)

    def test_project_ai_repair_drill_creates_safe_dry_run_for_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "projects": [
                        {
                            "id": "prod",
                            "name": "Production",
                            "environment": "prod",
                            "run_types": ["normal"],
                            "repo_root": str(repo),
                            "repair_context_files": ["sample.txt"],
                            "test_commands": ["python -m py_compile tests/test_sample.py"],
                        }
                    ],
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                            "repository_context": {"enabled": True},
                        }
                    },
                },
                base_dir=Path(tmp),
            )

            result = run_project_ai_repair_drill(
                storage,
                config,
                "prod",
                actor="tester",
                request={"summary": "Synthetic HTTP 500 for drill"},
            )
            prompt_payload = json.loads(result["proposal"]["prompt"]["user"])
            original_content = (repo / "sample.txt").read_text(encoding="utf-8")
            storage.close()

        self.assertEqual("project_ai_repair_drill", result["mode"])
        self.assertFalse(result["mutates_production"])
        self.assertEqual("resolved", result["incident"]["status"])
        self.assertEqual("dry_run_passed", result["status"])
        self.assertEqual("prod", prompt_payload["project"]["id"])
        self.assertEqual(["sample.txt"], [item["path"] for item in prompt_payload["repository_context"]["files"]])
        self.assertTrue(result["dry_run"]["mutates_files"])
        self.assertEqual("old\n", original_content)

    def test_project_ai_repair_drill_dashboard_api_runs_optional_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_sandbox_repo(Path(tmp) / "repo")
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "projects": [
                        {
                            "id": "prod",
                            "name": "Production",
                            "environment": "prod",
                            "run_types": ["normal"],
                            "repo_root": str(repo),
                            "repair_context_files": ["sample.txt"],
                            "test_commands": ["python -m unittest discover -s tests"],
                        }
                    ],
                    "ai": {
                        "repair": {
                            "provider": "openai_compatible",
                            "model": "mock-repair-model",
                            "mock_response": sandbox_patch_response(),
                            "repository_context": {"enabled": True},
                        }
                    },
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                result = post_json(
                    f"http://{host}:{port}/api/projects/prod/ai-repair/drill",
                    {
                        "actor": "tester",
                        "summary": "Synthetic HTTP 500 for project drill",
                        "run_sandbox": True,
                    },
                )
                audit = storage.latest_api_audit_logs(5)
                original_content = (repo / "sample.txt").read_text(encoding="utf-8")
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("ready", result["readiness"]["status"])
        self.assertEqual("test_passed", result["status"])
        self.assertEqual("passed", result["sandbox_result"]["status"])
        self.assertEqual("resolved", result["incident"]["status"])
        self.assertEqual("old\n", original_content)
        self.assertIn("ai_repair.project_drill", {row["operation"] for row in audit})

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

    def test_dry_run_allows_review_only_proposal_without_diff(self) -> None:
        result = validate_patch_dry_run(
            {
                "schema_version": 1,
                "patch_type": "manual_code_review",
                "apply_mode": "proposal_only",
                "diff": "",
                "files": [],
            }
        )

        self.assertTrue(result["valid"])
        self.assertFalse(result["mutates_files"])
        self.assertEqual([], result["errors"])
        self.assertTrue(any("review-only proposal" in warning for warning in result["warnings"]))

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

    def test_ai_repair_approval_queue_tracks_human_review_next_actions(self) -> None:
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
            dry_run_ai_repair_proposal(storage, proposal["id"], actor="tester")

            needs_sandbox = ai_repair_approval_queue(storage)
            sandbox_test_ai_repair_proposal(storage, proposal["id"], repo, actor="tester")
            ready = ai_repair_approval_queue(storage)
            storage.update_ai_repair_proposal_status(proposal["id"], "approved", actor="tester")
            approved = ai_repair_approval_queue(storage)
            storage.close()

        self.assertEqual("needs_sandbox", needs_sandbox["items"][0]["queue_state"])
        self.assertEqual("sandbox-test", needs_sandbox["items"][0]["next_action"]["type"])
        self.assertFalse(needs_sandbox["items"][0]["can_approve"])
        self.assertEqual("ready_for_approval", ready["items"][0]["queue_state"])
        self.assertEqual(1, ready["summary"]["ready_for_approval"])
        self.assertTrue(ready["items"][0]["can_approve"])
        self.assertEqual("approve", ready["items"][0]["next_action"]["type"])
        self.assertEqual("approved_needs_branch", approved["items"][0]["queue_state"])
        self.assertTrue(approved["items"][0]["can_prepare_branch"])
        self.assertEqual("prepare-branch", approved["items"][0]["next_action"]["type"])

    def test_ai_repair_pipeline_stops_at_human_approval_by_default(self) -> None:
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

            repaired = run_ai_repair_pipeline_for_incident(storage, config, incident_id, repo, actor="tester")
            rows = storage.latest_ai_repair_proposals(incident_id=incident_id)
            storage.close()

        pipeline = repaired["test_result"]["pipeline"]
        self.assertEqual("test_passed", repaired["status"])
        self.assertEqual("blocked", pipeline["status"])
        self.assertEqual("approval_required", pipeline["stopped_at"])
        self.assertEqual(["proposal", "dry_run", "sandbox_test"], [stage["name"] for stage in pipeline["stages"]])
        self.assertEqual([repaired["id"]], [row["id"] for row in rows])

    def test_ai_repair_pipeline_auto_approves_and_prepares_branch_when_requested(self) -> None:
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

            repaired = run_ai_repair_pipeline_for_incident(
                storage,
                config,
                incident_id,
                repo,
                actor="tester",
                auto_approve=True,
                prepare_branch=True,
            )
            controlled_apply = repaired["test_result"]["controlled_apply"]
            worktree_content = (Path(controlled_apply["worktree_path"]) / "sample.txt").read_text(encoding="utf-8")
            main_status = run_git_fixture(repo, ["status", "--porcelain"])
            storage.close()

        pipeline = repaired["test_result"]["pipeline"]
        self.assertEqual("branch_prepared", repaired["status"])
        self.assertEqual("completed", pipeline["status"])
        self.assertEqual("branch_prepared", pipeline["stopped_at"])
        self.assertEqual(
            ["proposal", "dry_run", "sandbox_test", "approval", "prepare_branch"],
            [stage["name"] for stage in pipeline["stages"]],
        )
        self.assertTrue(controlled_apply["ready_for_pr"])
        self.assertEqual("new\n", worktree_content)
        self.assertEqual("", main_status)

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

    def test_deploy_after_merge_fast_forwards_runs_tests_and_verifies_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            remote = create_bare_remote(Path(tmp) / "remote.git")
            run_git_fixture(repo, ["remote", "add", "origin", str(remote)])
            run_git_fixture(repo, ["push", "-u", "origin", "main"])
            fake_bin = create_fake_gh(Path(tmp) / "fake-bin", "https://github.com/example/repo/pull/9")
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
            prepare_ai_repair_branch(storage, proposal["id"], repo, actor="tester")
            with patched_path(fake_bin):
                published = publish_ai_repair_pull_request(storage, proposal["id"], repo, actor="tester")
            branch_name = published["test_result"]["pull_request"]["branch_name"]
            merge_branch_to_remote_main(remote, branch_name, Path(tmp) / "merge-clone")
            self.assertEqual("old\n", (repo / "sample.txt").read_text(encoding="utf-8"))

            with ok_http_server() as health_url:
                deployed = deploy_ai_repair_after_merge(
                    storage,
                    proposal["id"],
                    repo,
                    actor="tester",
                    commands=["python -m unittest discover -s tests"],
                    verify_urls=[health_url],
                    assume_merged=True,
                )
            deployed_content = (repo / "sample.txt").read_text(encoding="utf-8")
            storage.close()

        self.assertEqual("deployed", deployed["status"])
        self.assertEqual("new\n", deployed_content)
        self.assertTrue(deployed["test_result"]["deploy_result"]["ready"])
        self.assertEqual("passed", deployed["test_result"]["deploy_result"]["verification"]["status"])

    def test_deploy_after_merge_rolls_back_when_verification_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            remote = create_bare_remote(Path(tmp) / "remote.git")
            run_git_fixture(repo, ["remote", "add", "origin", str(remote)])
            run_git_fixture(repo, ["push", "-u", "origin", "main"])
            fake_bin = create_fake_gh(Path(tmp) / "fake-bin", "https://github.com/example/repo/pull/11")
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
            prepare_ai_repair_branch(storage, proposal["id"], repo, actor="tester")
            with patched_path(fake_bin):
                published = publish_ai_repair_pull_request(storage, proposal["id"], repo, actor="tester")
            branch_name = published["test_result"]["pull_request"]["branch_name"]
            merge_branch_to_remote_main(remote, branch_name, Path(tmp) / "merge-clone")

            with status_http_server(500) as failed_health_url, ok_http_server() as rollback_health_url:
                deployed = deploy_ai_repair_after_merge(
                    storage,
                    proposal["id"],
                    repo,
                    actor="tester",
                    commands=["python -m unittest discover -s tests"],
                    verify_urls=[failed_health_url],
                    rollback_commands=["python -m py_compile tests/test_sample.py"],
                    rollback_verify_urls=[rollback_health_url],
                    assume_merged=True,
                )
            rollback_content = (repo / "sample.txt").read_text(encoding="utf-8")
            storage.close()

        deploy_result = deployed["test_result"]["deploy_result"]
        rollback_result = deploy_result["rollback"]
        self.assertEqual("rollback_succeeded", deployed["status"])
        self.assertFalse(deploy_result["ready"])
        self.assertEqual("failed", deploy_result["verification"]["status"])
        self.assertTrue(rollback_result["ready"])
        self.assertEqual("passed", rollback_result["verification"]["status"])
        self.assertEqual(deploy_result["before_commit"], rollback_result["after_commit"])
        self.assertEqual("old\n", rollback_content)

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

    def test_ai_repair_dashboard_api_runs_incident_pipeline(self) -> None:
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
                repaired = post_json(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ai-repair/run-pipeline",
                    {"actor": "tester", "auto_approve": True, "prepare_branch": True},
                )
                audit = storage.latest_api_audit_logs(30)
                main_status = run_git_fixture(repo, ["status", "--porcelain"])
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        pipeline = repaired["test_result"]["pipeline"]
        self.assertEqual("branch_prepared", repaired["status"])
        self.assertEqual("completed", pipeline["status"])
        self.assertEqual("branch_prepared", pipeline["stopped_at"])
        self.assertEqual("", main_status)
        self.assertIn("ai_repair.run_pipeline", {row["operation"] for row in audit})

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

    def test_ai_repair_dashboard_api_deploys_merged_pr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            remote = create_bare_remote(Path(tmp) / "remote.git")
            run_git_fixture(repo, ["remote", "add", "origin", str(remote)])
            run_git_fixture(repo, ["push", "-u", "origin", "main"])
            fake_bin = create_fake_gh(Path(tmp) / "fake-bin", "https://github.com/example/repo/pull/10", merged=True)
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
                post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/prepare-branch",
                    {"actor": "tester"},
                )
                with patched_path(fake_bin):
                    published = post_json(
                        f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/create-pr",
                        {"actor": "tester"},
                    )
                    merge_branch_to_remote_main(
                        remote,
                        published["test_result"]["pull_request"]["branch_name"],
                        Path(tmp) / "merge-clone",
                    )
                    with ok_http_server() as health_url:
                        deployed = post_json(
                            f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/deploy-merged",
                            {
                                "actor": "tester",
                                "commands": ["python -m unittest discover -s tests"],
                                "verify_urls": [health_url],
                            },
                        )
                audit = storage.latest_api_audit_logs(60)
                deployed_content = (repo / "sample.txt").read_text(encoding="utf-8")
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("pr_created", published["status"])
        self.assertEqual("deployed", deployed["status"])
        self.assertEqual("new\n", deployed_content)
        self.assertEqual("passed", deployed["test_result"]["deploy_result"]["verification"]["status"])
        self.assertIn("ai_repair.deploy_merged", {row["operation"] for row in audit})

    def test_ai_repair_dashboard_api_rolls_back_failed_deploy_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = create_git_sandbox_repo(Path(tmp) / "repo")
            remote = create_bare_remote(Path(tmp) / "remote.git")
            run_git_fixture(repo, ["remote", "add", "origin", str(remote)])
            run_git_fixture(repo, ["push", "-u", "origin", "main"])
            fake_bin = create_fake_gh(Path(tmp) / "fake-bin", "https://github.com/example/repo/pull/12", merged=True)
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
                post_json(
                    f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/prepare-branch",
                    {"actor": "tester"},
                )
                with patched_path(fake_bin):
                    published = post_json(
                        f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/create-pr",
                        {"actor": "tester"},
                    )
                    merge_branch_to_remote_main(
                        remote,
                        published["test_result"]["pull_request"]["branch_name"],
                        Path(tmp) / "merge-clone",
                    )
                    with status_http_server(500) as failed_health_url, ok_http_server() as rollback_health_url:
                        deployed = post_json(
                            f"http://{host}:{port}/api/ai-repairs/{proposal['id']}/deploy-merged",
                            {
                                "actor": "tester",
                                "commands": ["python -m unittest discover -s tests"],
                                "verify_urls": [failed_health_url],
                                "rollback_commands": ["python -m py_compile tests/test_sample.py"],
                                "rollback_verify_urls": [rollback_health_url],
                            },
                        )
                audit = storage.latest_api_audit_logs(70)
                rollback_content = (repo / "sample.txt").read_text(encoding="utf-8")
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("pr_created", published["status"])
        self.assertEqual("rollback_succeeded", deployed["status"])
        self.assertEqual("old\n", rollback_content)
        self.assertTrue(deployed["test_result"]["deploy_result"]["rollback"]["ready"])
        self.assertIn("ai_repair.deploy_merged", {row["operation"] for row in audit})


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str) -> dict | list:
    with urllib.request.urlopen(url, timeout=30) as response:
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
    run_git_fixture(repo, ["branch", "-M", "main"])
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


def create_fake_gh(root: Path, pr_url: str, merged: bool = False) -> Path:
    root.mkdir(parents=True)
    view_json = (
        '{"state":"MERGED","mergedAt":"2026-07-06T00:00:00Z","mergeCommit":{"oid":"abc123"},'
        f'"url":"{pr_url}","number":{pr_url.rstrip("/").rsplit("/", 1)[-1]},'
        '"headRefName":"ai-repair-test","baseRefName":"main"}'
    )
    if os.name == "nt":
        script = root / "gh.cmd"
        if merged:
            script.write_text(
                f'@echo off\nif "%1"=="pr" if "%2"=="view" (\n  echo {view_json}\n  exit /B 0\n)\necho {pr_url}\n',
                encoding="utf-8",
            )
        else:
            script.write_text(f"@echo off\necho {pr_url}\n", encoding="utf-8")
    else:
        script = root / "gh"
        if merged:
            script.write_text(
                f'#!/bin/sh\nif [ "$1" = "pr" ] && [ "$2" = "view" ]; then\n  echo \'{view_json}\'\n  exit 0\nfi\necho {pr_url}\n',
                encoding="utf-8",
            )
        else:
            script.write_text(f"#!/bin/sh\necho {pr_url}\n", encoding="utf-8")
        script.chmod(0o755)
    return root


def merge_branch_to_remote_main(remote: Path, branch_name: str, clone_dir: Path) -> None:
    run_git_fixture(clone_dir.parent, ["clone", str(remote), str(clone_dir)])
    run_git_fixture(clone_dir, ["checkout", "main"])
    run_git_fixture(clone_dir, ["fetch", "origin", branch_name])
    run_git_fixture(clone_dir, ["merge", "--ff-only", f"origin/{branch_name}"])
    run_git_fixture(clone_dir, ["push", "origin", "main"])


@contextmanager
def ok_http_server():
    with status_http_server(200) as url:
        yield url


@contextmanager
def status_http_server(status_code: int):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status_code)
            self.end_headers()
            self.wfile.write(f"status {status_code}".encode("utf-8"))

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/health"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
