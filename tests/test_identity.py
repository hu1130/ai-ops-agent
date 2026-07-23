import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ops_agent.auth import authenticate_access_token, configured_api_tokens
from ops_agent.ai.repair import build_ai_repair_proposal
from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.events import CheckResult
from ops_agent.identity import create_session, create_user, hash_password, verify_password
from ops_agent.storage import Storage


class IdentityTest(unittest.TestCase):
    def test_password_hash_is_salted_and_verifiable(self) -> None:
        first = hash_password("StrongPassword!123")
        second = hash_password("StrongPassword!123")

        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("StrongPassword!123", first))
        self.assertFalse(verify_password("wrong-password", first))

    def test_session_authentication_preserves_project_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            storage.ensure_organization("acme", "Acme")
            user = create_user(
                storage,
                "acme",
                "viewer@example.com",
                "StrongPassword!123",
                "Viewer",
                "viewer",
                ["project-a"],
            )
            from ops_agent.identity import create_session

            token = create_session(storage, user, 12)
            auth = authenticate_access_token(token, [], storage)
            storage.close()

        self.assertTrue(auth.authenticated)
        self.assertEqual("viewer", auth.role)
        self.assertEqual(("project-a",), auth.project_ids)
        self.assertFalse(auth.all_projects)

    def test_bootstrap_login_user_and_api_credential_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"api_token": "install-admin-token", "api_auth_required_for_reads": True},
                    "identity": {"organization_id": "acme", "organization_name": "Acme"},
                    "projects": [
                        {"id": "project-a", "name": "Project A"},
                        {"id": "project-b", "name": "Project B"},
                    ],
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            base = f"http://{host}:{port}"
            try:
                status = self.request_json(base + "/api/auth/status")
                owner, owner_cookie = self.request_json_with_cookie(
                    base + "/api/auth/bootstrap",
                    {
                        "organization_name": "Acme",
                        "display_name": "Owner",
                        "email": "owner@example.com",
                        "password": "StrongPassword!123",
                    },
                    token="install-admin-token",
                )
                created = self.request_json(
                    base + "/api/users",
                    {
                        "display_name": "Viewer",
                        "email": "viewer@example.com",
                        "password": "AnotherStrong!123",
                        "role": "viewer",
                        "project_ids": ["project-a"],
                    },
                    cookie=owner_cookie,
                )
                _login, viewer_cookie = self.request_json_with_cookie(
                    base + "/api/auth/login",
                    {"email": "viewer@example.com", "password": "AnotherStrong!123"},
                )
                projects = self.request_json(base + "/api/projects", cookie=viewer_cookie)
                credential = self.request_json(
                    base + "/api/api-credentials",
                    {"name": "project-b-reader", "role": "viewer", "project_ids": ["project-b"]},
                    cookie=owner_cookie,
                )
                credential_projects = self.request_json(
                    base + "/api/projects", token=credential["token"]
                )
                forbidden = urllib.request.Request(
                    base + "/api/config/validate",
                    data=b"{}",
                    method="POST",
                    headers={"Content-Type": "application/json", "Cookie": viewer_cookie},
                )
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(forbidden, timeout=5)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertTrue(status["setup_required"])
        self.assertEqual("owner", owner["user"]["role"])
        self.assertEqual("viewer", created["role"])
        self.assertEqual(["project-a"], [row["id"] for row in projects["projects"]])
        self.assertEqual(["project-b"], [row["id"] for row in credential_projects["projects"]])
        self.assertEqual(403, denied.exception.code)

    def test_project_scoped_user_cannot_read_or_run_another_projects_ai_repair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            storage.ensure_organization("acme", "Acme")
            user = create_user(
                storage,
                "acme",
                "operator@example.com",
                "StrongPassword!123",
                "Operator",
                "operator",
                ["project-a"],
            )
            session = create_session(storage, user, 12)
            config = AppConfig(
                raw={
                    "app": {"api_auth_required_for_reads": True},
                    "identity": {"organization_id": "acme"},
                    "ai": {"repair": {"provider": "rules"}},
                    "projects": [
                        {"id": "project-a", "name": "Project A"},
                        {"id": "project-b", "name": "Project B"},
                    ],
                },
                base_dir=Path(tmp),
            )
            incident_a = storage.save_incident(
                "warning",
                "Project A issue",
                "analysis",
                [CheckResult(source="http", name="A", status="warning", summary="A failed", organization_id="acme", project_id="project-a")],
            )
            incident_b = storage.save_incident(
                "warning",
                "Project B issue",
                "analysis",
                [CheckResult(source="http", name="B", status="warning", summary="B failed", organization_id="acme", project_id="project-b")],
            )
            repair_a = build_ai_repair_proposal(storage, config, incident_a)
            repair_b = build_ai_repair_proposal(storage, config, incident_b)
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            base = f"http://{host}:{port}"
            try:
                listed = self.request_json(base + "/api/ai-repairs", token=session)
                queue = self.request_json(base + "/api/ai-repairs/approval-queue", token=session)
                forbidden_get = urllib.request.Request(
                    base + f"/api/ai-repairs/{repair_b['id']}",
                    headers={"Authorization": "Bearer " + session},
                )
                with self.assertRaises(urllib.error.HTTPError) as denied_get:
                    urllib.request.urlopen(forbidden_get, timeout=5)
                forbidden_post = urllib.request.Request(
                    base + f"/api/ai-repairs/{repair_b['id']}/dry-run",
                    data=b"{}",
                    method="POST",
                    headers={"Content-Type": "application/json", "Authorization": "Bearer " + session},
                )
                with self.assertRaises(urllib.error.HTTPError) as denied_post:
                    urllib.request.urlopen(forbidden_post, timeout=5)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual([repair_a["id"]], [row["id"] for row in listed])
        self.assertEqual([repair_a["id"]], [row["id"] for row in queue["items"]])
        self.assertEqual(1, queue["summary"]["total"])
        self.assertEqual(403, denied_get.exception.code)
        self.assertEqual(403, denied_post.exception.code)

    @staticmethod
    def request_json(
        url: str,
        body: dict | None = None,
        *,
        token: str = "",
        cookie: str = "",
    ) -> dict:
        headers = {}
        data = None
        method = "GET"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"
        if token:
            headers["Authorization"] = "Bearer " + token
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    @classmethod
    def request_json_with_cookie(
        cls,
        url: str,
        body: dict,
        *,
        token: str = "",
    ) -> tuple[dict, str]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            cookie = response.headers.get("Set-Cookie", "").split(";", 1)[0]
        return payload, cookie


if __name__ == "__main__":
    unittest.main()
