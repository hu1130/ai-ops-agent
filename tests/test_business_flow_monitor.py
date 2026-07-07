import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ops_agent.ai.classifier import classify_signal
from ops_agent.events import CheckResult
from ops_agent.monitors.business_flow_monitor import run_business_flow_check


class BusinessFlowHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/login":
            self.send_json(404, {"error": "missing"})
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        payload = json.loads(body.decode("utf-8") or "{}")
        if payload.get("username") != "ops" or payload.get("password") != "secret":
            self.send_json(401, {"error": "unauthorized"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", "session=ok; Path=/")
        response = json.dumps({"data": {"token": "abc-token"}}).encode("utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        cookie = self.headers.get("Cookie", "")
        if "session=ok" not in cookie or auth != "Bearer abc-token":
            self.send_json(403, {"error": "forbidden"})
            return
        if self.path == "/projects":
            self.send_json(200, {"data": {"projects": [{"id": "p1"}]}})
            return
        if self.path == "/projects/p1":
            self.send_json(200, {"data": {"id": "p1", "name": "Project Dashboard"}})
            return
        if self.path == "/broken-projects":
            self.send_json(200, {"data": {"projects": []}})
            return
        self.send_json(404, {"error": "missing"})

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class LocalBusinessServer:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), BusinessFlowHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "LocalBusinessServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{path}"


class BusinessFlowMonitorTest(unittest.TestCase):
    def test_authenticated_flow_carries_cookie_and_extracted_token(self) -> None:
        with LocalBusinessServer() as server:
            result = run_business_flow_check(
                {
                    "name": "project flow",
                    "variables": {"username": "ops", "password": "secret"},
                    "steps": [
                        {
                            "name": "login",
                            "url": server.url("/login"),
                            "json": {"username": "{{username}}", "password": "{{password}}"},
                            "required_json_paths": ["data.token"],
                            "extract": {"token": "json:data.token"},
                        },
                        {
                            "name": "project list",
                            "url": server.url("/projects"),
                            "headers": {"Authorization": "Bearer {{token}}"},
                            "required_json_paths": ["data.projects.0.id"],
                            "extract": {"project_id": "json:data.projects.0.id"},
                        },
                        {
                            "name": "project detail",
                            "url": server.url("/projects/{{project_id}}"),
                            "headers": {"Authorization": "Bearer {{token}}"},
                            "required_json_paths": ["data.id"],
                        },
                    ],
                }
            )

        self.assertEqual("ok", result.status)
        self.assertIn("Business flow OK", result.summary)
        self.assertEqual(3, len(result.details["steps"]))
        self.assertNotIn("abc-token", json.dumps(result.details))

    def test_flow_reports_failed_step_when_business_assertion_breaks(self) -> None:
        with LocalBusinessServer() as server:
            result = run_business_flow_check(
                {
                    "name": "project flow",
                    "alert_after_failures": 1,
                    "variables": {"username": "ops", "password": "secret"},
                    "steps": [
                        {
                            "name": "login",
                            "url": server.url("/login"),
                            "json": {"username": "{{username}}", "password": "{{password}}"},
                            "extract": {"token": "json:data.token"},
                        },
                        {
                            "name": "project list",
                            "url": server.url("/broken-projects"),
                            "headers": {"Authorization": "Bearer {{token}}"},
                            "required_json_paths": ["data.projects.0.id"],
                        },
                    ],
                }
            )

        self.assertEqual("critical", result.status)
        self.assertIn("Step 2 project list failed", result.summary)
        self.assertEqual(2, result.details["failed_step"]["index"])
        self.assertEqual(1, result.details["alert_after_failures"])

    def test_business_flow_classification_is_specific(self) -> None:
        classification = classify_signal(
            CheckResult(
                source="business_flow",
                name="project flow",
                status="critical",
                summary="Step 1 login failed: Unexpected HTTP 401, expected one of [200]",
                details={"failed_step": {"index": 1, "name": "login", "url": "https://example.com/login", "status_code": 401}},
            )
        )

        self.assertEqual("business_flow_failure", classification.category)
        self.assertGreaterEqual(classification.confidence, 0.85)


if __name__ == "__main__":
    unittest.main()
