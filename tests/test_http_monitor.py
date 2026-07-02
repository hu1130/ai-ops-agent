import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ops_agent.monitors.http_monitor import run_http_check


def make_handler(routes: dict[str, tuple[int, str]]):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, body = routes.get(self.path, (404, "missing"))
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


class LocalHttpServer:
    def __init__(self, routes: dict[str, tuple[int, str]]):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(routes))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "LocalHttpServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{path}"


class HttpMonitorTest(unittest.TestCase):
    def test_fallback_reachable_can_mark_primary_failure_ok(self) -> None:
        with LocalHttpServer({"/healthz": (404, "not found"), "/login": (200, "login ok")}) as server:
            result = run_http_check(
                {
                    "name": "site health",
                    "url": server.url("/healthz"),
                    "fallback_urls": ["/login"],
                    "fallback_success_status": "ok",
                }
            )

        self.assertEqual(result.status, "ok")
        self.assertIn("fallback reachable", result.summary)
        self.assertEqual(result.details["classification"], "primary_failed_fallback_reachable")
        self.assertEqual(result.details["fallback"]["status_code"], 200)

    def test_unexpected_primary_status_with_reachable_fallback_is_warning_by_default(self) -> None:
        with LocalHttpServer({"/health": (204, ""), "/login": (200, "login ok")}) as server:
            result = run_http_check(
                {
                    "name": "site health",
                    "url": server.url("/health"),
                    "expected_status": 200,
                    "fallback_urls": ["/login"],
                }
            )

        self.assertEqual(result.status, "warning")
        self.assertIn("Primary HTTP 204, expected 200", result.summary)
        self.assertEqual(result.details["fallback_success_status"], "warning")

    def test_primary_failure_stays_critical_when_fallback_is_not_reachable(self) -> None:
        with LocalHttpServer({"/healthz": (404, "not found"), "/login": (500, "server error")}) as server:
            result = run_http_check(
                {
                    "name": "site health",
                    "url": server.url("/healthz"),
                    "fallback_urls": ["/login"],
                    "fallback_expected_statuses": [200],
                    "fallback_success_status": "ok",
                }
            )

        self.assertEqual(result.status, "critical")
        self.assertIn("HTTP 404", result.summary)
        self.assertEqual(result.details["fallback_attempts"][0]["status_code"], 500)
        self.assertFalse(result.details["fallback_attempts"][0]["reachable"])


if __name__ == "__main__":
    unittest.main()
