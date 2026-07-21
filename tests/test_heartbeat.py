import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.heartbeat import send_success_heartbeat


class HeartbeatTest(unittest.TestCase):
    def test_sends_success_heartbeat(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(204)
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            config = AppConfig(
                raw={"heartbeat": {"enabled": True, "url": f"http://{host}:{port}/ping"}},
                base_dir=Path("."),
            )
            result = send_success_heartbeat(config)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual("sent", result["status"])
        self.assertEqual(204, result["status_code"])


if __name__ == "__main__":
    unittest.main()
