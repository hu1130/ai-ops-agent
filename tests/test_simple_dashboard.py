import unittest

from ops_agent.simple_dashboard import render_simple_page


class SimpleDashboardTest(unittest.TestCase):
    def test_project_actions_keep_candidate_id_in_data_attributes(self) -> None:
        html = render_simple_page(
            {
                "active_problem_count": 0,
                "current_status": "ok",
                "latest_targets": [],
                "ok_rate": 100,
                "open_incident_count": 0,
            },
            {
                "summary": {"detected_projects": 1, "bound_projects": 0, "unbound_projects": 1},
                "candidates": [
                    {
                        "id": "compose--sales-center",
                        "name": "sales-center",
                        "asset_names": ["sales-api-1"],
                        "management_mode": "unbound",
                        "automation_level": "monitor_only",
                    }
                ],
                "projects": [],
            },
            {"items": []},
            [],
        )

        self.assertIn('data-candidate-id="compose--sales-center"', html)
        self.assertIn('data-management-mode="managed"', html)
        self.assertNotIn('onclick="bindProject(', html)

    def test_server_view_keeps_node_actions_in_data_attributes(self) -> None:
        html = render_simple_page(
            {"current_status": "ok", "latest_targets": []},
            {"summary": {}, "candidates": [], "projects": []},
            {"items": []},
            [],
            {
                "summary": {"total": 1, "online": 1, "offline": 0, "disabled": 0},
                "nodes": [
                    {
                        "node_id": "server-1",
                        "name": "Production",
                        "hostname": "prod-1",
                        "status": "online",
                        "heartbeat_age_seconds": 4,
                        "projects": [{"candidate_id": "compose--sales"}],
                        "metrics": {"disk_percent": 42.5},
                    }
                ],
            },
        )

        self.assertIn('data-node-id="server-1"', html)
        self.assertIn('data-node-action="disable"', html)
        self.assertIn("1 台服务器在线", html)


if __name__ == "__main__":
    unittest.main()
