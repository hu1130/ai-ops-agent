import unittest

from ops_agent.monitors.json_api_monitor import (
    alert_policy_details,
    expand_dynamic_values,
    find_bad_phrase,
    get_path,
    validate_json_response,
)


class JsonApiMonitorTest(unittest.TestCase):
    def test_get_path_reads_nested_list_value(self) -> None:
        payload = {"messages": [{"text": "hello"}]}
        self.assertEqual(get_path(payload, "messages.0.text"), "hello")

    def test_validate_json_response_requires_path(self) -> None:
        error = validate_json_response({"messages": []}, {"required_paths": ["messages.0.text"]})
        self.assertIn("Missing required JSON path", error)

    def test_find_bad_phrase(self) -> None:
        phrase = find_bad_phrase({"message": "系统异常，请稍后再试"}, ["系统异常"])
        self.assertEqual(phrase, "系统异常")

    def test_expand_dynamic_values_replaces_uuid(self) -> None:
        payload = expand_dynamic_values({"session_id": "ops-agent-{{uuid}}"})
        self.assertTrue(str(payload["session_id"]).startswith("ops-agent-"))
        self.assertNotIn("{{uuid}}", payload["session_id"])

    def test_alert_policy_details_include_recovery_success_threshold(self) -> None:
        details = alert_policy_details({"alert_after_failures": 2, "recovery_after_successes": 3})
        self.assertEqual(2, details["alert_after_failures"])
        self.assertEqual(3, details["recovery_after_successes"])


if __name__ == "__main__":
    unittest.main()
