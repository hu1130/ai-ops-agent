import unittest

from ops_agent.monitors.json_api_monitor import find_bad_phrase, get_path, validate_json_response


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


if __name__ == "__main__":
    unittest.main()
