import unittest
from email.message import EmailMessage

from ops_agent.alerts.notifier import sanitize_header_value


class NotifierTest(unittest.TestCase):
    def test_sanitize_header_value_removes_line_breaks_and_keeps_unicode_subject_valid(self) -> None:
        subject = sanitize_header_value("[升级] Ops Agent incident #28\r\nrequires attention")
        message = EmailMessage()
        message["Subject"] = subject

        self.assertEqual("[升级] Ops Agent incident #28 requires attention", subject)
        self.assertNotIn("\n", message["Subject"])


if __name__ == "__main__":
    unittest.main()
