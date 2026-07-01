import unittest
from pathlib import Path

from ops_agent.auth import authenticate_token, configured_api_tokens, has_role
from ops_agent.config import AppConfig


class AuthTest(unittest.TestCase):
    def test_legacy_api_token_is_admin(self) -> None:
        config = AppConfig(raw={"app": {"api_token": "legacy-secret"}}, base_dir=Path("."))
        tokens = configured_api_tokens(config)
        result = authenticate_token("legacy-secret", tokens)

        self.assertTrue(result.authenticated)
        self.assertEqual("admin", result.role)
        self.assertTrue(has_role(result.role, "operator"))

    def test_api_tokens_support_roles(self) -> None:
        config = AppConfig(
            raw={
                "app": {
                    "api_tokens": [
                        {"name": "readonly", "token": "viewer-secret", "role": "viewer"},
                        {"name": "ops", "token": "operator-secret", "role": "operator"},
                    ]
                }
            },
            base_dir=Path("."),
        )
        tokens = configured_api_tokens(config)

        viewer = authenticate_token("viewer-secret", tokens)
        operator = authenticate_token("operator-secret", tokens)

        self.assertEqual("viewer", viewer.role)
        self.assertFalse(has_role(viewer.role, "operator"))
        self.assertEqual("operator", operator.role)
        self.assertTrue(has_role(operator.role, "operator"))

    def test_missing_token_is_allowed_when_auth_is_not_configured(self) -> None:
        result = authenticate_token("", [])

        self.assertTrue(result.authenticated)
        self.assertEqual("admin", result.role)


if __name__ == "__main__":
    unittest.main()
