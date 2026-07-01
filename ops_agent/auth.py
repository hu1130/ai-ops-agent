from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Any

from ops_agent.config import AppConfig


ROLE_ORDER = {"viewer": 10, "operator": 20, "admin": 30}


@dataclass(frozen=True)
class ApiToken:
    name: str
    token: str
    role: str


@dataclass(frozen=True)
class AuthResult:
    authenticated: bool
    role: str = "anonymous"
    token_name: str = ""
    reason: str = ""


def configured_api_tokens(config: AppConfig | None) -> list[ApiToken]:
    tokens: list[ApiToken] = []
    env_token = os.environ.get("OPS_AGENT_API_TOKEN", "").strip()
    if env_token:
        tokens.append(ApiToken(name="env", token=env_token, role="admin"))

    if config is None:
        return tokens

    app = config.app
    legacy_token = str(app.get("api_token") or app.get("dashboard_api_token") or "").strip()
    if legacy_token:
        tokens.append(ApiToken(name="legacy-admin", token=legacy_token, role="admin"))

    configured = app.get("api_tokens", [])
    if isinstance(configured, list):
        tokens.extend(parse_token_list(configured))
    elif isinstance(configured, dict):
        tokens.extend(parse_token_mapping(configured))
    return tokens


def parse_token_list(items: list[Any]) -> list[ApiToken]:
    tokens: list[ApiToken] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        token = str(item.get("token") or "").strip()
        if not token:
            continue
        role = normalize_role(item.get("role", "viewer"))
        name = str(item.get("name") or f"token-{index + 1}").strip() or f"token-{index + 1}"
        tokens.append(ApiToken(name=name, token=token, role=role))
    return tokens


def parse_token_mapping(items: dict[str, Any]) -> list[ApiToken]:
    tokens: list[ApiToken] = []
    for name, value in items.items():
        token_name = str(name).strip()
        if isinstance(value, dict):
            token = str(value.get("token") or "").strip()
            role = normalize_role(value.get("role", "viewer"))
        else:
            token = str(value or "").strip()
            role = "viewer"
        if token:
            tokens.append(ApiToken(name=token_name, token=token, role=role))
    return tokens


def authenticate_token(provided_token: str, tokens: list[ApiToken]) -> AuthResult:
    if not tokens:
        return AuthResult(authenticated=True, role="admin", token_name="auth-disabled")
    if not provided_token:
        return AuthResult(authenticated=False, reason="missing token")
    for token in tokens:
        if hmac.compare_digest(provided_token, token.token):
            return AuthResult(authenticated=True, role=token.role, token_name=token.name)
    return AuthResult(authenticated=False, reason="invalid token")


def has_role(actual: str, required: str) -> bool:
    return ROLE_ORDER.get(actual, 0) >= ROLE_ORDER.get(required, 0)


def normalize_role(value: object) -> str:
    role = str(value or "viewer").strip().lower()
    return role if role in ROLE_ORDER else "viewer"
