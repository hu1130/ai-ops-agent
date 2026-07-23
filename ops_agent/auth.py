from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.identity import hash_access_token

if TYPE_CHECKING:
    from ops_agent.storage import Storage


ROLE_ORDER = {"viewer": 10, "operator": 20, "admin": 30, "owner": 40}
API_TOKEN_ROLES = {"viewer", "operator", "admin"}


@dataclass(frozen=True)
class ApiToken:
    name: str
    token: str
    role: str
    project_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthResult:
    authenticated: bool
    role: str = "anonymous"
    token_name: str = ""
    reason: str = ""
    organization_id: str = "default"
    user_id: int | None = None
    email: str = ""
    display_name: str = ""
    project_ids: tuple[str, ...] = ()
    all_projects: bool = True
    token_kind: str = ""


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
        tokens.append(ApiToken(name=name, token=token, role=role, project_ids=parse_project_ids(item.get("project_ids"))))
    return tokens


def parse_token_mapping(items: dict[str, Any]) -> list[ApiToken]:
    tokens: list[ApiToken] = []
    for name, value in items.items():
        token_name = str(name).strip()
        if isinstance(value, dict):
            token = str(value.get("token") or "").strip()
            role = normalize_role(value.get("role", "viewer"))
            project_ids = parse_project_ids(value.get("project_ids"))
        else:
            token = str(value or "").strip()
            role = "viewer"
            project_ids = ()
        if token:
            tokens.append(ApiToken(name=token_name, token=token, role=role, project_ids=project_ids))
    return tokens


def authenticate_token(provided_token: str, tokens: list[ApiToken]) -> AuthResult:
    if not tokens:
        return AuthResult(authenticated=True, role="admin", token_name="auth-disabled")
    if not provided_token:
        return AuthResult(authenticated=False, reason="missing token")
    for token in tokens:
        if hmac.compare_digest(provided_token, token.token):
            return AuthResult(
                authenticated=True,
                role=token.role,
                token_name=token.name,
                project_ids=token.project_ids,
                all_projects=not bool(token.project_ids),
                token_kind="configured",
            )
    return AuthResult(authenticated=False, reason="invalid token")


def authenticate_access_token(
    provided_token: str,
    tokens: list[ApiToken],
    storage: Storage,
) -> AuthResult:
    if provided_token:
        configured = authenticate_token(provided_token, tokens) if tokens else None
        if configured and configured.authenticated:
            return configured
        token_hash = hash_access_token(provided_token)
        session = storage.find_auth_session(token_hash)
        if session:
            if not bool(session.get("user_enabled")):
                return AuthResult(authenticated=False, reason="user is disabled")
            if is_expired(session.get("expires_at")):
                storage.revoke_auth_session(token_hash)
                return AuthResult(authenticated=False, reason="session expired")
            storage.touch_auth_session(int(session["id"]))
            role = normalize_role(session.get("role"))
            project_ids = parse_project_ids_json(session.get("project_ids_json"))
            return AuthResult(
                authenticated=True,
                role=role,
                token_name=str(session.get("email") or f"user-{session.get('user_id')}"),
                organization_id=str(session.get("organization_id") or "default"),
                user_id=int(session.get("user_id") or 0) or None,
                email=str(session.get("email") or ""),
                display_name=str(session.get("display_name") or ""),
                project_ids=project_ids,
                all_projects=role in {"admin", "owner"},
                token_kind="session",
            )
        credential = storage.find_api_credential(token_hash)
        if credential:
            if is_expired(credential.get("expires_at")):
                return AuthResult(authenticated=False, reason="API credential expired")
            storage.touch_api_credential(int(credential["id"]))
            role = normalize_role(credential.get("role"))
            project_ids = parse_project_ids_json(credential.get("project_ids_json"))
            return AuthResult(
                authenticated=True,
                role=role,
                token_name=str(credential.get("name") or f"credential-{credential.get('id')}"),
                organization_id=str(credential.get("organization_id") or "default"),
                project_ids=project_ids,
                all_projects=role in {"admin", "owner"},
                token_kind="api_credential",
            )
        if not tokens and storage.identity_user_count() == 0:
            return AuthResult(authenticated=True, role="admin", token_name="auth-disabled", token_kind="disabled")
        return AuthResult(authenticated=False, reason="invalid token")
    if not tokens and storage.identity_user_count() == 0:
        return AuthResult(authenticated=True, role="admin", token_name="auth-disabled", token_kind="disabled")
    return AuthResult(authenticated=False, reason="missing token")


def has_role(actual: str, required: str) -> bool:
    return ROLE_ORDER.get(actual, 0) >= ROLE_ORDER.get(required, 0)


def normalize_role(value: object) -> str:
    role = str(value or "viewer").strip().lower()
    return role if role in ROLE_ORDER else "viewer"


def parse_project_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)):
        return ()
    return tuple(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))


def parse_project_ids_json(value: object) -> tuple[str, ...]:
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ()
    return parse_project_ids(parsed)


def is_expired(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= datetime.now(timezone.utc)
