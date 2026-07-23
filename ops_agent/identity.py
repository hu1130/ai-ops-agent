from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from time import monotonic
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.storage import Storage


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 310_000
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ROLE_NAMES = {"viewer", "operator", "admin", "owner"}


def identity_settings(config: AppConfig | None) -> dict[str, Any]:
    raw = dict(config.raw.get("identity") or {}) if config else {}
    app = dict(config.app) if config else {}
    return {
        "organization_id": clean_identifier(raw.get("organization_id") or app.get("organization_id") or "default"),
        "organization_name": str(raw.get("organization_name") or app.get("organization_name") or "My company").strip(),
        "session_hours": min(max(safe_int(raw.get("session_hours"), 12), 1), 24 * 30),
        "secure_cookie": bool(raw.get("secure_cookie", False)),
    }


def hash_password(password: str, iterations: int = PASSWORD_ITERATIONS) -> str:
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(
        (
            PASSWORD_SCHEME,
            str(iterations),
            base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, raw_iterations, raw_salt, raw_digest = str(encoded).split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(raw_iterations)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        salt = decode_base64(raw_salt)
        expected = decode_base64(raw_digest)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must contain at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must contain at most {MAX_PASSWORD_LENGTH} characters")
    if password.isspace():
        raise ValueError("password cannot contain only whitespace")


def normalize_email(value: object) -> str:
    email = str(value or "").strip().lower()
    if len(email) > 255 or not EMAIL_PATTERN.match(email):
        raise ValueError("a valid email address is required")
    return email


def normalize_role(value: object, allow_owner: bool = True) -> str:
    role = str(value or "viewer").strip().lower()
    allowed = ROLE_NAMES if allow_owner else ROLE_NAMES - {"owner"}
    if role not in allowed:
        raise ValueError("role must be viewer, operator, admin, or owner")
    return role


def normalize_project_ids(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("project_ids must be a list")
    result = []
    for item in value:
        project_id = str(item or "").strip()
        if not project_id or len(project_id) > 120:
            raise ValueError("project_ids contains an invalid project id")
        if project_id not in result:
            result.append(project_id)
    return result


def create_user(
    storage: Storage,
    organization_id: str,
    email: object,
    password: str,
    display_name: object = "",
    role: object = "viewer",
    project_ids: object = None,
) -> dict:
    normalized_email = normalize_email(email)
    normalized_role = normalize_role(role)
    normalized_projects = normalize_project_ids(project_ids)
    name = str(display_name or normalized_email.split("@", 1)[0]).strip()[:255]
    if storage.find_identity_user(organization_id, normalized_email):
        raise ValueError("a user with this email already exists")
    row = storage.create_identity_user(
        organization_id,
        normalized_email,
        name,
        hash_password(password),
        normalized_role,
        normalized_projects,
    )
    return public_user(row)


def update_user(storage: Storage, user_id: int, body: dict[str, Any], actor_user_id: int | None = None) -> dict:
    current = storage.get_identity_user(user_id)
    if not current:
        raise ValueError(f"user not found: {user_id}")
    role = normalize_role(body["role"]) if "role" in body else None
    enabled = bool(body["enabled"]) if "enabled" in body else None
    if str(current.get("role")) == "owner" and (role not in {None, "owner"} or enabled is False):
        owners = [row for row in storage.list_identity_users(str(current.get("organization_id") or "default")) if row.get("role") == "owner" and bool(row.get("enabled"))]
        if len(owners) <= 1:
            raise ValueError("the last enabled owner cannot be disabled or demoted")
    if actor_user_id == user_id and enabled is False:
        raise ValueError("you cannot disable your own account")
    password_hash = hash_password(str(body["password"])) if body.get("password") is not None else None
    projects = normalize_project_ids(body.get("project_ids")) if "project_ids" in body else None
    display_name = str(body.get("display_name") or "").strip()[:255] if "display_name" in body else None
    updated = storage.update_identity_user(
        user_id,
        display_name=display_name,
        password_hash=password_hash,
        role=role,
        project_ids=projects,
        enabled=enabled,
    )
    if enabled is False or password_hash is not None:
        storage.revoke_user_sessions(user_id)
    return public_user(updated)


def bootstrap_identity(storage: Storage, config: AppConfig | None, body: dict[str, Any]) -> tuple[dict, str]:
    settings = identity_settings(config)
    if storage.identity_user_count() > 0:
        raise ValueError("identity setup has already been completed")
    organization_name = str(body.get("organization_name") or settings["organization_name"]).strip()[:255]
    storage.ensure_organization(settings["organization_id"], organization_name)
    user = create_user(
        storage,
        settings["organization_id"],
        body.get("email"),
        str(body.get("password") or ""),
        body.get("display_name"),
        "owner",
        [],
    )
    token = create_session(storage, user, settings["session_hours"])
    return user, token


def login(storage: Storage, config: AppConfig | None, email: object, password: str) -> tuple[dict, str]:
    settings = identity_settings(config)
    row = storage.find_identity_user(settings["organization_id"], normalize_email(email))
    if not row or not bool(row.get("enabled")) or not verify_password(password, str(row.get("password_hash") or "")):
        raise ValueError("invalid email or password")
    storage.update_identity_user(int(row["id"]), last_login=True)
    user = public_user(storage.get_identity_user(int(row["id"])) or row)
    return user, create_session(storage, user, settings["session_hours"])


def create_session(storage: Storage, user: dict[str, Any], session_hours: int) -> str:
    token = "ops_session_" + secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=session_hours)
    storage.create_auth_session(
        str(user.get("organization_id") or "default"),
        int(user["id"]),
        hash_access_token(token),
        expires_at.isoformat(),
    )
    return token


def create_api_credential(
    storage: Storage,
    organization_id: str,
    body: dict[str, Any],
    created_by: str,
) -> tuple[dict, str]:
    name = str(body.get("name") or "").strip()[:255]
    if not name:
        raise ValueError("credential name is required")
    role = normalize_role(body.get("role") or "viewer", allow_owner=False)
    project_ids = normalize_project_ids(body.get("project_ids"))
    expires_at = normalize_expiry(body.get("expires_at"))
    token = "ops_api_" + secrets.token_urlsafe(32)
    row = storage.create_api_credential(
        organization_id,
        name,
        hash_access_token(token),
        token[:16],
        role,
        project_ids,
        expires_at,
        created_by,
    )
    return public_credential(row), token


def public_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row.get("id") or 0),
        "organization_id": str(row.get("organization_id") or "default"),
        "email": str(row.get("email") or ""),
        "display_name": str(row.get("display_name") or ""),
        "role": str(row.get("role") or "viewer"),
        "project_ids": parse_json_list(row.get("project_ids_json")),
        "enabled": bool(row.get("enabled")),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "last_login_at": row.get("last_login_at"),
    }


def public_credential(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row.get("id") or 0),
        "organization_id": str(row.get("organization_id") or "default"),
        "name": str(row.get("name") or ""),
        "token_prefix": str(row.get("token_prefix") or ""),
        "role": str(row.get("role") or "viewer"),
        "project_ids": parse_json_list(row.get("project_ids_json")),
        "enabled": bool(row.get("enabled")),
        "expires_at": row.get("expires_at"),
        "created_at": row.get("created_at"),
        "created_by": row.get("created_by"),
        "last_used_at": row.get("last_used_at"),
        "revoked_at": row.get("revoked_at"),
    }


def hash_access_token(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def auth_status(storage: Storage, config: AppConfig | None) -> dict[str, Any]:
    settings = identity_settings(config)
    user_count = storage.identity_user_count(settings["organization_id"])
    return {
        "setup_required": user_count == 0,
        "user_count": user_count,
        "organization_id": settings["organization_id"],
        "organization_name": settings["organization_name"],
        "password_min_length": MIN_PASSWORD_LENGTH,
    }


@dataclass
class LoginThrottle:
    max_failures: int = 5
    window_seconds: int = 300
    block_seconds: int = 600
    _records: dict[str, list[float]] = field(default_factory=dict)
    _blocked_until: dict[str, float] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def check(self, key: str) -> None:
        now = monotonic()
        with self._lock:
            if self._blocked_until.get(key, 0) > now:
                raise ValueError("too many login attempts; try again later")

    def failure(self, key: str) -> None:
        now = monotonic()
        with self._lock:
            recent = [value for value in self._records.get(key, []) if now - value <= self.window_seconds]
            recent.append(now)
            self._records[key] = recent
            if len(recent) >= self.max_failures:
                self._blocked_until[key] = now + self.block_seconds
                self._records.pop(key, None)

    def success(self, key: str) -> None:
        with self._lock:
            self._records.pop(key, None)
            self._blocked_until.pop(key, None)


def normalize_expiry(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")
    return parsed.astimezone(timezone.utc).isoformat()


def parse_json_list(value: object) -> list[str]:
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return [str(item) for item in parsed if str(item).strip()] if isinstance(parsed, list) else []


def clean_identifier(value: object) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "default").strip()).strip("-")
    return (cleaned or "default")[:80]


def decode_base64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
