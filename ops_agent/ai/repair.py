from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request

from ops_agent.config import AppConfig
from ops_agent.storage import Storage


SAFE_STATUSES = {"passed", "failed", "skipped", "not_run"}
DEFAULT_TEST_COMMANDS = ["python -m unittest discover -s tests"]
MODEL_PROVIDERS = {"openai", "openai_compatible", "llm"}
DEFAULT_MODEL_ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL_TIMEOUT_SECONDS = 45
DEFAULT_MAX_PROMPT_CHARS = 12000
DEFAULT_MAX_RESPONSE_CHARS = 60000
MAX_DIFF_CHARS = 80000
ALLOWED_DIFF_SUFFIXES = {
    ".cfg",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
ALLOWED_DIFF_FILENAMES = {"Dockerfile", "Makefile", "Procfile"}
SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "authorized_keys",
    "id_ed25519",
    "id_rsa",
}
SENSITIVE_PATH_PARTS = {".git", ".ssh", "secrets", "__pycache__"}


def build_ai_repair_proposal(
    storage: Storage,
    config: AppConfig | None,
    incident_id: int,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError(f"incident not found: {incident_id}")
    diagnoses = storage.latest_incident_diagnoses(incident_id, limit=1)
    diagnosis = diagnoses[0] if diagnoses else {}
    recommendations = storage.latest_incident_recommendations(incident_id)
    actions = storage.latest_action_logs(20, incident_id=incident_id)
    context = proposal_context(incident, diagnosis, recommendations, actions, config, request)
    proposal = model_based_repair(context) if should_use_model(context) else rule_based_repair(context)
    return storage.save_ai_repair_proposal(incident_id, proposal)


def dry_run_ai_repair_proposal(storage: Storage, repair_id: int, actor: str = "operator", note: str = "") -> dict:
    repair = require_ai_repair(storage, repair_id)
    patch = safe_dict(repair.get("patch"))
    result = validate_patch_dry_run(patch)
    next_status = "dry_run_passed" if result["valid"] else "dry_run_failed"
    return storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        dry_run=result,
    )


def record_ai_repair_test_result(
    storage: Storage,
    repair_id: int,
    result: dict[str, Any] | None = None,
    actor: str = "operator",
    note: str = "",
) -> dict:
    repair = require_ai_repair(storage, repair_id)
    payload = normalize_test_result(result or {}, repair)
    next_status = "test_passed" if payload["status"] == "passed" else "test_failed"
    if payload["status"] in {"skipped", "not_run"}:
        next_status = "test_not_run"
    return storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        test_result=payload,
    )


def require_ai_repair(storage: Storage, repair_id: int) -> dict:
    repair = storage.get_ai_repair_proposal(repair_id)
    if not repair:
        raise ValueError(f"AI repair proposal not found: #{repair_id}")
    return repair


def proposal_context(
    incident: dict[str, Any],
    diagnosis: dict[str, Any],
    recommendations: list[dict],
    actions: list[dict],
    config: AppConfig | None,
    request: dict[str, Any] | None,
) -> dict[str, Any]:
    ai_config = safe_dict(config.raw.get("ai") if config else {})
    repair_config = safe_dict(ai_config.get("repair"))
    return {
        "incident": incident,
        "diagnosis": diagnosis,
        "recommendations": recommendations,
        "actions": actions,
        "config": {
            "base_dir": str(config.base_dir) if config else "",
            "repair": repair_config,
            "provider": repair_config.get("provider") or "",
            "model": repair_config.get("model") or "",
        },
        "request": request or {},
    }


def should_use_model(context: dict[str, Any]) -> bool:
    config_context = safe_dict(context.get("config"))
    settings = safe_dict(config_context.get("repair"))
    provider = str(settings.get("provider") or config_context.get("provider") or "rules").strip().lower()
    if provider not in MODEL_PROVIDERS:
        return False
    if "enabled" in settings and not bool(settings.get("enabled")):
        return False
    return True


def model_based_repair(context: dict[str, Any]) -> dict[str, Any]:
    fallback = rule_based_repair(context)
    settings = repair_settings(context)
    prompt = build_model_prompt(context, settings)
    try:
        response_text = configured_model_response(settings, prompt)
        payload = parse_model_response(response_text)
        proposal = normalize_model_repair_payload(payload, context, fallback, prompt, settings)
    except ValueError as exc:
        return model_unavailable_repair(context, fallback, str(exc))
    return proposal


def repair_settings(context: dict[str, Any]) -> dict[str, Any]:
    config_context = safe_dict(context.get("config"))
    raw = safe_dict(config_context.get("repair"))
    provider = str(raw.get("provider") or config_context.get("provider") or "rules").strip().lower()
    return {
        "provider": provider,
        "model": str(raw.get("model") or config_context.get("model") or "gpt-4.1-mini"),
        "endpoint_url": str(raw.get("endpoint_url") or DEFAULT_MODEL_ENDPOINT),
        "api_key": str(raw.get("api_key") or ""),
        "api_key_env": str(raw.get("api_key_env") or "OPS_AGENT_LLM_API_KEY"),
        "timeout_seconds": safe_int(raw.get("timeout_seconds"), DEFAULT_MODEL_TIMEOUT_SECONDS),
        "max_prompt_chars": safe_int(raw.get("max_prompt_chars"), DEFAULT_MAX_PROMPT_CHARS),
        "max_response_chars": safe_int(raw.get("max_response_chars"), DEFAULT_MAX_RESPONSE_CHARS),
        "mock_response": raw.get("mock_response"),
    }


def build_model_prompt(context: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    incident = public_incident_context(safe_dict(context.get("incident")))
    diagnosis = safe_dict(context.get("diagnosis"))
    recommendations = [
        public_recommendation_context(item)
        for item in safe_list(context.get("recommendations"))[:10]
    ]
    actions = [
        public_action_context(item)
        for item in safe_list(context.get("actions"))[:10]
    ]
    user_payload = {
        "objective": "Generate a minimal repair proposal for this incident.",
        "incident": incident,
        "diagnosis": diagnosis,
        "recommendations": recommendations,
        "actions": actions,
        "output_schema": {
            "title": "short title",
            "summary": "short summary",
            "risk": "low|medium|high|critical",
            "root_cause": "probable root cause",
            "repair_plan": ["ordered repair steps"],
            "patch": {
                "schema_version": 1,
                "patch_type": "unified_diff|config_review|manual_code_review",
                "apply_mode": "proposal_only",
                "diff": "optional unified diff",
                "files": [{"path": "relative/path.py", "change_type": "modify|add|review", "reason": "why"}],
            },
            "test_plan": {"commands": ["python -m unittest discover -s tests"]},
        },
        "constraints": [
            "Return only a JSON object.",
            "Do not include secrets, credentials, private keys, tokens, or environment variable values.",
            "Use proposal_only apply mode. Do not ask to directly mutate production.",
            "Generate the smallest safe patch. Prefer diagnostics if evidence is insufficient.",
            "Use relative paths only. Do not modify .env, .ssh, .git, secrets, or private key files.",
        ],
    }
    user_text = json.dumps(user_payload, ensure_ascii=False, sort_keys=True)
    max_prompt_chars = safe_int(settings.get("max_prompt_chars"), DEFAULT_MAX_PROMPT_CHARS)
    if len(user_text) > max_prompt_chars:
        user_text = user_text[:max_prompt_chars] + "\n...[truncated]"
    return {
        "system": (
            "You are an AI operations repair assistant. Produce safe, reviewable repair proposals. "
            "Never claim that a patch was applied. Never include secrets."
        ),
        "user": user_text,
    }


def configured_model_response(settings: dict[str, Any], prompt: dict[str, Any]) -> str:
    mock_response = settings.get("mock_response")
    if isinstance(mock_response, dict):
        return json.dumps(mock_response, ensure_ascii=False)
    if isinstance(mock_response, str) and mock_response.strip():
        return mock_response
    api_key = model_api_key(settings)
    if not api_key:
        raise ValueError(
            f"model API key is not configured; set {settings.get('api_key_env') or 'OPS_AGENT_LLM_API_KEY'}"
        )
    return call_openai_compatible_model(settings, prompt, api_key)


def call_openai_compatible_model(settings: dict[str, Any], prompt: dict[str, Any], api_key: str) -> str:
    body = {
        "model": str(settings.get("model") or "gpt-4.1-mini"),
        "messages": [
            {"role": "system", "content": str(prompt.get("system") or "")},
            {"role": "user", "content": str(prompt.get("user") or "")},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        str(settings.get("endpoint_url") or DEFAULT_MODEL_ENDPOINT),
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    timeout = safe_int(settings.get("timeout_seconds"), DEFAULT_MODEL_TIMEOUT_SECONDS)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise ValueError(f"model request failed: {exc}") from exc
    if len(raw) > safe_int(settings.get("max_response_chars"), DEFAULT_MAX_RESPONSE_CHARS):
        raise ValueError("model response exceeded max_response_chars")
    parsed = parse_json_object(raw)
    choices = safe_list(parsed.get("choices"))
    first = safe_dict(choices[0]) if choices else {}
    message = safe_dict(first.get("message"))
    content = str(message.get("content") or "")
    if not content.strip():
        raise ValueError("model response did not include message content")
    return content


def model_api_key(settings: dict[str, Any]) -> str:
    direct = str(settings.get("api_key") or "").strip()
    if direct:
        return direct
    env_name = str(settings.get("api_key_env") or "OPS_AGENT_LLM_API_KEY").strip()
    return os.environ.get(env_name, "").strip() if env_name else ""


def parse_model_response(response_text: str) -> dict[str, Any]:
    text = response_text.strip()
    parsed = parse_json_object(text)
    if parsed:
        return parsed
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        parsed = parse_json_object(text[start : end + 1])
    if not parsed:
        raise ValueError("model response is not valid JSON")
    return parsed


def normalize_model_repair_payload(
    payload: dict[str, Any],
    context: dict[str, Any],
    fallback: dict[str, Any],
    prompt: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    patch = safe_dict(payload.get("patch")) or safe_dict(fallback.get("patch"))
    patch["schema_version"] = safe_int(patch.get("schema_version"), 1)
    patch["apply_mode"] = "proposal_only"
    if "patch_type" not in patch:
        patch["patch_type"] = "unified_diff" if str(patch.get("diff") or "").strip() else "manual_code_review"
    validation = validate_patch_dry_run(patch)
    repair_plan = safe_list(payload.get("repair_plan")) or safe_list(safe_dict(fallback.get("proposal")).get("repair_plan"))
    limitations = [
        "No production code is changed by this proposal.",
        "Generated patches require dry-run validation, tests, and approval before use.",
    ]
    if not validation["valid"]:
        limitations.append("Generated patch failed safety validation and must be revised.")
    return {
        "title": str(payload.get("title") or fallback.get("title") or "AI repair proposal"),
        "summary": str(payload.get("summary") or fallback.get("summary") or ""),
        "risk": normalize_risk(payload.get("risk") or fallback.get("risk")),
        "root_cause": str(payload.get("root_cause") or fallback.get("root_cause") or ""),
        "model_provider": str(settings.get("provider") or "openai_compatible"),
        "model_name": str(settings.get("model") or ""),
        "prompt": {
            "mode": "model_repair_proposal",
            "provider": str(settings.get("provider") or ""),
            "model": str(settings.get("model") or ""),
            "system": prompt.get("system"),
            "user": prompt.get("user"),
            "validation": validation,
            "requested_by": safe_dict(context.get("request")).get("actor") or "",
        },
        "proposal": {
            "root_cause": str(payload.get("root_cause") or fallback.get("root_cause") or ""),
            "repair_plan": [str(item) for item in repair_plan],
            "review_required": True,
            "limitations": limitations,
        },
        "patch": patch,
        "test_plan": normalize_test_plan(payload.get("test_plan") or fallback.get("test_plan")),
    }


def model_unavailable_repair(context: dict[str, Any], fallback: dict[str, Any], reason: str) -> dict[str, Any]:
    config_context = safe_dict(context.get("config"))
    settings = safe_dict(config_context.get("repair"))
    proposal = safe_dict(fallback.get("proposal"))
    limitations = safe_list(proposal.get("limitations"))
    limitations.append(f"Model repair generation unavailable: {reason}")
    fallback["model_provider"] = str(settings.get("provider") or "openai_compatible")
    fallback["model_name"] = str(settings.get("model") or "")
    fallback["summary"] = f"{fallback.get('summary', '')} Model generation was skipped; rules fallback was used.".strip()
    fallback["prompt"] = {
        **safe_dict(fallback.get("prompt")),
        "mode": "rules_fallback_after_model_unavailable",
        "model_unavailable_reason": reason,
    }
    fallback["proposal"] = {**proposal, "limitations": limitations}
    return fallback


def rule_based_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    diagnosis = safe_dict(context.get("diagnosis"))
    summary = str(incident.get("last_summary") or incident.get("title") or "")
    category = str(
        diagnosis.get("top_category")
        or incident.get("classification_category")
        or ""
    )
    if is_healthcheck_config_issue(summary, category):
        return healthcheck_config_repair(context)
    if category in {"unknown", "unclassified", ""}:
        return classifier_repair(context)
    return generic_repair(context)


def healthcheck_config_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    url = extract_url(str(incident.get("last_summary") or ""))
    return base_repair(
        context,
        title=f"Review health check endpoint for incident #{incident.get('id')}",
        summary=(
            "The incident looks like a monitor or health-check route mismatch. "
            "Generate a configuration patch proposal before changing production code."
        ),
        risk="low",
        root_cause="Health endpoint returned 404 while the primary site may still be reachable.",
        repair_plan=[
            "Confirm the service's real health endpoint from the deployed application or reverse proxy.",
            "Update the monitor target to a real health route or add a lightweight health endpoint.",
            "Run API/dashboard tests before deployment.",
        ],
        patch={
            "schema_version": 1,
            "patch_type": "config_or_route_review",
            "apply_mode": "proposal_only",
            "operations": [
                {
                    "op": "review_monitor_target",
                    "path": ["http_checks"],
                    "match": {"url": url, "status_code": 404},
                    "recommended_change": "Replace missing /healthz monitor path with a valid health endpoint or add the route in application code.",
                }
            ],
            "files": [
                {
                    "path": "config.json",
                    "change_type": "review",
                    "reason": "Monitor URL may point to a missing route.",
                }
            ],
        },
        test_plan=DEFAULT_TEST_COMMANDS,
    )


def classifier_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    return base_repair(
        context,
        title=f"Improve classification rule for incident #{incident.get('id')}",
        summary="The incident lacks a confident category; propose a classifier/playbook tuning task.",
        risk="medium",
        root_cause="Classifier confidence is missing or too low for safe automated repair.",
        repair_plan=[
            "Collect examples from the incident and related events.",
            "Add a draft classifier rule with positive and negative evidence.",
            "Keep the rule disabled until reviewed.",
        ],
        patch={
            "schema_version": 1,
            "patch_type": "classifier_review",
            "apply_mode": "proposal_only",
            "operations": [
                {
                    "op": "draft_classifier_rule",
                    "path": ["classification_rules"],
                    "recommended_change": "Add a disabled classifier rule after owner review.",
                }
            ],
            "files": [
                {
                    "path": "config.json",
                    "change_type": "review",
                    "reason": "Classifier rules live in configuration.",
                }
            ],
        },
        test_plan=DEFAULT_TEST_COMMANDS,
    )


def generic_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    category = str(incident.get("classification_category") or "general")
    return base_repair(
        context,
        title=f"AI repair draft for incident #{incident.get('id')}",
        summary="Create a repair proposal from incident context. Human review is required before patch application.",
        risk="medium",
        root_cause=f"Incident category: {category}. More evidence is required before code changes.",
        repair_plan=[
            "Review diagnosis, failed actions, and recent deployment changes.",
            "Identify the smallest code or configuration change.",
            "Apply only in a temporary branch or sandbox, then run tests.",
        ],
        patch={
            "schema_version": 1,
            "patch_type": "manual_code_review",
            "apply_mode": "proposal_only",
            "operations": [
                {
                    "op": "manual_patch_required",
                    "path": [],
                    "recommended_change": "Generate a concrete diff after model provider is configured.",
                }
            ],
            "files": [],
        },
        test_plan=DEFAULT_TEST_COMMANDS,
    )


def base_repair(
    context: dict[str, Any],
    title: str,
    summary: str,
    risk: str,
    root_cause: str,
    repair_plan: list[str],
    patch: dict[str, Any],
    test_plan: list[str],
) -> dict[str, Any]:
    request = safe_dict(context.get("request"))
    config_context = safe_dict(context.get("config"))
    return {
        "title": title,
        "summary": summary,
        "risk": risk,
        "root_cause": root_cause,
        "model_provider": str(config_context.get("provider") or "rules"),
        "model_name": str(config_context.get("model") or "rule-based-repair-v1"),
        "prompt": {
            "mode": "rules_until_model_configured",
            "requested_by": request.get("actor") or "",
            "incident": safe_dict(context.get("incident")),
            "diagnosis": safe_dict(context.get("diagnosis")),
            "recommendation_count": len(safe_list(context.get("recommendations"))),
            "action_count": len(safe_list(context.get("actions"))),
        },
        "proposal": {
            "root_cause": root_cause,
            "repair_plan": repair_plan,
            "review_required": True,
            "limitations": [
                "No production code is changed by this proposal.",
                "A configured model provider is required for concrete source-code diffs.",
            ],
        },
        "patch": patch,
        "test_plan": {
            "commands": test_plan,
            "requires_sandbox": True,
            "run_before_merge": True,
        },
    }


def validate_patch_dry_run(patch: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    operations = safe_list(patch.get("operations"))
    files = safe_list(patch.get("files"))
    diff = str(patch.get("diff") or "")
    apply_mode = str(patch.get("apply_mode") or "proposal_only")
    if apply_mode != "proposal_only":
        errors.append("patch apply_mode must be proposal_only")
    if len(diff) > MAX_DIFF_CHARS:
        errors.append(f"diff is too large: {len(diff)} chars")
    if not operations and not files and not diff.strip():
        errors.append("patch has no operations, files, or diff")
    for file_item in files:
        file_payload = safe_dict(file_item)
        path = str(file_payload.get("path") or "")
        if not is_safe_patch_path(path):
            errors.append(f"unsafe file path: {path}")
    for diff_path in diff_paths(diff):
        if not is_safe_patch_path(diff_path):
            errors.append(f"unsafe diff path: {diff_path}")
    if not diff.strip():
        warnings.append("no unified diff was generated; proposal remains review-only")
    checked_files = sorted(
        {
            str(safe_dict(item).get("path") or "")
            for item in files
            if str(safe_dict(item).get("path") or "")
        }
        | set(diff_paths(diff))
    )
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "checked_files": checked_files,
        "operation_count": len(operations),
        "diff_path_count": len(diff_paths(diff)),
        "mutates_files": bool(diff.strip()),
    }


def normalize_test_result(result: dict[str, Any], repair: dict[str, Any]) -> dict[str, Any]:
    status = str(result.get("status") or "").strip().lower()
    if status not in SAFE_STATUSES:
        status = "not_run"
    commands = safe_list(result.get("commands"))
    if not commands:
        commands = safe_list(safe_dict(repair.get("test_plan")).get("commands"))
    return {
        "status": status,
        "commands": [str(item) for item in commands],
        "output": str(result.get("output") or ""),
        "error": str(result.get("error") or ""),
        "note": str(result.get("note") or "test execution is external until sandbox runner is configured"),
    }


def normalize_test_plan(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        commands = [str(item) for item in value if str(item).strip()]
    else:
        payload = safe_dict(value)
        commands = [str(item) for item in safe_list(payload.get("commands")) if str(item).strip()]
    if not commands:
        commands = DEFAULT_TEST_COMMANDS
    return {
        "commands": commands,
        "requires_sandbox": True,
        "run_before_merge": True,
    }


def normalize_risk(value: Any) -> str:
    risk = str(value or "medium").strip().lower()
    return risk if risk in {"low", "medium", "high", "critical"} else "medium"


def public_incident_context(incident: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "id",
        "severity",
        "title",
        "last_summary",
        "classification_category",
        "classification_confidence",
        "classification_summary",
        "occurrence_count",
        "status",
        "environment",
        "run_type",
    ]
    return {key: redact_sensitive_text(incident.get(key)) for key in keys if key in incident}


def public_recommendation_context(item: dict[str, Any]) -> dict[str, Any]:
    keys = ["id", "category", "action_type", "title", "reason", "risk", "status", "source"]
    return {key: redact_sensitive_text(item.get(key)) for key in keys if key in item}


def public_action_context(item: dict[str, Any]) -> dict[str, Any]:
    keys = ["id", "action_type", "title", "risk", "status", "reason", "output", "error"]
    payload = {key: redact_sensitive_text(item.get(key)) for key in keys if key in item}
    if "params_json" in item:
        payload["params_json"] = redact_sensitive_text(item.get("params_json"))
    return payload


def redact_sensitive_text(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    lowered = text.lower()
    if any(marker in lowered for marker in ("api_key", "apikey", "token", "password", "secret")):
        return "[redacted]"
    return text


def is_healthcheck_config_issue(summary: str, category: str) -> bool:
    lowered = summary.lower()
    return (
        category in {"route_or_healthcheck_config_mismatch", "probe_config_issue"}
        or ("healthz" in lowered and "404" in lowered)
        or ("health" in lowered and "404" in lowered)
    )


def extract_url(text: str) -> str:
    for token in text.split():
        if token.startswith("http://") or token.startswith("https://"):
            return token.strip(".,;)")
    return ""


def diff_paths(diff: str) -> list[str]:
    paths: list[str] = []
    for line in diff.splitlines():
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            path = line[6:].strip()
            if path and path != "/dev/null":
                paths.append(path)
        elif line.startswith("diff --git "):
            parts = line.split()
            for part in parts[2:4]:
                if part.startswith("a/") or part.startswith("b/"):
                    paths.append(part[2:])
        elif line.startswith("+++ ") or line.startswith("--- "):
            path = line[4:].strip()
            if path.startswith("a/") or path.startswith("b/"):
                paths.append(path[2:])
    return paths


def is_safe_patch_path(value: str) -> bool:
    if not is_safe_relative_path(value):
        return False
    path = Path(value)
    parts = {part.lower() for part in path.parts}
    if parts & SENSITIVE_PATH_PARTS:
        return False
    name = path.name.lower()
    if name in SENSITIVE_FILENAMES:
        return False
    if path.name in ALLOWED_DIFF_FILENAMES:
        return True
    suffix = path.suffix.lower()
    return suffix in ALLOWED_DIFF_SUFFIXES


def is_safe_relative_path(value: str) -> bool:
    if not value:
        return False
    path = Path(value)
    if path.is_absolute():
        return False
    return ".." not in path.parts


def parse_json_object(value: str) -> dict:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def safe_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def safe_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
