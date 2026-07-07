from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any

from ops_agent.events import CheckResult
from ops_agent.monitors.json_api_monitor import get_path


SENSITIVE_KEY_PARTS = ("password", "passwd", "secret", "token", "authorization", "cookie", "key")
DEFAULT_MAX_RESPONSE_BYTES = 65536


@dataclass
class FlowState:
    variables: dict[str, Any] = field(default_factory=dict)
    cookie_jar: CookieJar = field(default_factory=CookieJar)

    @property
    def opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))


@dataclass
class StepOutcome:
    ok: bool
    status: str
    summary: str
    details: dict[str, Any]
    body_text: str = ""
    parsed_json: Any = None
    headers: dict[str, str] = field(default_factory=dict)


def run_business_flow_checks(checks: list[dict[str, Any]]) -> list[CheckResult]:
    return [run_business_flow_check(check) for check in checks]


def run_business_flow_check(check: dict[str, Any]) -> CheckResult:
    name = str(check.get("name") or "Business flow")
    steps = [step for step in check.get("steps", []) if isinstance(step, dict)]
    if not steps:
        return CheckResult(
            source="business_flow",
            name=name,
            status="critical",
            summary="Business flow has no executable steps",
            details={"step_count": 0, **alert_policy_details(check)},
        )

    state = FlowState(variables=initial_variables(check))
    step_results: list[dict[str, Any]] = []
    started = time.perf_counter()

    for index, step in enumerate(steps, start=1):
        outcome = run_flow_step(step, check, state, index)
        step_results.append(public_step_details(outcome.details))
        if not outcome.ok:
            return CheckResult(
                source="business_flow",
                name=name,
                status=step_failure_status(step, check),
                summary=f"Step {index} {step_name(step, index)} failed: {outcome.summary}",
                details={
                    "step_count": len(steps),
                    "failed_step": public_step_details(outcome.details),
                    "steps": step_results,
                    "total_latency_ms": int((time.perf_counter() - started) * 1000),
                    **alert_policy_details(check),
                },
            )
        extract_variables(step, state, outcome)

    total_latency_ms = int((time.perf_counter() - started) * 1000)
    max_latency_ms = int(check.get("max_total_latency_ms", 0) or 0)
    if max_latency_ms > 0 and total_latency_ms > max_latency_ms:
        return CheckResult(
            source="business_flow",
            name=name,
            status="warning",
            summary=f"Business flow slow: {total_latency_ms} ms",
            details={
                "step_count": len(steps),
                "steps": step_results,
                "total_latency_ms": total_latency_ms,
                "max_total_latency_ms": max_latency_ms,
                **alert_policy_details(check),
            },
        )

    return CheckResult(
        source="business_flow",
        name=name,
        status="ok",
        summary=f"Business flow OK in {total_latency_ms} ms",
        details={
            "step_count": len(steps),
            "steps": step_results,
            "total_latency_ms": total_latency_ms,
            **alert_policy_details(check),
        },
    )


def run_flow_step(step: dict[str, Any], check: dict[str, Any], state: FlowState, index: int) -> StepOutcome:
    timeout = float(step.get("timeout_seconds", check.get("timeout_seconds", 15)))
    max_response_bytes = int(step.get("max_response_bytes", check.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)))
    headers = build_headers(check, step, state)
    method = str(step.get("method") or default_method(step)).upper()
    url = interpolate(str(step.get("url", "")), state.variables)
    body = build_request_body(step, state, headers)
    request = urllib.request.Request(url=url, data=body, method=method, headers=headers)
    start = time.perf_counter()

    try:
        with state.opener.open(request, timeout=timeout) as response:
            response_body = response.read(max_response_bytes)
            status_code = int(response.status)
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        response_body = exc.read(max_response_bytes)
        status_code = int(exc.code)
        response_headers = dict(exc.headers.items())
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return StepOutcome(
            ok=False,
            status="critical",
            summary=f"Request failed for {url}: {exc}",
            details=base_step_details(step, index, url, latency_ms, error=repr(exc)),
        )

    latency_ms = int((time.perf_counter() - start) * 1000)
    text = response_body.decode("utf-8", errors="replace")
    parsed = parse_json_if_possible(text)
    details = base_step_details(
        step,
        index,
        url,
        latency_ms,
        status_code=status_code,
        sample=redact_response_sample(text),
    )
    details["expected_statuses"] = sorted(expected_statuses(step, check))

    validation_error = validate_step_response(step, check, status_code, text, parsed)
    max_latency_ms = int(step.get("max_latency_ms", check.get("max_latency_ms", 0)) or 0)
    if validation_error:
        return StepOutcome(
            ok=False,
            status=step_failure_status(step, check),
            summary=validation_error,
            details={**details, "validation_error": validation_error},
            body_text=text,
            parsed_json=parsed,
            headers=response_headers,
        )
    if max_latency_ms > 0 and latency_ms > max_latency_ms:
        return StepOutcome(
            ok=False,
            status="warning",
            summary=f"Slow step response: {latency_ms} ms",
            details={**details, "max_latency_ms": max_latency_ms},
            body_text=text,
            parsed_json=parsed,
            headers=response_headers,
        )

    return StepOutcome(
        ok=True,
        status="ok",
        summary=f"HTTP {status_code} in {latency_ms} ms",
        details=details,
        body_text=text,
        parsed_json=parsed,
        headers=response_headers,
    )


def build_headers(check: dict[str, Any], step: dict[str, Any], state: FlowState) -> dict[str, str]:
    headers = {"User-Agent": "ops-agent/0.1"}
    headers.update(interpolate_mapping(check.get("headers", {}), state.variables))
    headers.update(interpolate_mapping(step.get("headers", {}), state.variables))
    return {str(key): str(value) for key, value in headers.items()}


def build_request_body(step: dict[str, Any], state: FlowState, headers: dict[str, str]) -> bytes | None:
    if "json" in step:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(interpolate_value(step.get("json", {}), state.variables), ensure_ascii=False).encode("utf-8")
    if "form" in step:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        form = interpolate_value(step.get("form", {}), state.variables)
        return urllib.parse.urlencode({str(key): str(value) for key, value in safe_dict(form).items()}).encode("utf-8")
    if "body" in step:
        body = interpolate(str(step.get("body", "")), state.variables)
        return body.encode("utf-8")
    return None


def validate_step_response(
    step: dict[str, Any],
    check: dict[str, Any],
    status_code: int,
    text: str,
    parsed_json: Any,
) -> str:
    statuses = expected_statuses(step, check)
    if status_code not in statuses:
        return f"Unexpected HTTP {status_code}, expected one of {sorted(statuses)}"

    for required in clean_string_list(step.get("required_texts")):
        if required not in text:
            return f"Missing required response text: {required}"

    lower_text = text.lower()
    for forbidden in clean_string_list(step.get("forbidden_texts")):
        if forbidden.lower() in lower_text:
            return f"Response contains forbidden text: {forbidden}"

    required_paths = clean_string_list(step.get("required_json_paths", step.get("required_paths", [])))
    if required_paths:
        if parsed_json is None:
            return "Response is not valid JSON"
        for path in required_paths:
            value = get_path(parsed_json, path)
            if value is None:
                return f"Missing required JSON path: {path}"
            if step.get("require_non_empty", True) and empty_value(value):
                return f"Required JSON path is empty: {path}"

    bad_phrase = find_bad_phrase(text, step.get("bad_phrases", check.get("bad_phrases", [])))
    if bad_phrase:
        return f"Response contains suspicious phrase: {bad_phrase}"

    min_body_bytes = int(step.get("min_body_bytes", 0) or 0)
    if min_body_bytes > 0 and len(text.encode("utf-8")) < min_body_bytes:
        return f"Response body too small: {len(text.encode('utf-8'))} bytes, expected at least {min_body_bytes}"

    return ""


def extract_variables(step: dict[str, Any], state: FlowState, outcome: StepOutcome) -> None:
    extract = step.get("extract", {})
    if not isinstance(extract, dict):
        return
    for variable_name, spec in extract.items():
        name = str(variable_name).strip()
        if not name:
            continue
        value = extract_value(spec, outcome, state)
        if value is not None:
            state.variables[name] = value


def extract_value(spec: Any, outcome: StepOutcome, state: FlowState) -> Any:
    if isinstance(spec, str):
        if spec.startswith("json:"):
            return get_path(outcome.parsed_json, spec.removeprefix("json:"))
        if spec.startswith("header:"):
            return header_value(outcome.headers, spec.removeprefix("header:"))
        if spec.startswith("cookie:"):
            return cookie_value(state.cookie_jar, spec.removeprefix("cookie:"))
        if spec.startswith("regex:"):
            return regex_value(outcome.body_text, spec.removeprefix("regex:"))
        return get_path(outcome.parsed_json, spec)

    config = safe_dict(spec)
    source = str(config.get("from", "json")).strip().lower()
    if source == "json":
        return get_path(outcome.parsed_json, str(config.get("path", "")))
    if source == "header":
        return header_value(outcome.headers, str(config.get("name", "")))
    if source == "cookie":
        return cookie_value(state.cookie_jar, str(config.get("name", "")))
    if source == "regex":
        return regex_value(outcome.body_text, str(config.get("pattern", "")), int(config.get("group", 1) or 1))
    if source == "literal":
        return config.get("value")
    return None


def initial_variables(check: dict[str, Any]) -> dict[str, Any]:
    variables = safe_dict(check.get("variables"))
    return {str(key): value for key, value in variables.items()}


def interpolate_mapping(value: Any, variables: dict[str, Any]) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(interpolate_value(item, variables)) for key, item in value.items()}


def interpolate_value(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: interpolate_value(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [interpolate_value(item, variables) for item in value]
    if isinstance(value, str):
        return interpolate(value, variables)
    return value


def interpolate(value: str, variables: dict[str, Any]) -> str:
    dynamic = {
        "uuid": uuid.uuid4().hex,
        "timestamp": str(int(time.time())),
    }

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if key in dynamic:
            return dynamic[key]
        if key in variables:
            return str(variables[key])
        return match.group(0)

    return re.sub(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", replace, value)


def expected_statuses(step: dict[str, Any], check: dict[str, Any]) -> set[int]:
    raw = step.get("expected_statuses", step.get("expected_status", check.get("expected_status", 200)))
    if isinstance(raw, list):
        values = raw
    else:
        values = [raw]
    statuses: set[int] = set()
    for value in values:
        try:
            statuses.add(int(value))
        except (TypeError, ValueError):
            continue
    return statuses or {200}


def default_method(step: dict[str, Any]) -> str:
    if any(key in step for key in ("json", "form", "body")):
        return "POST"
    return "GET"


def step_failure_status(step: dict[str, Any], check: dict[str, Any]) -> str:
    value = str(step.get("failure_status", check.get("failure_status", "critical"))).strip().lower()
    if value in {"warning", "critical"}:
        return value
    return "critical"


def step_name(step: dict[str, Any], index: int) -> str:
    return str(step.get("name") or step.get("id") or f"step-{index}")


def base_step_details(
    step: dict[str, Any],
    index: int,
    url: str,
    latency_ms: int,
    status_code: int | None = None,
    sample: str = "",
    error: str = "",
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "index": index,
        "name": step_name(step, index),
        "method": str(step.get("method") or default_method(step)).upper(),
        "url": redact_url(url),
        "latency_ms": latency_ms,
    }
    if status_code is not None:
        details["status_code"] = status_code
    if sample:
        details["sample"] = sample
    if error:
        details["error"] = error
    return details


def public_step_details(details: dict[str, Any]) -> dict[str, Any]:
    return redact_value(details)


def redact_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    safe_query = [
        (key, "***" if is_sensitive_key(key) else value)
        for key, value in query
    ]
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(safe_query),
            parsed.fragment,
        )
    )


def redact_response_sample(text: str) -> str:
    parsed = parse_json_if_possible(text)
    if parsed is not None:
        try:
            return json.dumps(redact_value(parsed), ensure_ascii=False)[:500]
        except (TypeError, ValueError):
            return "***"
    sample = text[:500]
    sample = re.sub(
        r'(?i)("?(?:access_)?token"?\s*[:=]\s*")([^"]+)(")',
        r"\1***\3",
        sample,
    )
    sample = re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]+)",
        r"\1***",
        sample,
    )
    return sample


def redact_value(value: Any, key_name: str = "") -> Any:
    if isinstance(value, dict):
        return {
            key: ("***" if is_sensitive_key(str(key)) else redact_value(item, str(key)))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item, key_name) for item in value]
    if is_sensitive_key(key_name):
        return "***"
    return value


def is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower()
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def parse_json_if_possible(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def header_value(headers: dict[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def cookie_value(cookie_jar: CookieJar, name: str) -> str | None:
    for cookie in cookie_jar:
        if cookie.name == name:
            return cookie.value
    return None


def regex_value(text: str, pattern: str, group: int = 1) -> str | None:
    if not pattern:
        return None
    match = re.search(pattern, text, flags=re.DOTALL)
    if not match:
        return None
    try:
        return match.group(group)
    except IndexError:
        return None


def find_bad_phrase(text: str, phrases: Any) -> str:
    lower_text = text.lower()
    for phrase in clean_string_list(phrases):
        if phrase.lower() in lower_text:
            return phrase
    return ""


def empty_value(value: Any) -> bool:
    if value == "":
        return True
    if isinstance(value, (list, dict)) and not value:
        return True
    return False


def clean_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def alert_policy_details(check: dict[str, Any]) -> dict[str, Any]:
    value = check.get("alert_after_failures", check.get("consecutive_failures"))
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return {}
    return {"alert_after_failures": parsed} if parsed > 0 else {}
