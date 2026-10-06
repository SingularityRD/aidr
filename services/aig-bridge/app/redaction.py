"""Bounded redaction helpers for AIG request/result boundaries.

The Tencent service may echo model credentials, target headers, prompts and
tool output in result envelopes.  The bridge therefore never forwards a raw
upstream object.  This module is intentionally dependency-free and safe to use
from error paths.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
MAX_DEPTH = 8
MAX_STRING = 16_384
MAX_ITEMS = 200
MAX_OBJECT_KEYS = 128
MAX_PAYLOAD_BYTES = 512_000

_SECRET_KEY = re.compile(
    r"(?:^|[_-])(token|secret|password|passwd|api[_-]?key|authorization|cookie|set-cookie|private[_-]?key|access[_-]?key|refresh[_-]?token|client[_-]?secret)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_QUERY = {
    "token", "key", "api_key", "apikey", "secret", "password", "authorization",
    "sig", "signature", "access_token", "refresh_token", "client_secret",
}
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")


def redact_url(value: str) -> str:
    """Remove credentials and sensitive query values while keeping the host."""

    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            return _redact_string(value)
        # Never preserve URL userinfo in an evidence/result envelope.  The
        # bridge rejects credentials on inbound targets, but upstream tools
        # may still echo a credential-bearing redirect.
        netloc = parsed.netloc
        if parsed.username or parsed.password:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                netloc = f"{host}:{parsed.port}" if parsed.port else host
            except ValueError:
                netloc = host
        query = []
        for name, item in parse_qsl(parsed.query, keep_blank_values=True):
            query.append((name, REDACTED if name.lower() in _SECRET_QUERY else item))
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query), ""))
    except (TypeError, ValueError):
        return REDACTED


def _redact_string(value: str) -> str:
    text = value if len(value) <= MAX_STRING else value[:MAX_STRING] + TRUNCATED
    text = _BEARER.sub(lambda match: f"{match.group(1)} {REDACTED}", text)
    # Common JSON/YAML style secret assignments in model/tool output.
    text = re.sub(
        r"(?i)(\b(?:api[_-]?key|token|secret|password|authorization)\b\s*[:=]\s*)([^\s,;]+)",
        rf"\1{REDACTED}",
        text,
    )
    if "://" in text:
        text = re.sub(r"https?://[^\s<>\"']+", lambda match: redact_url(match.group()), text)
    return text


def redact_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact secrets and bound attacker-controlled output."""

    if depth > MAX_DEPTH:
        return TRUNCATED
    if isinstance(value, str):
        return _redact_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_OBJECT_KEYS:
                output[TRUNCATED] = TRUNCATED
                break
            name = str(key)
            output[name] = REDACTED if _SECRET_KEY.search(name) else redact_value(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple, set)):
        values = list(value)
        output = [redact_value(item, depth=depth + 1) for item in values[:MAX_ITEMS]]
        if len(values) > MAX_ITEMS:
            output.append(TRUNCATED)
        return output
    return _redact_string(str(value))


def bounded_redacted(value: Any, *, max_bytes: int = MAX_PAYLOAD_BYTES) -> Any:
    """Redact a value and enforce a JSON byte budget."""

    result = redact_value(value)
    try:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return REDACTED
    if len(encoded.encode("utf-8")) <= max_bytes:
        return result
    # Keep a useful, deterministic envelope instead of returning an unbounded
    # upstream report.  Typed adapters may still expose their bounded fields.
    return {"truncated": True, "sha256": _sha256(encoded), "value": TRUNCATED}


def _sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_text(value: Any, *, max_length: int = 4_096) -> str:
    """Convert a result field to bounded, redacted text."""

    text = _redact_string(str(value or ""))
    return text[:max_length] if len(text) <= max_length else text[:max_length] + TRUNCATED
