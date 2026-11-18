"""Credential and secret redaction.

Python port of ``reconx-go/internal/redact/redact.go``.  The helpers mask
sensitive headers, query/body parameters, Bearer tokens, JWTs and raw HTTP
transcripts before findings, evidence files, reports and notifications are
written.

The module has no third-party dependencies so it can be used from every stage
of the pipeline (including tests) without importing ``requests``.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
REDACTED_JWT = "[REDACTED_JWT]"

# Headers that always carry credentials or session state.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-id",
        "api-key",
    }
)

# Header names containing any of these substrings are treated as sensitive.
SENSITIVE_HEADER_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "passwd",
    "session",
    "cookie",
    "apikey",
    "api_key",
    "credential",
    "private",
    "auth",
)

# Query/body parameter names that always carry secrets.
SENSITIVE_PARAM_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "session",
        "sessionid",
        "session_id",
        "phpsessid",
        "jsessionid",
        "jwt",
        "bearer",
        "private_key",
    }
)

_SENSITIVE_PARAM_SUBSTRINGS = (
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "session",
    "private_key",
)

# Mirrors the expressions in the Go implementation.
_BEARER_RE = re.compile(
    r"\b(Bearer|Token|Basic)\s+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE
)
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_KV_RE = re.compile(
    r"\b(password|passwd|pwd|secret|client_secret|access_token|refresh_token|"
    r"api_key|apikey|token|sessionid|phpsessid)([\"'\s:=]+)([^\s\"'&;,}{]{3,})",
    re.IGNORECASE,
)


def is_sensitive_header(name: str) -> bool:
    """Return ``True`` when *name* carries credentials or session state."""
    lower = str(name or "").strip().lower()
    if not lower:
        return False
    if lower in SENSITIVE_HEADERS:
        return True
    return any(sub in lower for sub in SENSITIVE_HEADER_SUBSTRINGS)


def is_sensitive_param(name: str) -> bool:
    """Return ``True`` when a query or body parameter is sensitive."""
    lower = str(name or "").strip().lower()
    if not lower:
        return False
    if lower in SENSITIVE_PARAM_NAMES:
        return True
    return any(sub in lower for sub in _SENSITIVE_PARAM_SUBSTRINGS)


def text(value: str) -> str:
    """Scrub Bearer tokens, JWTs and sensitive ``key=value`` pairs."""
    if not value:
        return ""
    out = _BEARER_RE.sub(r"\1 " + REDACTED, value)
    out = _JWT_RE.sub(REDACTED_JWT, out)
    out = _KV_RE.sub(r"\1\2" + REDACTED, out)
    return out


def headers(in_headers: dict[str, Any] | None) -> dict[str, str]:
    """Return a copy of *in_headers* with sensitive values masked."""
    if not in_headers:
        return {}
    out: dict[str, str] = {}
    for key, value in in_headers.items():
        name = str(key)
        rendered = "" if value is None else str(value)
        if is_sensitive_header(name):
            if name.lower() in {"authorization", "proxy-authorization"}:
                parts = rendered.split()
                if len(parts) >= 2:
                    out[name] = f"{parts[0]} {REDACTED}"
                    continue
            out[name] = REDACTED
        else:
            out[name] = text(rendered)
    return out


def url(raw_url: str) -> str:
    """Mask sensitive query parameter values in *raw_url*."""
    if not raw_url:
        return raw_url
    try:
        split = urlsplit(raw_url)
    except ValueError:
        return text(raw_url)

    netloc = split.netloc
    # Drop userinfo (user:password@) without disturbing the host/port.
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    query = split.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        redacted: list[tuple[str, str]] = []
        changed = False
        for key, value in pairs:
            if is_sensitive_param(key):
                redacted.append((key, REDACTED))
                changed = True
            else:
                redacted.append((key, value))
        if changed:
            query = urlencode(redacted, doseq=True)

    if "@" not in split.netloc and query == split.query:
        # Nothing to change; avoid normalising the URL.
        return raw_url
    return urlunsplit((split.scheme, netloc, split.path, query, split.fragment))


def samples(in_samples: dict[str, Any] | None) -> dict[str, str]:
    """Mask sensitive parameter sample values."""
    if not in_samples:
        return {}
    out: dict[str, str] = {}
    for key, value in in_samples.items():
        name = str(key)
        if is_sensitive_param(name):
            out[name] = REDACTED
        else:
            out[name] = text("" if value is None else str(value))
    return out


def raw_http(raw: str) -> str:
    """Scrub sensitive header values from a raw HTTP transcript.

    The rest of the request/response is preserved for triage.
    """
    if not raw:
        return raw
    lines = raw.split("\n")
    for index, line in enumerate(lines):
        colon = line.find(":")
        if colon > 0 and is_sensitive_header(line[:colon]):
            lines[index] = line[:colon].rstrip(" \t") + f": {REDACTED}"
            continue
        lines[index] = text(line)
    return "\n".join(lines)


def redact_finding(finding: Any) -> Any:
    """Return a copy of a :class:`core.models.Finding` with secrets masked.

    The finding's fingerprint is intentionally preserved so deduplication
    remains stable between runs.
    """
    if finding is None:
        return None

    request = dict(getattr(finding, "request", None) or {})
    response = dict(getattr(finding, "response", None) or {})

    if "headers" in request:
        request["headers"] = headers(request.get("headers"))
    if request.get("body") is not None:
        request["body"] = text(str(request["body"]))
    if request.get("raw") is not None:
        request["raw"] = raw_http(str(request["raw"]))

    if "headers" in response:
        response["headers"] = headers(response.get("headers"))
    if response.get("body_snippet") is not None:
        response["body_snippet"] = text(str(response["body_snippet"]))
    if response.get("raw") is not None:
        response["raw"] = raw_http(str(response["raw"]))

    return replace(
        finding,
        url=url(str(getattr(finding, "url", "") or "")),
        payload=text(str(getattr(finding, "payload", "") or "")),
        evidence=text(str(getattr(finding, "evidence", "") or "")),
        request=request,
        response=response,
    )
