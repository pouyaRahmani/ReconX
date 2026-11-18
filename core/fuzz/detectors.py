"""Vulnerability detectors.

Each detector compares a payload response against a clean baseline response and
returns a :class:`~core.models.Finding` only when there is concrete evidence.
The emphasis is on keeping false positives low: reflection must be observable,
SQL errors must match DB signatures, redirects must actually point off-site,
and header findings must change state or be reflected.
"""

from __future__ import annotations

import re
from typing import Callable

from core import redact
from core.fuzz.payloads import parse_header, redirect_hosts, sleep_seconds
from core.models import Finding, FuzzJob, HttpResult, TargetConfig
from core.recon.urls import hostname

# ---------------------------------------------------------------------------
# Static knowledge
# ---------------------------------------------------------------------------

SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "unterminated quoted string",
    "mysql_fetch_array",
    "mysql_fetch_assoc",
    "mysqli_sql_exception",
    "warning: mysql",
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    "sqlite3.operationalerror",
    "sqlite error",
    "microsoft ole db provider for sql server",
    "microsoft sql native client",
    "microsoft odbc sql server driver",
    "ora-00933",
    "ora-01756",
    "ora-00907",
    "oracle error",
    "sqlstate[",
    "sqlstate:",
    "unrecognized token:",
    "sql syntax error",
    "db2 sql error",
    "invalid query",
    "jdbc sqlexception",
    "syntax error at or near",
    "division by zero",
    "conversion failed when converting",
)

CACHE_HEADER_NAMES = (
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "cdn-cache",
    "x-proxy-cache",
    "x-fastly-cache",
    "x-akamai-transformed",
    "age",
    "cache-control",
    "via",
    "x-served-by",
)

BYPASS_HEADER_NAMES = {
    "x-original-url",
    "x-rewrite-url",
    "x-custom-ip-authorization",
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "x-originating-ip",
    "x-remote-addr",
    "x-remote-ip",
    "true-client-ip",
    "forwarded",
}

HTML_TYPES = ("text/html", "application/xhtml", "application/xml", "text/xml")
TEXT_TYPES = ("text/plain", "text/css", "application/javascript", "text/javascript")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snippet(text: str, needle: str, radius: int = 120) -> str:
    if not text:
        return ""
    index = text.find(needle) if needle else -1
    if index < 0 and needle:
        index = text.lower().find(needle.lower())
    if index < 0:
        return text[: radius * 2].replace("\n", " ")
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return text[start:end].replace("\n", " ").strip()


def _request_host(url: str) -> str:
    return hostname(url)


def _location_host(location: str, request_url: str) -> str:
    """Host that a ``Location`` value points to (resolves relative URLs)."""
    from urllib.parse import urljoin

    try:
        joined = urljoin(request_url, location)
    except Exception:
        return ""
    return hostname(joined)


def _finding(
    job: FuzzJob,
    payload: str,
    response: HttpResult,
    *,
    severity: str,
    confidence: str,
    evidence: str,
    param: str = "",
    body_snippet: str | None = None,
) -> Finding:
    finding = Finding(
        vuln=job.vuln,
        url=redact.url(response.url or job.url),
        method=job.method,
        param=param or ",".join(job.params),
        payload=payload,
        status=response.status,
        evidence=redact.text(evidence),
        severity=severity,
        confidence=confidence,
        source="fuzzer",
        request={
            "headers": redact.headers(response.request_headers),
            "body": (
                redact.text(response.request_body)
                if response.request_body is not None
                else None
            ),
        },
        response={
            "status": response.status,
            "length": response.length,
            "content_type": response.content_type,
            "elapsed_ms": response.elapsed_ms,
            "headers": redact.headers(
                {
                    key: value
                    for key, value in response.headers.items()
                    if key in CACHE_HEADER_NAMES or key in {"location", "refresh", "server"}
                }
            ),
            "body_snippet": redact.text(
                body_snippet if body_snippet is not None else response.body[:800]
            ),
        },
    )
    finding.fingerprint = finding.compute_fingerprint()
    return finding


def _is_time_based(payload: str) -> bool:
    return sleep_seconds(payload) > 0


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

def detect_xss(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    if not response.ok or response.status >= 500 or response.status == 0:
        return None
    payload = payload.strip()
    if len(payload) < 3:
        return None

    index = response.body.find(payload)
    if index < 0:
        return None
    if baseline and payload in baseline.body:
        return None

    content_type = response.content_type
    if content_type and any(t in content_type for t in HTML_TYPES):
        confidence = "confirmed"
        severity = "high"
    elif not content_type or any(t in content_type for t in TEXT_TYPES):
        confidence = "candidate"
        severity = "medium"
    else:
        return None

    lowered = payload.lower()
    if any(token in lowered for token in ("<script", "onerror", "onload", "javascript:", "<svg", "<img")):
        severity = "high" if confidence == "confirmed" else "medium"

    evidence = (
        f"payload reflected at byte {index}; "
        f"content-type={content_type or 'unknown'}; len={response.length}"
    )
    return _finding(
        job,
        payload,
        response,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        body_snippet=_snippet(response.body, payload),
    )


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

def _sql_error_match(body: str) -> str:
    lowered = body.lower()
    for signature in SQL_ERROR_SIGNATURES:
        if signature in lowered:
            return signature
    return ""


def detect_sqli(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    if response.status == 0:
        return None

    # Time-based ---------------------------------------------------------
    delay = sleep_seconds(payload)
    if delay > 0:
        baseline_elapsed = baseline.elapsed if baseline else 0.0
        threshold = max(cfg.sleep_threshold, delay * 0.7)
        slow_baseline = baseline is not None and baseline.elapsed >= cfg.sleep_threshold
        if (
            response.ok
            and not slow_baseline
            and response.elapsed >= threshold
            and response.elapsed >= baseline_elapsed + delay * 0.6
        ):
            evidence = (
                f"time-based: response delayed {response.elapsed:.2f}s "
                f"(payload asks {delay:g}s, baseline {baseline_elapsed:.2f}s)"
            )
            return _finding(
                job,
                payload,
                response,
                severity="critical",
                confidence="confirmed",
                evidence=evidence,
                body_snippet=_snippet(response.body, payload),
            )
        return None

    # Error-based --------------------------------------------------------
    if not response.body:
        return None
    signature = _sql_error_match(response.body)
    if not signature:
        return None
    if baseline and signature in baseline.body.lower():
        return None

    evidence = f"database error signature: {signature!r}; status={response.status}"
    return _finding(
        job,
        payload,
        response,
        severity="high",
        confidence="confirmed",
        evidence=evidence,
        body_snippet=_snippet(response.body, signature),
    )


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------

_REFRESH_RE = re.compile(r"http-equiv\s*=\s*[\"']?refresh", re.IGNORECASE)
_JS_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)",
    re.IGNORECASE,
)


def detect_open_redirect(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    intended_hosts = redirect_hosts(payload)
    if not intended_hosts:
        return None
    request_host = _request_host(response.url or job.url)

    location = response.header("location") or response.header("refresh")
    if location:
        location_host = _location_host(location, response.url or job.url)
        literal_match = any(host in location.lower() for host in intended_hosts)
        offsite = bool(location_host) and location_host != request_host
        if literal_match and offsite:
            evidence = (
                f"redirect target {location_host!r} differs from request host "
                f"{request_host!r}; Location={location[:180]}"
            )
            return _finding(
                job,
                payload,
                response,
                severity="medium",
                confidence="confirmed",
                evidence=evidence,
                body_snippet=_snippet(response.body, intended_hosts[0]),
            )

    # Meta-refresh / JavaScript redirects in the body.
    body = response.body
    for host in intended_hosts:
        if host not in body.lower():
            continue
        if _REFRESH_RE.search(body):
            evidence = f"meta-refresh redirect contains {host!r} (status={response.status})"
            return _finding(
                job,
                payload,
                response,
                severity="medium",
                confidence="candidate",
                evidence=evidence,
                body_snippet=_snippet(body, host),
            )
        match = _JS_REDIRECT_RE.search(body)
        if match and host in match.group(1).lower():
            evidence = f"JavaScript redirect contains {host!r} (status={response.status})"
            return _finding(
                job,
                payload,
                response,
                severity="medium",
                confidence="candidate",
                evidence=evidence,
                body_snippet=_snippet(body, host),
            )
        break
    return None


# ---------------------------------------------------------------------------
# Header checks
# ---------------------------------------------------------------------------

def detect_header_reflection(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    parsed = parse_header(payload)
    if not parsed:
        return None
    name, marker = parsed
    if len(marker) < 4:
        return None

    baseline_body = baseline.body if baseline else ""
    body_reflected = marker in response.body and marker not in baseline_body
    header_hits = [
        f"{key}: {value}"
        for key, value in response.headers.items()
        if marker in value
    ]
    baseline_header_hits = [
        f"{key}: {value}"
        for key, value in (baseline.headers if baseline else {}).items()
        if marker in value
    ]
    header_reflected = bool(header_hits) and not baseline_header_hits

    if not body_reflected and not header_reflected:
        return None

    if body_reflected:
        confidence = "confirmed"
        severity = "medium"
        where = "response body"
    else:
        confidence = "candidate"
        severity = "low"
        where = "response header: " + "; ".join(header_hits[:2])

    evidence = f"injected header {name}: {marker!r} reflected in {where}"
    return _finding(
        job,
        payload,
        response,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        param=name,
        body_snippet=_snippet(response.body, marker),
    )


def detect_header_status(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    if not baseline or not baseline.ok or not response.ok:
        return None
    parsed = parse_header(payload)
    if not parsed:
        return None
    name, _ = parsed

    baseline_status = baseline.status
    status = response.status
    bypass_set = {401, 403, 404, 405}

    if baseline_status in bypass_set and status in {200, 201, 202, 204, 301, 302, 307, 308}:
        evidence = (
            f"access-control bypass candidate: {baseline_status} -> {status} "
            f"with header {name}: {parsed[1]!r}"
        )
        return _finding(
            job,
            payload,
            response,
            severity="high",
            confidence="confirmed",
            evidence=evidence,
            param=name,
        )

    if baseline_status >= 400 and status == 200:
        evidence = f"status changed {baseline_status} -> 200 with header {name}: {parsed[1]!r}"
        return _finding(
            job,
            payload,
            response,
            severity="medium",
            confidence="confirmed",
            evidence=evidence,
            param=name,
        )

    # Large body change on a protected path can be an auth-bypass candidate.
    if (
        name.lower() in BYPASS_HEADER_NAMES
        and baseline_status == status
        and baseline.length > 0
        and abs(response.length - baseline.length) / max(1, baseline.length) > 0.5
        and status == 200
    ):
        evidence = (
            f"body length changed {baseline.length} -> {response.length} "
            f"with header {name}: {parsed[1]!r}"
        )
        return _finding(
            job,
            payload,
            response,
            severity="low",
            confidence="candidate",
            evidence=evidence,
            param=name,
        )
    return None


def detect_cache_poison(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    parsed = parse_header(payload)
    if not parsed:
        return None
    name, marker = parsed
    if len(marker) < 4:
        return None

    baseline_body = baseline.body if baseline else ""
    reflected_body = marker in response.body and marker not in baseline_body
    reflected_headers = [
        f"{key}: {value}"
        for key, value in response.headers.items()
        if marker in value and (not baseline or marker not in baseline.headers.get(key, ""))
    ]
    if not reflected_body and not reflected_headers:
        return None

    cache_values = " ".join(response.headers.get(key, "") for key in CACHE_HEADER_NAMES).lower()
    cacheable = any(
        token in cache_values
        for token in ("hit", "public", "max-age", "s-maxage", "cached", "akamai")
    )
    try:
        age = int(response.headers.get("age", "0") or 0)
        cacheable = cacheable or age > 0
    except ValueError:
        pass

    where = "body" if reflected_body else "headers"
    evidence = (
        f"unkeyed header {name}: {marker!r} reflected in response {where}; "
        f"cache indicators={'yes' if cacheable else 'no'}"
    )
    return _finding(
        job,
        payload,
        response,
        severity="medium" if cacheable else "low",
        confidence="confirmed" if cacheable else "candidate",
        evidence=evidence,
        param=name,
        body_snippet=_snippet(response.body, marker),
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

Detector = Callable[[FuzzJob, str, HttpResult | None, HttpResult, TargetConfig], Finding | None]

_DETECTORS: dict[str, Detector] = {
    "xss": detect_xss,
    "sqli": detect_sqli,
    "open-redirect": detect_open_redirect,
    "headers-reflection": detect_header_reflection,
    "headers-status": detect_header_status,
    "cache-poison": detect_cache_poison,
}


def detect(
    job: FuzzJob,
    payload: str,
    baseline: HttpResult | None,
    response: HttpResult,
    cfg: TargetConfig,
) -> Finding | None:
    """Run the detector for ``job.vuln``."""
    detector = _DETECTORS.get(job.vuln)
    if not detector:
        return None
    try:
        return detector(job, payload, baseline, response, cfg)
    except Exception:
        return None


def supported_vulns() -> tuple[str, ...]:
    return tuple(_DETECTORS)
