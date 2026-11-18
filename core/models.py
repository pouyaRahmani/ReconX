"""Typed data structures shared by the ReconX modules."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VALID_VULNS = (
    "xss",
    "sqli",
    "open-redirect",
    "headers-reflection",
    "headers-status",
    "cache-poison",
)

VALID_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
VALID_CONTENT_TYPES = ("urlencoded", "json", "multipart")

# Short aliases accepted in config files.
VULN_ALIASES = {"mysqli": "sqli", "redirect": "open-redirect", "crlf": "headers-reflection"}


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


@dataclass
class NotificationConfig:
    """Telegram / generic webhook delivery settings."""

    enabled: bool = False
    only_on_diff: bool = True
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "NotificationConfig":
        data = data if isinstance(data, dict) else {}
        return cls(
            enabled=_as_bool(data.get("enabled"), False),
            only_on_diff=_as_bool(data.get("only_on_diff"), True),
            telegram_bot_token=str(data.get("telegram_bot_token") or "").strip(),
            telegram_chat_id=str(data.get("telegram_chat_id") or "").strip(),
            webhook_url=str(data.get("webhook_url") or "").strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TargetConfig:
    """Validated target configuration."""

    target: str
    sub: str = ""
    seeds: list[str] = field(default_factory=list)
    cross_page_params: bool = True
    cross_sub_passive_params: bool = False
    shared_param_limit: int = 15
    methods: list[str] = field(default_factory=lambda: ["GET"])
    content_types: list[str] = field(default_factory=lambda: ["urlencoded"])
    chunk_size: int = 25
    vulns: list[str] = field(default_factory=lambda: ["xss"])
    rl: int = 20
    c: int = 10
    timeout: int = 60
    max_payloads: int = 100
    max_requests: int = 20000
    max_jobs: int = 20000
    max_header_targets: int = 25
    baseline_samples: int = 1
    sleep_threshold: float = 8.0
    verify_tls: bool = True
    follow_redirects: bool = False
    save_evidence: bool = True
    max_response_bytes: int = 1_000_000
    user_agent: str = ""
    proxy: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    ignore_params: list[str] = field(default_factory=list)
    exclude_extensions: list[str] = field(default_factory=list)
    scope_domains: list[str] = field(default_factory=list)
    nuclei: dict[str, Any] = field(default_factory=dict)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    output: dict[str, Any] = field(default_factory=dict)

    # -- convenience ---------------------------------------------------------
    def vuln_list(self) -> list[str]:
        return list(self.vulns)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetConfig":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in data.items() if k in allowed}
        if isinstance(kwargs.get("notifications"), dict):
            kwargs["notifications"] = NotificationConfig.from_dict(kwargs["notifications"])
        return cls(**kwargs)


# ---------------------------------------------------------------------------
# Recon / parameter model
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    """One fuzzable location (URL + method + parameter location)."""

    url: str                                   # URL without query string
    method: str = "GET"
    location: str = "query"                    # query | body
    content_type: str | None = None
    params: list[str] = field(default_factory=list)
    samples: dict[str, str] = field(default_factory=dict)
    merged: bool = False
    shared: bool = False
    sources: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.location} {self.url} {self.content_type or ''}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Endpoint":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class FuzzJob:
    """A unit of work for the fuzzing engine."""

    vuln: str
    url: str
    method: str
    location: str                              # query | body | header
    params: list[str]
    samples: dict[str, str]
    payload_file: str
    content_type: str | None = None
    chunk_index: int = 0
    serial: bool = False
    source_endpoint: str = ""

    @property
    def key(self) -> str:
        return "|".join(
            [
                self.vuln,
                self.method.upper(),
                self.location,
                self.url,
                self.content_type or "",
                ",".join(self.params),
                self.payload_file,
                str(self.chunk_index),
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FuzzJob":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in allowed})


# ---------------------------------------------------------------------------
# HTTP response
# ---------------------------------------------------------------------------

@dataclass
class HttpResult:
    """Normalised HTTP result used by the detectors."""

    ok: bool = False
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0                       # seconds
    url: str = ""
    error: str = ""
    method: str = "GET"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None

    @property
    def length(self) -> int:
        return len(self.body)

    @property
    def elapsed_ms(self) -> float:
        return round(self.elapsed * 1000, 1)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """A confirmed or candidate vulnerability."""

    vuln: str
    url: str
    method: str = "GET"
    param: str = ""
    payload: str = ""
    status: int = 0
    evidence: str = ""
    severity: str = "medium"
    confidence: str = "candidate"              # confirmed | candidate | info
    source: str = "fuzzer"                     # fuzzer | nuclei
    template: str = ""
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        raw = "\x00".join(
            [
                self.vuln.lower(),
                self.method.upper(),
                _normalise_for_fingerprint(self.url),
                self.param,
                self.payload,
                self.template,
            ]
        )
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data.get("fingerprint"):
            data["fingerprint"] = self.compute_fingerprint()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        finding = cls(**{k: v for k, v in data.items() if k in allowed})
        if not finding.fingerprint:
            finding.fingerprint = finding.compute_fingerprint()
        return finding

    def hit_line(self) -> str:
        """Legacy ``hits.txt`` representation (kept for compatibility)."""
        return (
            f"[{self.vuln.upper()}] {self.url} | {self.param or '-'} | "
            f"{self.payload or '-'} | {self.status} | {self.evidence}"
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=False)


def _normalise_for_fingerprint(url: str) -> str:
    """Cheap, dependency-free URL normalisation for deduplication."""
    try:
        from core.recon.urls import normalize_url

        return normalize_url(url) or url
    except Exception:
        return url
