"""Settings and per-target configuration loading / validation.

Two configuration layers exist:

``config/settings.yaml``
    Global tool paths and sensible defaults.

``target-configs/<name>.json``
    Per-target options (scope, vuln list, rate limits, methods…).

The loader is strict about the values that affect request safety (rate limit,
methods, vulns, chunk size) and produces actionable error messages.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from core import ui
from core.models import (
    VALID_CONTENT_TYPES,
    VALID_METHODS,
    VALID_VULNS,
    VULN_ALIASES,
    NotificationConfig,
    TargetConfig,
)
from core.paths import project_root
from core.recon.urls import DEFAULT_STATIC_EXTENSIONS, normalize_url


class ConfigError(ValueError):
    """Raised when a configuration file is invalid."""


DEFAULT_IGNORE_PARAMS = [
    "utm_*", "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref", "referrer", "source", "yclid", "igshid",
    "__cf_chl_*", "cf_chl_*",
]

DEFAULT_SETTINGS: dict[str, Any] = {
    "tools": {
        "waybackurls": "waybackurls",
        "gau": "gau",
        "uro": "uro",
        "katana": "katana",
        "subfinder": "subfinder",
        "nuclei": "nuclei",
        "unfurl": "unfurl",
        "httpx": "httpx",
        "ffuf": "ffuf",
    },
    "gau": {
        # waybackurls covers the Wayback CDX index in one request; gau's own
        # Wayback provider paginates it and is slow on busy domains.
        "providers": ["otx", "urlscan"],
        "threads": 5,
        "timeout": 20,
        "extra_args": [],
    },
    "defaults": {
        "rate_limit": 20,
        "concurrency": 10,
        "timeout": 60,
        "chunk_size": 25,
        "max_payloads": 100,
        "max_requests": 20000,
        "max_jobs": 20000,
        "max_header_targets": 25,
        "baseline_samples": 1,
        "sleep_threshold": 8.0,
        "verify_tls": True,
        "follow_redirects": False,
        "save_evidence": True,
        "max_response_bytes": 1000000,
        "user_agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 ReconX/2.0"
        ),
        "proxy": "",
        "headers": {},
        "cross_page_params": True,
        "cross_sub_passive_params": False,
        "shared_param_limit": 15,
        "ignore_params": DEFAULT_IGNORE_PARAMS,
        "exclude_extensions": [e.lstrip(".") for e in DEFAULT_STATIC_EXTENSIONS],
        "scope_domains": [],
    },
    "timeouts": {
        "waybackurls": 180,
        "gau": 240,
        "uro": 120,
        "katana": 900,
        "subfinder": 180,
        "nuclei": 1800,
    },
    "nuclei": {
        "enabled": True,
        "templates": "nuclei-templates",
        "dast": True,
        "severity": "low,medium,high,critical",
        "extra_tags": "",
        "max_urls": 200,
        "extra_args": [],
    },
    "notifications": {
        "enabled": False,
        "only_on_diff": True,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "webhook_url": "",
    },
    "output": {
        "formats": ["txt", "json", "html"],
        "html_theme": "dark",
    },
}


# ---------------------------------------------------------------------------
# YAML settings
# ---------------------------------------------------------------------------

def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_settings(path: str | Path | None = None) -> dict[str, Any]:
    """Load ``config/settings.yaml`` merged over the built-in defaults."""
    settings_path = Path(path) if path else project_root() / "config" / "settings.yaml"
    if not settings_path.is_file():
        return copy.deepcopy(DEFAULT_SETTINGS)

    try:
        import yaml  # imported lazily so target configs work without PyYAML
    except ImportError as exc:  # pragma: no cover - requirements installs it
        raise ConfigError("PyYAML is required to read config/settings.yaml") from exc

    try:
        with open(settings_path, "r", encoding="utf-8") as handle:
            user_settings = yaml.safe_load(handle) or {}
    except Exception as exc:
        raise ConfigError(f"Cannot parse {settings_path}: {exc}") from exc

    if not isinstance(user_settings, dict):
        raise ConfigError(f"{settings_path} must contain a YAML mapping")

    return _deep_merge(DEFAULT_SETTINGS, user_settings)


def tool_path(settings: dict[str, Any], name: str) -> str:
    """Return the configured command for *name* (defaults to the tool name)."""
    tools = settings.get("tools") or {}
    value = tools.get(name) or name
    return str(value)


def tool_timeout(settings: dict[str, Any], name: str, default: float = 300) -> float:
    return float((settings.get("timeouts") or {}).get(name, default))


# ---------------------------------------------------------------------------
# Target configuration
# ---------------------------------------------------------------------------

def _normalise_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _as_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        result: list[str] = []
        for item in value:
            if not isinstance(item, (str, int, float)):
                raise ConfigError(f"'{field_name}' entries must be strings, got {type(item).__name__}")
            result.append(str(item).strip())
        return result
    raise ConfigError(f"'{field_name}' must be a string or a list of strings")


def _as_positive_int(value: Any, field_name: str, *, minimum: int = 1) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"'{field_name}' must be an integer, got {value!r}") from exc
    if number < minimum:
        raise ConfigError(f"'{field_name}' must be >= {minimum}, got {number}")
    return number


def _normalise_seeds(values: list[str]) -> list[str]:
    seeds: list[str] = []
    for value in values:
        candidate = value.strip()
        if not candidate:
            continue
        if "://" not in candidate:
            candidate = "https://" + candidate
        normalized = normalize_url(candidate)
        if not normalized:
            raise ConfigError(f"invalid seed URL: {value!r}")
        if normalized not in seeds:
            seeds.append(normalized)
    return seeds


def _default_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("'headers' must be an object of header -> value")
    headers: dict[str, str] = {}
    for key, value in raw.items():
        key = str(key).strip()
        if not key or "\n" in key or "\r" in key:
            raise ConfigError(f"invalid header name: {key!r}")
        value = str(value)
        if "\n" in value or "\r" in value:
            raise ConfigError(f"invalid value for header {key!r}")
        headers[key] = value
    return headers


def default_target_config(
    target: str,
    *,
    seeds: list[str] | None = None,
    sub: str = "",
    settings: dict[str, Any] | None = None,
) -> TargetConfig:
    """Build a target config using global defaults (used by passive/active)."""
    settings = settings or load_settings()
    defaults = settings.get("defaults") or {}
    return TargetConfig(
        target=target,
        sub=sub,
        seeds=_normalise_seeds(seeds or []),
        cross_page_params=_normalise_bool(defaults.get("cross_page_params", True)),
        cross_sub_passive_params=_normalise_bool(defaults.get("cross_sub_passive_params", False)),
        shared_param_limit=int(defaults.get("shared_param_limit", 15)),
        methods=["GET"],
        content_types=["urlencoded"],
        chunk_size=int(defaults.get("chunk_size", 25)),
        vulns=["xss"],
        rl=int(defaults.get("rate_limit", 20)),
        c=int(defaults.get("concurrency", 10)),
        timeout=int(defaults.get("timeout", 60)),
        max_payloads=int(defaults.get("max_payloads", 100)),
        max_requests=int(defaults.get("max_requests", 20000)),
        max_jobs=int(defaults.get("max_jobs", 20000)),
        max_header_targets=int(defaults.get("max_header_targets", 25)),
        baseline_samples=int(defaults.get("baseline_samples", 1)),
        sleep_threshold=float(defaults.get("sleep_threshold", 8.0)),
        verify_tls=_normalise_bool(defaults.get("verify_tls", True)),
        follow_redirects=_normalise_bool(defaults.get("follow_redirects", False)),
        save_evidence=_normalise_bool(defaults.get("save_evidence", True)),
        max_response_bytes=int(defaults.get("max_response_bytes", 1000000)),
        user_agent=str(defaults.get("user_agent", "")),
        proxy=str(defaults.get("proxy", "") or ""),
        headers=_default_headers(defaults.get("headers")),
        ignore_params=[str(p) for p in defaults.get("ignore_params", DEFAULT_IGNORE_PARAMS)],
        exclude_extensions=[str(e) for e in defaults.get("exclude_extensions", [])],
        scope_domains=[str(d) for d in defaults.get("scope_domains", [])],
        nuclei=copy.deepcopy(settings.get("nuclei") or {}),
        notifications=NotificationConfig.from_dict(settings.get("notifications")),
        output=copy.deepcopy(settings.get("output") or {}),
    )


def validate_config(raw: dict[str, Any], settings: dict[str, Any] | None = None) -> TargetConfig:
    """Validate and normalise a raw target-config mapping."""
    if not isinstance(raw, dict):
        raise ConfigError("target config must be a JSON object")

    settings = settings or load_settings()
    defaults = settings.get("defaults") or {}
    known = set(TargetConfig.__dataclass_fields__)  # type: ignore[attr-defined]
    unknown = sorted(set(raw) - known)
    if unknown:
        ui.warn(f"Ignoring unknown config key(s): {', '.join(unknown)}")

    target = str(raw.get("target", "")).strip()
    if not target:
        raise ConfigError(
            "'target' must be a non-empty string (e.g. \"acme\" or \"hackerone\")"
        )

    seeds = _normalise_seeds(_as_list(raw.get("seeds"), "seeds"))
    sub = str(raw.get("sub", "") or "").strip()

    # Vulnerability list -----------------------------------------------------
    raw_vulns = _as_list(raw.get("vulns"), "vulns")
    if not raw_vulns:
        raw_vulns = ["xss"]
    vulns: list[str] = []
    for item in raw_vulns:
        item = item.strip().lower()
        item = VULN_ALIASES.get(item, item)
        if item not in VALID_VULNS:
            raise ConfigError(
                f"invalid vulnerability {item!r}; choose from: {', '.join(VALID_VULNS)}"
            )
        if item not in vulns:
            vulns.append(item)

    # Methods ----------------------------------------------------------------
    methods = [m.upper() for m in _as_list(raw.get("methods", "GET"), "methods")]
    if not methods:
        methods = ["GET"]
    invalid = [m for m in methods if m not in VALID_METHODS]
    if invalid:
        raise ConfigError(
            f"invalid method(s) {invalid}; choose from: {', '.join(VALID_METHODS)}"
        )
    methods = list(dict.fromkeys(methods))

    # Content types ----------------------------------------------------------
    content_types = [c.lower() for c in _as_list(raw.get("content_types", "urlencoded"), "content_types")]
    if not content_types:
        content_types = ["urlencoded"]
    invalid = [c for c in content_types if c not in VALID_CONTENT_TYPES]
    if invalid:
        raise ConfigError(
            f"invalid content type(s) {invalid}; choose from: {', '.join(VALID_CONTENT_TYPES)}"
        )
    content_types = list(dict.fromkeys(content_types))

    # Numeric / boolean fields ----------------------------------------------
    chunk_size = _as_positive_int(raw.get("chunk_size", defaults.get("chunk_size", 25)), "chunk_size")
    rl = _as_positive_int(raw.get("rl", defaults.get("rate_limit", 20)), "rl")
    concurrency = _as_positive_int(raw.get("c", defaults.get("concurrency", 10)), "c")
    timeout = _as_positive_int(raw.get("timeout", defaults.get("timeout", 60)), "timeout")
    max_payloads = _as_positive_int(raw.get("max_payloads", defaults.get("max_payloads", 100)), "max_payloads")
    max_requests = _as_positive_int(raw.get("max_requests", defaults.get("max_requests", 20000)), "max_requests")
    max_jobs = _as_positive_int(raw.get("max_jobs", defaults.get("max_jobs", 20000)), "max_jobs")
    max_header_targets = _as_positive_int(
        raw.get("max_header_targets", defaults.get("max_header_targets", 25)), "max_header_targets"
    )
    baseline_samples = _as_positive_int(
        raw.get("baseline_samples", defaults.get("baseline_samples", 1)), "baseline_samples", minimum=1
    )
    try:
        sleep_threshold = float(raw.get("sleep_threshold", defaults.get("sleep_threshold", 8.0)))
    except (TypeError, ValueError) as exc:
        raise ConfigError("'sleep_threshold' must be a number") from exc
    if sleep_threshold <= 0:
        raise ConfigError("'sleep_threshold' must be > 0")

    shared_param_limit = _as_positive_int(
        raw.get("shared_param_limit", defaults.get("shared_param_limit", 15)),
        "shared_param_limit",
        minimum=0,
    )
    max_response_bytes = _as_positive_int(
        raw.get("max_response_bytes", defaults.get("max_response_bytes", 1000000)),
        "max_response_bytes",
        minimum=1024,
    )

    if "sqli" in vulns and timeout < 18:
        ui.warn(
            f"timeout={timeout}s is too short for SLEEP(15) payloads; "
            "time-based SQLi checks will be skipped. Use timeout >= 20."
        )

    # Lists / patterns -------------------------------------------------------
    ignore_params = _as_list(raw.get("ignore_params", defaults.get("ignore_params", [])), "ignore_params")
    exclude_extensions = _as_list(
        raw.get("exclude_extensions", defaults.get("exclude_extensions", [])),
        "exclude_extensions",
    )
    scope_domains = _as_list(raw.get("scope_domains", defaults.get("scope_domains", [])), "scope_domains")

    # Derived scope: seed hosts plus the selected subdomain.
    if not scope_domains:
        from core.recon.urls import parse_host, root_domain_guess

        for seed in seeds:
            scope_domains.append(root_domain_guess(parse_host(seed)))
        if sub:
            scope_domains.append(root_domain_guess(sub))
        scope_domains = list(dict.fromkeys(d for d in scope_domains if d))

    # Nested settings --------------------------------------------------------
    nuclei = _deep_merge(
        copy.deepcopy(settings.get("nuclei") or {}),
        raw.get("nuclei") if isinstance(raw.get("nuclei"), dict) else {},
    )
    output = _deep_merge(
        copy.deepcopy(settings.get("output") or {}),
        raw.get("output") if isinstance(raw.get("output"), dict) else {},
    )
    notifications = _deep_merge(
        copy.deepcopy(settings.get("notifications") or {}),
        raw.get("notifications") if isinstance(raw.get("notifications"), dict) else {},
    )

    cfg = TargetConfig(
        target=target,
        sub=sub,
        seeds=seeds,
        cross_page_params=_normalise_bool(
            raw.get("cross_page_params", defaults.get("cross_page_params", True))
        ),
        cross_sub_passive_params=_normalise_bool(
            raw.get("cross_sub_passive_params", defaults.get("cross_sub_passive_params", False))
        ),
        shared_param_limit=shared_param_limit,
        methods=methods,
        content_types=content_types,
        chunk_size=chunk_size,
        vulns=vulns,
        rl=rl,
        c=concurrency,
        timeout=timeout,
        max_payloads=max_payloads,
        max_requests=max_requests,
        max_jobs=max_jobs,
        max_header_targets=max_header_targets,
        baseline_samples=baseline_samples,
        sleep_threshold=sleep_threshold,
        verify_tls=_normalise_bool(raw.get("verify_tls", defaults.get("verify_tls", True))),
        follow_redirects=_normalise_bool(
            raw.get("follow_redirects", defaults.get("follow_redirects", False))
        ),
        save_evidence=_normalise_bool(raw.get("save_evidence", defaults.get("save_evidence", True))),
        max_response_bytes=max_response_bytes,
        user_agent=str(
            raw.get("user_agent", defaults.get("user_agent", "")) or ""
        ).strip(),
        proxy=str(raw.get("proxy", defaults.get("proxy", "")) or "").strip(),
        headers=_default_headers(raw.get("headers", defaults.get("headers"))),
        ignore_params=ignore_params,
        exclude_extensions=exclude_extensions,
        scope_domains=scope_domains,
        nuclei=nuclei,
        notifications=NotificationConfig.from_dict(notifications),
        output=output,
    )
    return cfg


def load_target_config(path: str | Path, settings: dict[str, Any] | None = None) -> TargetConfig:
    """Load, merge and validate a target JSON config file."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"invalid JSON in {config_path} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path} must contain a JSON object")

    ui.debug(f"loaded target config: {config_path}")
    return validate_config(raw, settings)


# ---------------------------------------------------------------------------
# Config scaffolding
# ---------------------------------------------------------------------------

SAMPLE_CONFIG: dict[str, Any] = {
    "target": "example",
    "sub": "",
    "seeds": ["https://example.com"],
    "cross_page_params": True,
    "cross_sub_passive_params": False,
    "shared_param_limit": 15,
    "methods": ["GET", "POST"],
    "content_types": ["urlencoded", "json"],
    "chunk_size": 25,
    "vulns": [
        "xss",
        "sqli",
        "open-redirect",
        "headers-reflection",
        "headers-status",
        "cache-poison",
    ],
    "rl": 20,
    "c": 10,
    "timeout": 60,
    "max_payloads": 80,
    "max_requests": 20000,
    "verify_tls": True,
    "follow_redirects": False,
    "headers": {},
    "nuclei": {"enabled": True, "dast": True},
    "notifications": {
        "enabled": False,
        "only_on_diff": True,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "webhook_url": "",
    },
    "output": {"formats": ["txt", "json", "html"]},
}


def write_sample_config(destination: str | Path, name: str, seeds: list[str] | None = None) -> Path:
    """Create a starter target config and return its path."""
    destination = Path(destination)
    data = copy.deepcopy(SAMPLE_CONFIG)
    data["target"] = name
    data["seeds"] = _normalise_seeds(seeds or [])
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    return destination
