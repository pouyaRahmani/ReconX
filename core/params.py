"""Parameter extraction, merging and parametrised URL generation.

Sources consumed per subdomain:

* ``<host>.passive``                  – archived GET URLs
* ``<host>.katana``                   – crawled URLs
* ``<host>.katana.requests.jsonl``    – structured requests (method/body/forms)

The result is ``params.json``::

    {
      "subdomain": "app.example.com",
      "endpoints": [
        {"url": "...", "method": "GET", "location": "query",
         "params": ["q"], "samples": {"q": "test"}}
      ],
      "all_params": ["q"],
      "targets": ["https://app.example.com/", ...],
      "urls": ["https://app.example.com/search?q=test", ...]
    }
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from core import ui
from core.models import Endpoint, TargetConfig, utc_now
from core.paths import SubPaths, TargetPaths, Workspace
from core.recon.urls import (
    base_url,
    host_root,
    normalize_url,
    parse_host,
    query_pairs,
    query_samples,
)

_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")
_MULTIPART_NAME_RE = re.compile(r'name="([^"]+)"')


@dataclass
class ParamStats:
    subdomain: str
    endpoints: int = 0
    params: int = 0
    urls: int = 0

    def as_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "endpoints": self.endpoints,
            "params": self.params,
            "urls": self.urls,
        }


# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------

def _ignored(name: str, patterns: list[str]) -> bool:
    if not name:
        return True
    for pattern in patterns:
        if fnmatch.fnmatch(name.lower(), pattern.lower()):
            return True
    return False


def _clean_params(names: list[str], cfg: TargetConfig) -> list[str]:
    result: list[str] = []
    for name in names:
        name = (name or "").strip()
        if not name or not _PARAM_NAME_RE.match(name):
            continue
        if _ignored(name, cfg.ignore_params):
            continue
        if name not in result:
            result.append(name)
    return result


def _clean_samples(samples: dict[str, str], cfg: TargetConfig, params: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in params:
        value = samples.get(name, "1")
        value = str(value).replace("\r", " ").replace("\n", " ")[:120]
        result[name] = value
    return result


def _parse_body(body: str, content_type: str) -> tuple[str, dict[str, str]]:
    """Return ``(normalised_content_type, samples)`` for a request body."""
    ct = (content_type or "").lower()
    body = body or ""
    if not body.strip():
        return ("urlencoded", {})

    if "json" in ct or body.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return ("json", {})
        samples: dict[str, str] = {}
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    samples[str(key)] = "" if value is None else str(value)
        elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            for key, value in parsed[0].items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    samples[str(key)] = "" if value is None else str(value)
        return ("json", samples)

    if "multipart" in ct:
        names = _MULTIPART_NAME_RE.findall(body)
        return ("multipart", {name: "1" for name in names})

    pairs = parse_qsl(body, keep_blank_values=True)
    samples = {}
    for name, value in pairs:
        samples.setdefault(name, value)
    return ("urlencoded", samples)


def _add_endpoint(
    endpoints: dict[tuple, Endpoint],
    *,
    url: str,
    method: str,
    location: str,
    content_type: str | None,
    params: list[str],
    samples: dict[str, str],
    source: str,
    cfg: TargetConfig,
) -> None:
    clean = _clean_params(params, cfg)
    if not clean:
        return
    endpoint = Endpoint(
        url=base_url(url),
        method=method.upper(),
        location=location,
        content_type=content_type,
        params=clean,
        samples=_clean_samples(samples, cfg, clean),
        sources=[source],
    )
    key = (endpoint.url, endpoint.method, endpoint.location, endpoint.content_type)
    existing = endpoints.get(key)
    if existing:
        for name in clean:
            if name not in existing.params:
                existing.params.append(name)
        existing.samples.update(endpoint.samples)
        if source not in existing.sources:
            existing.sources.append(source)
    else:
        endpoints[key] = endpoint


def _read_lines(path) -> list[str]:
    if not hasattr(path, "is_file") or not path.is_file():
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return [line.strip() for line in handle if line.strip()]


def _read_records(path) -> list[dict]:
    records: list[dict] = []
    if not hasattr(path, "is_file") or not path.is_file():
        return records
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
    return records


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_params(
    workspace: Workspace,
    target: str,
    host: str,
    cfg: TargetConfig,
    *,
    refresh: bool = False,
) -> dict[str, Any]:
    """Extract parameters for *host* and write ``params.json``."""
    target_paths: TargetPaths = workspace.target(target)
    sub: SubPaths = target_paths.sub(host).ensure()

    if sub.params_file.is_file() and not refresh:
        data = load_params(sub)
        ui.debug(f"{host}: reusing existing params.json")
        return data

    ui.info(f"Extracting parameters for {ui.colorize(host, ui.CYAN)}")

    url_set: set[str] = set()
    passive_urls = _read_lines(sub.passive_file)
    katana_urls = _read_lines(sub.katana_file)
    request_records = _read_records(sub.katana_requests_file)

    for raw in [*passive_urls, *katana_urls]:
        normalized = normalize_url(raw)
        if normalized:
            url_set.add(normalized)

    endpoints: dict[tuple, Endpoint] = {}
    params_sources: dict[str, set[str]] = {"passive": set(), "katana": set(), "forms": set()}

    # -- URL query strings ---------------------------------------------------
    for raw in passive_urls:
        normalized = normalize_url(raw)
        if not normalized:
            continue
        names = [n for n, _ in query_pairs(normalized)]
        if not names:
            continue
        samples = query_samples(normalized)
        _add_endpoint(
            endpoints,
            url=normalized,
            method="GET",
            location="query",
            content_type=None,
            params=names,
            samples=samples,
            source="passive",
            cfg=cfg,
        )
        params_sources["passive"].update(_clean_params(names, cfg))

    for raw in katana_urls:
        normalized = normalize_url(raw)
        if not normalized:
            continue
        names = [n for n, _ in query_pairs(normalized)]
        if not names:
            continue
        samples = query_samples(normalized)
        _add_endpoint(
            endpoints,
            url=normalized,
            method="GET",
            location="query",
            content_type=None,
            params=names,
            samples=samples,
            source="katana",
            cfg=cfg,
        )
        params_sources["katana"].update(_clean_params(names, cfg))

    # -- Structured requests (POST bodies, JSON, forms) ----------------------
    for record in request_records:
        url = normalize_url(record.get("url", ""))
        if not url:
            continue
        method = str(record.get("method") or "GET").upper()
        headers = record.get("headers") or {}
        content_type = str(headers.get("content-type") or record.get("content_type") or "")

        names = [n for n, _ in query_pairs(url)]
        if names:
            _add_endpoint(
                endpoints,
                url=url,
                method=method,
                location="query",
                content_type=None,
                params=names,
                samples=query_samples(url),
                source="katana",
                cfg=cfg,
            )
            params_sources["katana"].update(_clean_params(names, cfg))

        body = record.get("body") or ""
        if body:
            normalised_ct, samples = _parse_body(body, content_type)
            _add_endpoint(
                endpoints,
                url=url,
                method=method,
                location="body",
                content_type=normalised_ct,
                params=list(samples.keys()),
                samples=samples,
                source="katana",
                cfg=cfg,
            )
            params_sources["katana"].update(_clean_params(list(samples.keys()), cfg))

        for form in record.get("forms") or []:
            action = normalize_url(form.get("action") or url)
            if not action:
                continue
            fields = [str(f) for f in form.get("fields") or []]
            form_method = str(form.get("method") or "GET").upper()
            location = "query" if form_method in {"GET", "HEAD"} else "body"
            _add_endpoint(
                endpoints,
                url=action,
                method=form_method,
                location=location,
                content_type=None if location == "query" else "urlencoded",
                params=fields,
                samples={f: "1" for f in fields},
                source="forms",
                cfg=cfg,
            )
            params_sources["forms"].update(_clean_params(fields, cfg))
            url_set.add(action)

    # -- Cross-page merge ----------------------------------------------------
    if cfg.cross_page_params and len(endpoints) > 1:
        groups: dict[tuple, list[Endpoint]] = {}
        for endpoint in endpoints.values():
            group_key = (endpoint.method, endpoint.location, endpoint.content_type)
            groups.setdefault(group_key, []).append(endpoint)
        for group in groups.values():
            merged_params: list[str] = []
            merged_samples: dict[str, str] = {}
            for endpoint in group:
                for name in endpoint.params:
                    if name not in merged_params:
                        merged_params.append(name)
                merged_samples.update(endpoint.samples)
            if len(group) < 2 or not merged_params:
                continue
            for endpoint in group:
                added = False
                for name in merged_params:
                    if name not in endpoint.params:
                        endpoint.params.append(name)
                        added = True
                for name in endpoint.params:
                    endpoint.samples.setdefault(name, merged_samples.get(name, "1"))
                if added:
                    endpoint.merged = True

    # -- Aggregate output ----------------------------------------------------
    endpoint_list = sorted(
        endpoints.values(),
        key=lambda e: (e.url, e.method, e.location, e.content_type or ""),
    )
    all_params = sorted({name for endpoint in endpoint_list for name in endpoint.params})
    passive_params = sorted(params_sources["passive"])

    # Parametrised URLs: real URLs that carry a query string.
    parametrised: set[str] = set()
    for raw in [*passive_urls, *katana_urls]:
        normalized = normalize_url(raw)
        if normalized and query_pairs(normalized):
            parametrised.add(normalized)
    for record in request_records:
        normalized = normalize_url(record.get("url", ""))
        if normalized and query_pairs(normalized):
            parametrised.add(normalized)

    # Base targets: useful for nuclei header templates and reporting.
    targets: set[str] = {f"https://{host}/"}
    for raw in [*passive_urls, *katana_urls]:
        normalized = normalize_url(raw)
        if normalized:
            targets.add(base_url(normalized))
    for record in request_records:
        normalized = normalize_url(record.get("url", ""))
        if normalized:
            targets.add(base_url(normalized))
    for endpoint in endpoint_list:
        targets.add(endpoint.url)

    sub.crawl_dir.mkdir(parents=True, exist_ok=True)
    with open(sub.crawl_urls_file, "w", encoding="utf-8") as handle:
        if parametrised:
            handle.write("\n".join(sorted(parametrised)) + "\n")
    with open(sub.crawl_targets_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(sorted(targets)) + "\n")

    stats = ParamStats(
        subdomain=host,
        endpoints=len(endpoint_list),
        params=len(all_params),
        urls=len(parametrised),
    )
    data: dict[str, Any] = {
        "subdomain": host,
        "generated_at": utc_now(),
        "sources": {
            "passive": len(passive_urls),
            "katana": len(katana_urls),
            "requests": len(request_records),
            "forms": sum(len(r.get("forms") or []) for r in request_records),
        },
        "endpoints": [endpoint.to_dict() for endpoint in endpoint_list],
        "all_params": all_params,
        "passive_params": passive_params,
        "targets": sorted(targets),
        "urls": sorted(parametrised),
        "stats": stats.as_dict(),
    }
    _write_json(sub.params_file, data)

    ui.ok(
        f"{host}: {stats.endpoints} endpoint(s), {stats.params} parameter(s), "
        f"{stats.urls} parametrised URL(s)"
    )
    return data


# ---------------------------------------------------------------------------
# Cross-subdomain parameter sharing
# ---------------------------------------------------------------------------

def cross_sub_merge(
    workspace: Workspace,
    target: str,
    cfg: TargetConfig,
) -> list[str]:
    """Merge passive parameters seen across subdomains (opt-in)."""
    if not cfg.cross_sub_passive_params:
        return []

    target_paths = workspace.target(target)
    counter: Counter[str] = Counter()
    sources: dict[str, list[str]] = {}

    for host in target_paths.hosts():
        sub = target_paths.sub(host)
        try:
            data = load_params(sub)
        except (OSError, json.JSONDecodeError):
            continue
        names = data.get("passive_params") or data.get("all_params") or []
        for name in names:
            if _ignored(name, cfg.ignore_params) or not _PARAM_NAME_RE.match(name):
                continue
            counter[name] += 1
            sources.setdefault(name, []).append(host)

    if not counter:
        ui.info("Cross-subdomain parameter merge: no passive parameters found")
        return []

    limit = max(0, cfg.shared_param_limit)
    ordered = [name for name, _ in counter.most_common()]
    shared = ordered[:limit] if limit else []

    payload = {
        "generated_at": utc_now(),
        "params": shared,
        "frequency": {name: counter[name] for name in shared},
        "sources": {name: sources.get(name, []) for name in shared},
    }
    _write_json(target_paths.shared_params_file, payload)
    ui.ok(
        f"Cross-subdomain merge: {len(shared)} shared passive parameter(s) "
        f"from {len(sources)} host(s)"
    )
    return shared


def apply_shared_params(
    workspace: Workspace,
    target: str,
    host: str,
    shared: list[str],
    cfg: TargetConfig,
) -> int:
    """Add shared passive parameters to GET endpoints of *host*."""
    if not shared:
        return 0
    target_paths = workspace.target(target)
    sub = target_paths.sub(host)
    if not sub.params_file.is_file():
        return 0

    data = load_params(sub)
    added_total = 0
    for raw_endpoint in data.get("endpoints", []):
        endpoint = Endpoint.from_dict(raw_endpoint)
        if endpoint.location != "query" or endpoint.method.upper() not in {"GET", "HEAD"}:
            continue
        available = max(0, cfg.shared_param_limit)
        for name in shared:
            if available <= 0:
                break
            if name in endpoint.params:
                continue
            endpoint.params.append(name)
            endpoint.samples.setdefault(name, "1")
            endpoint.shared = True
            available -= 1
            added_total += 1
        raw_endpoint.update(endpoint.to_dict())

    if added_total:
        data["all_params"] = sorted(
            {name for endpoint in data.get("endpoints", []) for name in endpoint.get("params", [])}
        )
        _write_json(sub.params_file, data)
        ui.info(f"{host}: added {added_total} shared parameter assignment(s)")
    return added_total


# ---------------------------------------------------------------------------
# Single-URL mode
# ---------------------------------------------------------------------------

def build_single_params(
    workspace: Workspace,
    target: str,
    url: str,
    cfg: TargetConfig,
    *,
    method: str | None = None,
    data: str | None = None,
    params: list[str] | None = None,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Create a params.json for an arbitrary URL (``single-fuzz``)."""
    normalized = normalize_url(url)
    if not normalized:
        raise ValueError(f"invalid URL: {url}")
    host = parse_host(normalized)
    if not host:
        raise ValueError(f"cannot determine host for URL: {url}")

    target_paths = workspace.target(target).ensure()
    sub = target_paths.sub(host).ensure()

    endpoints: dict[tuple, Endpoint] = {}
    query_names = [n for n, _ in query_pairs(normalized)]
    query_name_values = query_samples(normalized)

    chosen_method = (method or ("POST" if data else "GET")).upper()
    if query_names:
        _add_endpoint(
            endpoints,
            url=normalized,
            method="GET" if not method else chosen_method,
            location="query",
            content_type=None,
            params=query_names,
            samples=query_name_values,
            source="single",
            cfg=cfg,
        )

    body_ct = "urlencoded"
    body_samples: dict[str, str] = {}
    if data:
        raw_ct = content_type or "urlencoded"
        if raw_ct in {"json", "application/json"}:
            body_ct, body_samples = _parse_body(data, "application/json")
        elif raw_ct in {"multipart", "multipart/form-data"}:
            body_ct, body_samples = _parse_body(data, "multipart/form-data")
        else:
            body_ct, body_samples = _parse_body(data, "application/x-www-form-urlencoded")
        _add_endpoint(
            endpoints,
            url=normalized,
            method=chosen_method,
            location="body",
            content_type=body_ct,
            params=list(body_samples.keys()),
            samples=body_samples,
            source="single",
            cfg=cfg,
        )

    if params:
        location = "query" if chosen_method in {"GET", "HEAD"} else "body"
        _add_endpoint(
            endpoints,
            url=normalized,
            method=chosen_method,
            location=location,
            content_type=None if location == "query" else (content_type or "urlencoded"),
            params=params,
            samples={p: "1" for p in params},
            source="single",
            cfg=cfg,
        )

    endpoint_list = sorted(endpoints.values(), key=lambda e: (e.url, e.method, e.location))
    all_params = sorted({p for e in endpoint_list for p in e.params})
    targets = sorted({base_url(normalized), host_root(normalized) + "/"})
    urls = [normalized] if query_names else []

    sub.crawl_dir.mkdir(parents=True, exist_ok=True)
    with open(sub.crawl_urls_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(urls) + ("\n" if urls else ""))
    with open(sub.crawl_targets_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(targets) + "\n")

    data_dict: dict[str, Any] = {
        "subdomain": host,
        "generated_at": utc_now(),
        "mode": "single",
        "seeds": [normalized],
        "endpoints": [e.to_dict() for e in endpoint_list],
        "all_params": all_params,
        "passive_params": [],
        "targets": targets,
        "urls": urls,
        "stats": {
            "subdomain": host,
            "endpoints": len(endpoint_list),
            "params": len(all_params),
            "urls": len(urls),
        },
    }
    _write_json(sub.params_file, data_dict)
    ui.ok(
        f"single-fuzz target prepared: {host} "
        f"({len(endpoint_list)} endpoint(s), {len(all_params)} parameter(s))"
    )
    return data_dict


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def load_params(sub: SubPaths) -> dict[str, Any]:
    with open(sub.params_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise json.JSONDecodeError("params.json must contain an object", "", 0)
    return data


def _write_json(path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
