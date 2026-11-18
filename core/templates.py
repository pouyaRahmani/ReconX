"""Fuzz-job generation.

Template files are JSONL for transparency and easy debugging; the engine
consumes the in-memory :class:`~core.models.FuzzJob` list directly.

Layout produced per subdomain::

    templates/
    ├── all.jsonl
    ├── summary.txt
    ├── xss/jobs.jsonl
    ├── sqli/jobs.jsonl
    └── ...
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from core import ui
from core.models import Endpoint, FuzzJob, TargetConfig
from core.paths import SubPaths, TargetPaths, Workspace, project_root
from core.params import load_params


# Vulnerability -> payload files (relative to config/payloads).
PARAM_PAYLOADS: dict[str, list[str]] = {
    "xss": ["xss.txt"],
    "sqli": ["sqli.txt", "sleep.txt"],
    "open-redirect": ["open-redirect.txt"],
}

HEADER_PAYLOADS: dict[str, list[str]] = {
    "headers-reflection": ["headers-reflection.txt"],
    "headers-status": ["headers-status.txt"],
    "cache-poison": ["cache-poison.txt"],
}

PAYLOAD_DIR = project_root() / "config" / "payloads"


@dataclass
class TemplateStats:
    host: str
    jobs: int = 0
    per_vuln: dict[str, int] | None = None
    truncated: bool = False

    def __post_init__(self) -> None:
        if self.per_vuln is None:
            self.per_vuln = {}

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "jobs": self.jobs,
            "per_vuln": self.per_vuln,
            "truncated": self.truncated,
        }


def _payload_path(name: str) -> Path:
    return PAYLOAD_DIR / name


def _payload_usable(name: str) -> bool:
    path = _payload_path(name)
    if not path.is_file():
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    return True
    except OSError:
        return False
    return False


def chunk_params(params: list[str], chunk_size: int) -> list[list[str]]:
    """Split *params* into chunks of at most *chunk_size* names."""
    size = max(1, int(chunk_size))
    return [params[i : i + size] for i in range(0, len(params), size)]


def _endpoint_methods(endpoint: Endpoint, cfg: TargetConfig) -> list[str]:
    method = endpoint.method.upper()
    if method not in cfg.methods:
        return []
    return [method]


def _header_targets(data: dict, host: str, limit: int) -> list[str]:
    targets: list[str] = [f"https://{host}/"]
    for endpoint in data.get("endpoints", []):
        url = endpoint.get("url")
        if url and url not in targets:
            targets.append(url)
    for url in data.get("targets", []):
        if url and url not in targets:
            targets.append(url)
    return targets[: max(1, limit)]


def build_jobs(
    workspace: Workspace,
    target: str,
    host: str,
    cfg: TargetConfig,
    *,
    write: bool = True,
) -> tuple[list[FuzzJob], TemplateStats]:
    """Build every fuzz job for one subdomain."""
    target_paths: TargetPaths = workspace.target(target)
    sub: SubPaths = target_paths.sub(host)
    stats = TemplateStats(host=host)

    if not sub.params_file.is_file():
        ui.warn(f"{host}: params.json is missing — run parameter extraction first")
        return [], stats

    data = load_params(sub)
    endpoints = [Endpoint.from_dict(item) for item in data.get("endpoints", [])]
    jobs: list[FuzzJob] = []
    seen: set[str] = set()

    def add(job: FuzzJob) -> None:
        if job.key in seen:
            return
        seen.add(job.key)
        jobs.append(job)

    def payload_jobs(vuln: str, payload_file: str) -> None:
        for endpoint in endpoints:
            methods = _endpoint_methods(endpoint, cfg)
            if not methods:
                continue
            chunks = chunk_params(endpoint.params, cfg.chunk_size)
            for chunk_index, chunk in enumerate(chunks):
                for method in methods:
                    content_type = (
                        endpoint.content_type
                        if endpoint.location == "body"
                        else None
                    )
                    if endpoint.location == "body" and not content_type:
                        content_type = cfg.content_types[0] if cfg.content_types else "urlencoded"
                    add(
                        FuzzJob(
                            vuln=vuln,
                            url=endpoint.url,
                            method=method,
                            location=endpoint.location,
                            params=chunk,
                            # Keep every endpoint parameter so the engine can
                            # preserve the non-fuzzed ones with their sample
                            # values while replacing only this chunk.
                            samples={name: endpoint.samples.get(name, "1") for name in endpoint.params},
                            payload_file=str(_payload_path(payload_file)),
                            content_type=content_type,
                            chunk_index=chunk_index,
                            serial="sleep" in Path(payload_file).stem,
                            source_endpoint=endpoint.key,
                        )
                    )

    # ------------------------------------------------------------------
    # Parameter-based vulnerabilities
    # ------------------------------------------------------------------
    for vuln in cfg.vulns:
        if vuln not in PARAM_PAYLOADS:
            continue
        for payload_file in PARAM_PAYLOADS[vuln]:
            if not _payload_usable(payload_file):
                ui.warn(f"{host}: payload file missing or empty: {payload_file}")
                continue
            if payload_file == "sleep.txt" and cfg.timeout < 18:
                ui.warn(
                    f"{host}: skipping time-based SQLi jobs — timeout={cfg.timeout}s "
                    "is too short for SLEEP(15) payloads"
                )
                continue
            before = len(jobs)
            payload_jobs(vuln, payload_file)
            stats.per_vuln[vuln] = stats.per_vuln.get(vuln, 0) + (len(jobs) - before)

    # ------------------------------------------------------------------
    # Header-based checks (no parameters required)
    # ------------------------------------------------------------------
    for vuln in cfg.vulns:
        if vuln not in HEADER_PAYLOADS:
            continue
        for payload_file in HEADER_PAYLOADS[vuln]:
            if not _payload_usable(payload_file):
                ui.warn(f"{host}: payload file missing or empty: {payload_file}")
                continue
            before = len(jobs)
            for target_url in _header_targets(data, host, cfg.max_header_targets):
                add(
                    FuzzJob(
                        vuln=vuln,
                        url=target_url,
                        method="GET",
                        location="header",
                        params=[],
                        samples={},
                        payload_file=str(_payload_path(payload_file)),
                        content_type=None,
                        serial="status" in vuln,
                    )
                )
            stats.per_vuln[vuln] = stats.per_vuln.get(vuln, 0) + (len(jobs) - before)

    # ------------------------------------------------------------------
    # Job cap
    # ------------------------------------------------------------------
    if len(jobs) > cfg.max_jobs:
        stats.truncated = True
        ui.warn(
            f"{host}: job count {len(jobs)} exceeds max_jobs={cfg.max_jobs}; "
            "truncating (raise max_jobs in the target config if intended)"
        )
        jobs = jobs[: cfg.max_jobs]

    stats.jobs = len(jobs)

    if write:
        _write_templates(sub, jobs, stats)

    return jobs, stats


def _write_templates(sub: SubPaths, jobs: list[FuzzJob], stats: TemplateStats) -> None:
    templates = sub.templates_dir
    templates.mkdir(parents=True, exist_ok=True)

    # Remove stale per-vuln files from previous runs.
    for child in templates.iterdir():
        if child.is_dir():
            for item in child.iterdir():
                if item.is_file():
                    item.unlink()
        elif child.name.endswith(".jsonl"):
            child.unlink()

    by_vuln: dict[str, list[FuzzJob]] = {}
    for job in jobs:
        by_vuln.setdefault(job.vuln, []).append(job)

    with open(templates / "all.jsonl", "w", encoding="utf-8") as handle:
        for job in jobs:
            handle.write(json.dumps(job.to_dict(), ensure_ascii=False) + "\n")

    for vuln, vuln_jobs in by_vuln.items():
        directory = templates / vuln
        directory.mkdir(parents=True, exist_ok=True)
        with open(directory / "jobs.jsonl", "w", encoding="utf-8") as handle:
            for job in vuln_jobs:
                handle.write(json.dumps(job.to_dict(), ensure_ascii=False) + "\n")

    lines = [
        f"ReconX fuzz templates — {stats.host}",
        f"total jobs: {stats.jobs}",
        "",
    ]
    for vuln, count in sorted((stats.per_vuln or {}).items()):
        lines.append(f"  {vuln:<22} {count}")
    with open(templates / "summary.txt", "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def remove_templates(sub: SubPaths) -> None:
    """Delete the templates directory after a successful run."""
    if not sub.templates_dir.is_dir():
        return
    for root, dirs, files in os.walk(sub.templates_dir, topdown=False):
        for name in files:
            Path(root, name).unlink(missing_ok=True)
        for name in dirs:
            Path(root, name).rmdir()
    sub.templates_dir.rmdir()
