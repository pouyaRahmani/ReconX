"""Nuclei integration.

ReconX runs its own curated templates by default (``nuclei-templates/``) and
merges the JSONL findings into the same finding store used by the fuzzer.
Community template tags can be enabled from the target config.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from core import redact, ui
from core.config_loader import tool_path, tool_timeout
from core.fuzz.store import FindingStore
from core.models import Finding, TargetConfig
from core.paths import SubPaths, TargetPaths, Workspace, project_root
from core.process import run, which

_TEXT_LINE_RE = re.compile(
    r"^\[(?P<template>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<url>\S+)"
)


@dataclass
class NucleiStats:
    host: str
    urls: int = 0
    templates: int = 0
    findings: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "urls": self.urls,
            "templates": self.templates,
            "findings": self.findings,
            "errors": self.errors,
        }


def _resolve_templates(value, cfg: TargetConfig) -> list[Path]:
    if isinstance(value, (list, tuple)):
        raw_values = [str(v) for v in value]
    else:
        raw_values = [str(value)] if value else []
    if not raw_values:
        raw_values = ["nuclei-templates"]

    paths: list[Path] = []
    for raw in raw_values:
        path = Path(raw)
        if not path.is_absolute():
            path = project_root() / path
        paths.append(path)
    return paths


def _count_templates(paths: list[Path]) -> int:
    count = 0
    for path in paths:
        if path.is_file() and path.suffix in {".yaml", ".yml"}:
            count += 1
        elif path.is_dir():
            count += sum(1 for _ in path.rglob("*.y*ml"))
    return count


def _nuclei_available(settings: dict) -> bool:
    return which(tool_path(settings, "nuclei")) is not None


def _collect_urls(sub: SubPaths, limit: int) -> list[str]:
    urls: list[str] = []
    for path in (sub.crawl_urls_file, sub.crawl_targets_file, sub.katana_file, sub.passive_file):
        if not path.is_file():
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                url = line.strip()
                if url.startswith(("http://", "https://")) and url not in urls:
                    urls.append(url)
                if len(urls) >= limit:
                    return urls
    return urls


def _map_vuln(template_id: str, tags: list[str]) -> str:
    haystack = " ".join([template_id, *tags]).lower()
    if "xss" in haystack or "cross-site-scripting" in haystack:
        return "xss"
    if "sqli" in haystack or "sql-injection" in haystack or "sql_injection" in haystack:
        return "sqli"
    if "redirect" in haystack:
        return "open-redirect"
    if "cache" in haystack:
        return "cache-poison"
    if "status" in haystack or "bypass" in haystack:
        return "headers-status"
    if "header" in haystack:
        return "headers-reflection"
    return "nuclei"


def _severity_of(data: dict) -> str:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    severity = str(info.get("severity") or data.get("severity") or "info").lower()
    return severity if severity in {"critical", "high", "medium", "low", "info", "unknown"} else "info"


def _finding_from_json(data: dict) -> Finding | None:
    template_id = str(
        data.get("template-id") or data.get("templateID") or data.get("template") or "unknown"
    )
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    tags_raw = info.get("tags") or data.get("tags") or []
    if isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    elif isinstance(tags_raw, (list, tuple)):
        tags = [str(t) for t in tags_raw]
    else:
        tags = []

    url = str(
        data.get("matched-at")
        or data.get("matched_at")
        or data.get("host")
        or data.get("url")
        or ""
    )
    if not url:
        return None

    extracted = data.get("extracted-results") or data.get("extracted_results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    payload = str(extracted[0]) if extracted else str(data.get("matcher-name") or "")
    matcher = str(data.get("matcher-name") or data.get("matcher_name") or "")
    vuln = _map_vuln(template_id, tags)

    evidence = f"nuclei template {template_id}"
    if matcher:
        evidence += f" matcher={matcher}"
    if extracted:
        evidence += f" extracted={'; '.join(str(e) for e in extracted[:3])}"

    finding = Finding(
        vuln=vuln,
        url=redact.url(url),
        method=str(data.get("type") or data.get("method") or "GET").upper()
        if str(data.get("type", "")).lower() in {"get", "post", "put", "patch", "delete"}
        else "GET",
        param=matcher,
        payload=redact.text(payload),
        status=0,
        evidence=redact.text(evidence),
        severity=_severity_of(data),
        confidence="confirmed",
        source="nuclei",
        template=template_id,
        request={"raw": redact.raw_http(str(data.get("request") or "")[:4000])},
        response={"raw": redact.raw_http(str(data.get("response") or "")[:4000])},
    )
    finding.fingerprint = finding.compute_fingerprint()
    return finding


def _parse_text_output(text: str) -> list[Finding]:
    """Parse the legacy human-readable ``[template] [severity] url`` format."""
    findings: list[Finding] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        match = _TEXT_LINE_RE.match(line)
        if not match:
            continue
        finding = Finding(
            vuln=_map_vuln(match.group("template"), []),
            url=redact.url(match.group("url")),
            severity=match.group("severity").lower(),
            confidence="confirmed",
            source="nuclei",
            template=match.group("template"),
            evidence=redact.text(line[:500]),
        )
        finding.fingerprint = finding.compute_fingerprint()
        findings.append(finding)
    return findings


def run_nuclei(
    workspace: Workspace,
    target: str,
    host: str,
    cfg: TargetConfig,
    settings: dict,
) -> NucleiStats:
    """Run Nuclei for one subdomain and store its findings."""
    stats = NucleiStats(host=host)
    nuclei_cfg = cfg.nuclei or {}
    if not nuclei_cfg.get("enabled", True):
        ui.debug(f"{host}: nuclei disabled in config")
        return stats

    target_paths: TargetPaths = workspace.target(target)
    sub: SubPaths = target_paths.sub(host).ensure()
    if not _nuclei_available(settings):
        stats.errors.append("nuclei not found on PATH")
        ui.warn("nuclei is not installed — skipping template scan (run ./reconx doctor)")
        return stats

    template_paths = _resolve_templates(nuclei_cfg.get("templates"), cfg)
    template_count = _count_templates(template_paths)
    stats.templates = template_count

    tags = str(nuclei_cfg.get("extra_tags") or "").strip()
    if not template_count and not tags:
        ui.warn(
            f"{host}: no nuclei templates found at "
            f"{', '.join(str(p) for p in template_paths)} — skipping"
        )
        return stats

    limit = int(nuclei_cfg.get("max_urls", 200) or 200)
    urls = _collect_urls(sub, max(1, limit))
    stats.urls = len(urls)
    if not urls:
        ui.warn(f"{host}: no URLs for nuclei")
        return stats

    targets_file = sub.fuzz_dir / "nuclei_targets.txt"
    sub.fuzz_dir.mkdir(parents=True, exist_ok=True)
    with open(targets_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(urls) + "\n")

    output_file = sub.fuzz_dir / "nuclei.jsonl"
    if output_file.exists():
        output_file.unlink()

    tool = tool_path(settings, "nuclei")
    cmd = [
        tool,
        "-l", str(targets_file),
        "-jsonl",
        "-o", str(output_file),
        "-silent",
        "-nc",
        "-or",                          # omit raw request/response blobs
        "-ot",                          # omit encoded template
        "-rl", str(cfg.rl),
        "-c", str(cfg.c),
        "-timeout", str(cfg.timeout),
    ]
    severity = str(nuclei_cfg.get("severity") or "").strip()
    if severity:
        cmd.extend(["-severity", severity])
    if tags:
        cmd.extend(["-tags", tags])
    if template_count:
        for path in template_paths:
            if path.exists():
                cmd.extend(["-t", str(path)])
    if nuclei_cfg.get("dast", True):
        cmd.append("-dast")
    if cfg.proxy:
        cmd.extend(["-proxy", cfg.proxy])
    for key, value in cfg.headers.items():
        cmd.extend(["-H", f"{key}: {value}"])
    for extra in nuclei_cfg.get("extra_args") or []:
        cmd.append(str(extra))

    ui.info(
        f"nuclei       {ui.colorize(host, ui.CYAN)} "
        f"({len(urls)} URL(s), {template_count} template(s))"
    )
    result = run(cmd, timeout=tool_timeout(settings, "nuclei", 1800))

    if result.timed_out:
        stats.errors.append("nuclei timed out")
        ui.warn("nuclei timed out — parsing partial output")
    if result.returncode not in (0, 1, 124) and not output_file.is_file():
        detail = (result.stderr or "").strip().splitlines()
        message = f"nuclei failed (rc={result.returncode}): {detail[-1] if detail else 'unknown error'}"
        stats.errors.append(message)
        ui.warn(message)

    findings: list[Finding] = []
    if output_file.is_file() and output_file.stat().st_size > 0:
        with open(output_file, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict):
                    finding = _finding_from_json(data)
                    if finding:
                        findings.append(finding)
    else:
        # Very old nuclei versions only emit text; parse stdout/stderr.
        findings.extend(_parse_text_output(result.stdout))
        findings.extend(_parse_text_output(result.stderr))

    store = FindingStore(sub, save_evidence=cfg.save_evidence)
    added = 0
    for finding in findings:
        if store.add(finding):
            added += 1
            ui.ok(
                f"{ui.colorize('NUCLEI', ui.MAGENTA)} "
                f"{finding.template} {finding.url} [{finding.severity}]"
            )

    stats.findings = added
    if added:
        ui.ok(f"{host}: nuclei added {added} finding(s)")
    else:
        ui.info(f"{host}: nuclei found nothing")
    return stats
