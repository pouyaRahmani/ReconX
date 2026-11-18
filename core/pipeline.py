"""High-level orchestration for ``mass-fuzz`` and ``single-fuzz``."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core import ui
from core.fuzz import engine as fuzz_engine
from core.models import Finding, TargetConfig
from core.nuclei import run_nuclei
from core.notify import DiffSummary, ScanSummary, Sender
from core.params import (
    apply_shared_params,
    build_single_params,
    cross_sub_merge,
    extract_params,
)
from core.paths import SubPaths, TargetPaths, Workspace
from core.report import aggregate, collect_findings
from core.state import State
from core.templates import build_jobs, remove_templates


@dataclass
class MassFuzzOptions:
    only: list[str] = field(default_factory=list)
    resume: bool = False
    keep_templates: bool = False
    skip_fuzz: bool = False
    skip_nuclei: bool = False
    refresh_params: bool = False
    refresh_fuzz: bool = False
    max_hosts: int | None = None


@dataclass
class PipelineResult:
    target: str
    hosts: list[str] = field(default_factory=list)
    findings: int = 0
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "hosts": self.hosts,
            "findings": self.findings,
            "errors": self.errors,
            "elapsed_seconds": round(self.elapsed, 2),
        }


def _count_findings(sub: SubPaths) -> int:
    if not sub.findings_file.is_file():
        return 0
    with open(sub.findings_file, "r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def _record_host(target_paths: TargetPaths, host: str) -> None:
    hosts: list[str] = []
    if target_paths.subdomains_file.is_file():
        with open(target_paths.subdomains_file, "r", encoding="utf-8", errors="replace") as handle:
            hosts = [line.strip() for line in handle if line.strip()]
    if host not in hosts:
        hosts.append(host)
        with open(target_paths.subdomains_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(sorted(hosts)) + "\n")


def _selected_hosts(target_paths: TargetPaths, cfg: TargetConfig, options: MassFuzzOptions) -> list[str]:
    hosts = target_paths.hosts()
    if cfg.sub:
        hosts = [h for h in hosts if h == cfg.sub]
    if options.only:
        wanted = set(options.only)
        hosts = [h for h in hosts if h in wanted]
    if options.max_hosts:
        hosts = hosts[: max(1, options.max_hosts)]
    return hosts


def _count_endpoints(target_paths: TargetPaths) -> int:
    """Count endpoint records across every host's ``params.json``."""
    total = 0
    for host in target_paths.hosts():
        path = target_paths.sub(host).params_file
        if not path.is_file():
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        endpoints = data.get("endpoints") if isinstance(data, dict) else None
        if isinstance(endpoints, list):
            total += len(endpoints)
    return total


def _send_notifications(
    cfg: TargetConfig,
    target_paths: TargetPaths,
    previous_findings: list[Finding],
    previous_hosts: list[str],
    previous_run_id: str,
) -> list[str]:
    """Notify configured channels after aggregation (warnings only)."""
    config = cfg.notifications
    if not config.enabled:
        return []

    findings, hosts = collect_findings(target_paths)
    summary = ScanSummary(
        target=cfg.target,
        run_id=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        hosts=hosts,
        endpoints=_count_endpoints(target_paths),
        findings=findings,
    )
    diff = DiffSummary.between(
        [f.fingerprint or f.compute_fingerprint() for f in previous_findings],
        previous_hosts,
        findings,
        hosts,
        previous_run_id,
    )
    failures = Sender().notify(config, summary, diff)
    for message in failures:
        ui.warn(f"notification failed: {message}")
    return failures


# ---------------------------------------------------------------------------
# mass-fuzz
# ---------------------------------------------------------------------------

def run_mass_fuzz(
    workspace: Workspace,
    cfg: TargetConfig,
    settings: dict,
    options: MassFuzzOptions | None = None,
) -> PipelineResult:
    options = options or MassFuzzOptions()
    started = time.monotonic()
    target_paths = workspace.target(cfg.target)
    result = PipelineResult(target=cfg.target)

    if not target_paths.subdomains.is_dir():
        raise ValueError(
            f"no recon data for target '{cfg.target}'. "
            f"Run: ./reconx passive -t {cfg.target} <domain> && "
            f"./reconx active -t {cfg.target}"
        )

    hosts = _selected_hosts(target_paths, cfg, options)
    if not hosts:
        raise ValueError("no matching subdomain directories to fuzz")

    result.hosts = list(hosts)
    state = State(target_paths)
    previous_findings, previous_hosts = collect_findings(target_paths)
    previous_run_id = str(state.data.get("updated_at") or "")
    ui.step(f"mass-fuzz: {cfg.target} ({len(hosts)} subdomain(s))")
    ui.kv("vulns", ", ".join(cfg.vulns))
    ui.kv("methods", ", ".join(cfg.methods))
    ui.kv("rate/concurrency", f"{cfg.rl} req/s / {cfg.c} workers")
    ui.kv("chunk size", cfg.chunk_size)

    # ------------------------------------------------------------------
    # Phase 1: parameter extraction
    # ------------------------------------------------------------------
    ui.step("Phase 1 — parameter extraction")
    extracted = 0
    for host in hosts:
        sub = target_paths.sub(host)
        try:
            if options.refresh_params or not sub.params_file.is_file():
                data = extract_params(workspace, cfg.target, host, cfg, refresh=True)
                extracted += 1
            else:
                with open(sub.params_file, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                ui.info(f"{host}: reusing params.json")
            state.update(host, params_endpoints=len(data.get("endpoints", [])), status="params")
        except Exception as exc:
            message = f"{host}: parameter extraction failed: {exc}"
            result.errors.append(message)
            ui.error(message)
            state.update(host, status="error", error=str(exc))

    # ------------------------------------------------------------------
    # Phase 2: cross-subdomain passive parameter merge (optional)
    # ------------------------------------------------------------------
    shared = cross_sub_merge(workspace, cfg.target, cfg)
    if shared:
        for host in hosts:
            apply_shared_params(workspace, cfg.target, host, shared, cfg)

    # ------------------------------------------------------------------
    # Phase 3: template generation + fuzzing + nuclei
    # ------------------------------------------------------------------
    ui.step("Phase 2 — fuzzing pipeline")
    state.save()

    try:
        for position, host in enumerate(hosts, start=1):
            sub = target_paths.sub(host).ensure()
            entry = state.get(host)
            if (
                options.resume
                and entry.get("status") == "done"
                and not options.refresh_fuzz
                and not options.refresh_params
            ):
                ui.info(f"[{position}/{len(hosts)}] {host}: already done — skipping (resume)")
                continue

            ui.step(f"[{position}/{len(hosts)}] {host}")
            try:
                jobs, template_stats = build_jobs(workspace, cfg.target, host, cfg)
                state.update(host, jobs=template_stats.jobs, templates=template_stats.as_dict())

                if not jobs:
                    ui.warn(f"{host}: no fuzz jobs generated")
                if options.skip_fuzz:
                    ui.info("fuzzing skipped (--skip-fuzz)")
                elif jobs:
                    engine_stats, _store = fuzz_engine.run_fuzz(cfg, sub, jobs)
                    state.update(host, fuzz=engine_stats.as_dict())

                if options.skip_nuclei:
                    ui.info("nuclei skipped (--skip-nuclei)")
                else:
                    nuclei_stats = run_nuclei(workspace, cfg.target, host, cfg, settings)
                    state.update(host, nuclei=nuclei_stats.as_dict())

                if jobs and not options.keep_templates:
                    remove_templates(sub)

                total = _count_findings(sub)
                state.mark_done(host, findings=total)
                result.findings += total
                ui.ok(f"{host}: {total} finding(s) recorded")
            except KeyboardInterrupt:
                state.update(host, status="interrupted")
                raise
            except Exception as exc:
                message = f"{host}: pipeline failed: {exc}"
                result.errors.append(message)
                ui.error(message)
                state.update(host, status="error", error=str(exc))
    except KeyboardInterrupt:
        ui.warn("pipeline interrupted — aggregating partial results")
        aggregate(workspace, cfg.target, cfg.output.get("formats"))
        raise

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------
    ui.step("Aggregating findings")
    result.findings = aggregate(workspace, cfg.target, cfg.output.get("formats"))
    result.elapsed = time.monotonic() - started
    _send_notifications(
        cfg,
        target_paths,
        previous_findings,
        previous_hosts,
        previous_run_id,
    )

    if result.errors:
        ui.warn(f"pipeline completed with {len(result.errors)} error(s)")
    ui.ok(f"mass-fuzz finished in {result.elapsed:.1f}s — {result.findings} finding(s)")
    return result


# ---------------------------------------------------------------------------
# single-fuzz
# ---------------------------------------------------------------------------

@dataclass
class SingleFuzzOptions:
    method: str | None = None
    data: str | None = None
    params: list[str] = field(default_factory=list)
    content_type: str | None = None
    skip_nuclei: bool = False
    keep_templates: bool = True


def run_single_fuzz(
    workspace: Workspace,
    cfg: TargetConfig,
    settings: dict,
    url: str,
    options: SingleFuzzOptions | None = None,
) -> PipelineResult:
    options = options or SingleFuzzOptions()
    started = time.monotonic()
    result = PipelineResult(target=cfg.target)

    target_paths = workspace.target(cfg.target).ensure()
    previous_findings, previous_hosts = collect_findings(target_paths)
    data = build_single_params(
        workspace,
        cfg.target,
        url,
        cfg,
        method=options.method,
        data=options.data,
        params=options.params,
        content_type=options.content_type,
    )
    host = data["subdomain"]
    _record_host(target_paths, host)
    sub = target_paths.sub(host).ensure()
    result.hosts = [host]

    state = State(target_paths)
    previous_run_id = str(state.data.get("updated_at") or "")
    state.update(host, params_endpoints=len(data.get("endpoints", [])), mode="single")

    ui.step(f"single-fuzz: {url}")
    ui.kv("target", cfg.target)
    ui.kv("vulns", ", ".join(cfg.vulns))
    ui.kv("endpoints", len(data.get("endpoints", [])))
    ui.kv("parameters", len(data.get("all_params", [])))

    jobs, template_stats = build_jobs(workspace, cfg.target, host, cfg)
    state.update(host, jobs=template_stats.jobs, templates=template_stats.as_dict())
    if not jobs:
        ui.warn(
            "no fuzz jobs generated — the URL may have no parameters and no "
            "header-based vulnerability selected"
        )

    if jobs:
        try:
            engine_stats, _store = fuzz_engine.run_fuzz(cfg, sub, jobs)
            state.update(host, fuzz=engine_stats.as_dict())
        except KeyboardInterrupt:
            state.update(host, status="interrupted")
            raise

    if not options.skip_nuclei:
        nuclei_stats = run_nuclei(workspace, cfg.target, host, cfg, settings)
        state.update(host, nuclei=nuclei_stats.as_dict())

    if jobs and not options.keep_templates:
        remove_templates(sub)

    total = _count_findings(sub)
    state.mark_done(host, findings=total, mode="single")
    result.findings = total
    result.elapsed = time.monotonic() - started

    _print_findings(sub)
    aggregate(workspace, cfg.target, cfg.output.get("formats"))
    _send_notifications(
        cfg,
        target_paths,
        previous_findings,
        previous_hosts,
        previous_run_id,
    )
    ui.ok(f"single-fuzz finished in {result.elapsed:.1f}s — {total} finding(s)")
    return result


def _print_findings(sub: SubPaths, limit: int = 100) -> None:
    if not sub.hits_file.is_file():
        return
    lines = sub.hits_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    if not lines:
        return
    ui.step(f"findings ({len(lines)})")
    for line in lines[:limit]:
        print("  " + line)
    if len(lines) > limit:
        ui.info(f"… {len(lines) - limit} more line(s) in {sub.hits_file}")
