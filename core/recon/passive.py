"""Passive reconnaissance with waybackurls, gau and uro.

The module behaves like the original ``nice_passive.py`` script but adds:

* per-subdomain routing of discovered URLs (a root scan can populate several
  subdomain directories),
* strict URL normalisation / static-asset filtering in Python,
* graceful handling of missing tools and timeouts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core import ui
from core.config_loader import tool_path, tool_timeout
from core.models import TargetConfig
from core.paths import SubPaths, TargetPaths, Workspace
from core.process import ProcResult, run, which
from core.recon.urls import (
    DEFAULT_STATIC_EXTENSIONS,
    normalize_url,
    parse_host,
    root_domain_guess,
    should_keep_url,
)

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)


@dataclass
class PassiveOptions:
    wayback: bool = True
    gau: bool = True
    use_uro: bool = True
    enumerate: bool = False
    subdomains_file: str = ""
    max_hosts: int = 500
    refresh: bool = True


@dataclass
class PassiveStats:
    hosts: list[str] = field(default_factory=list)
    urls: int = 0
    per_host: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "hosts": self.hosts,
            "urls": self.urls,
            "per_host": self.per_host,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extensions(cfg: TargetConfig) -> list[str]:
    exts = cfg.exclude_extensions or [e.lstrip(".") for e in DEFAULT_STATIC_EXTENSIONS]
    return ["." + e.lstrip(".") for e in exts]


def _scope(cfg: TargetConfig, seed_host: str) -> list[str]:
    return cfg.scope_domains or [root_domain_guess(seed_host)]


def _read_subdomain_file(path: str) -> list[str]:
    hosts: list[str] = []
    if not path:
        return hosts
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                host = parse_host(line.strip())
                if host:
                    hosts.append(host)
    except OSError as exc:
        ui.warn(f"cannot read subdomain file {path}: {exc}")
    return hosts


def _valid_host(host: str) -> bool:
    host = host.split(":")[0]
    return bool(_HOST_RE.match(host)) or host in {"localhost", "127.0.0.1"}


def enumerate_subdomains(root: str, settings: dict, cfg: TargetConfig) -> list[str]:
    """Run subfinder (when available) and return in-scope subdomains."""
    tool = tool_path(settings, "subfinder")
    if not which(tool):
        ui.warn("subfinder not found — skipping subdomain enumeration")
        return []

    root = root_domain_guess(root)
    ui.info(f"Enumerating subdomains for {ui.colorize(root, ui.CYAN)} with subfinder")
    result = run(
        [tool, "-d", root, "-silent", "-nc"],
        timeout=tool_timeout(settings, "subfinder", 180),
    )
    if result.missing:
        ui.warn("subfinder is not installed")
        return []
    if result.timed_out:
        ui.warn("subfinder timed out")
    hosts: list[str] = []
    for line in result.stdout.splitlines():
        host = parse_host(line.strip())
        if host and _valid_host(host) and host not in hosts:
            hosts.append(host)
    ui.ok(f"subfinder found {len(hosts)} subdomain(s)")
    return hosts


def _tool_output(
    name: str,
    command: str,
    args: list[str],
    *,
    input_text: str | None,
    settings: dict,
) -> tuple[list[str], str | None]:
    """Run one passive tool, returning ``(lines, error)``."""
    if not which(command):
        return [], f"{name} not found on PATH"
    result: ProcResult = run(
        [command, *args],
        input_text=input_text,
        timeout=tool_timeout(settings, name, 240),
    )
    if result.timed_out:
        return result.stdout.splitlines(), f"{name} timed out"
    if result.returncode == 127:
        return [], f"{name} not found"
    if result.returncode != 0 and not result.stdout.strip():
        detail = (result.stderr or "").strip().splitlines()
        return [], f"{name} failed (rc={result.returncode}): {detail[-1] if detail else 'unknown error'}"
    return result.stdout.splitlines(), None


def _apply_uro(lines: list[str], settings: dict) -> list[str]:
    tool = tool_path(settings, "uro")
    if not lines or not which(tool):
        return lines
    ui.debug(f"running uro on {len(lines)} line(s)")
    result = run([tool], input_text="\n".join(lines) + "\n", timeout=tool_timeout(settings, "uro", 120))
    if result.ok and result.stdout.strip():
        return result.stdout.splitlines()
    return lines


def _write_urls(sub: SubPaths, urls: list[str]) -> int:
    sub.ensure()
    clean = sorted({u for u in urls if u})
    if clean:
        with open(sub.passive_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(clean) + "\n")
    elif sub.passive_file.exists():
        # Do not destroy a previous run's results on a failed refresh.
        with open(sub.passive_file, "r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    return len(clean)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_passive(
    workspace: Workspace,
    target: str,
    hosts: list[str],
    settings: dict,
    cfg: TargetConfig,
    options: PassiveOptions | None = None,
) -> PassiveStats:
    """Collect passive URLs for *hosts* and write per-host ``.passive`` files."""
    options = options or PassiveOptions()
    target_paths: TargetPaths = workspace.target(target).ensure()
    stats = PassiveStats()

    # Build the host list: seeds + enumeration + existing file.
    requested: list[str] = []
    for host in hosts:
        host = parse_host(host)
        if host and host not in requested and _valid_host(host):
            requested.append(host)

    if not requested:
        raise ValueError("no valid host supplied for passive recon")

    seed_host = requested[0]
    if options.subdomains_file:
        for host in _read_subdomain_file(options.subdomains_file):
            if host not in requested and _valid_host(host):
                requested.append(host)
    if target_paths.subdomains_file.is_file():
        for host in _read_subdomain_file(str(target_paths.subdomains_file)):
            if host not in requested and _valid_host(host):
                requested.append(host)
    if options.enumerate:
        for host in enumerate_subdomains(seed_host, settings, cfg):
            if host not in requested and _valid_host(host):
                requested.append(host)

    requested = requested[: options.max_hosts]
    stats.hosts = list(requested)

    scope = _scope(cfg, seed_host)
    extensions = _extensions(cfg)
    buckets: dict[str, set[str]] = {host: set() for host in requested}
    for host in requested:
        buckets[host].add(f"https://{host}/")

    def collect(host: str) -> None:
        raw_lines: list[str] = []

        if options.wayback:
            ui.info(f"waybackurls  {ui.colorize(host, ui.CYAN)}")
            lines, err = _tool_output(
                "waybackurls",
                tool_path(settings, "waybackurls"),
                [],
                input_text=f"{host}\n",
                settings=settings,
            )
            raw_lines.extend(lines)
            if err:
                stats.errors.append(err)
                ui.warn(err)

        if options.gau:
            ui.info(f"gau          {ui.colorize(host, ui.CYAN)}")
            lines, err = _tool_output(
                "gau",
                tool_path(settings, "gau"),
                [host, "--threads", "1", "--subs"],
                input_text=None,
                settings=settings,
            )
            raw_lines.extend(lines)
            if err:
                stats.errors.append(err)
                ui.warn(err)

        if options.use_uro:
            raw_lines = _apply_uro(raw_lines, settings)

        kept = 0
        for line in raw_lines:
            for candidate in line.replace("\t", " ").split():
                url = normalize_url(candidate)
                if not url:
                    continue
                if not should_keep_url(url, extensions=extensions, exclude_patterns=[]):
                    continue
                url_host = parse_host(url)
                if not url_host:
                    continue
                if not _host_in_scope(url_host, scope):
                    continue
                buckets.setdefault(url_host, set()).add(url)
                kept += 1
        ui.debug(f"{host}: {kept} usable URL(s) before deduplication")

    for host in requested:
        collect(host)

    # Write every bucket (requested hosts and in-scope hosts discovered by gau --subs).
    for host, urls in sorted(buckets.items()):
        if not _host_in_scope(host, scope):
            continue
        sub = target_paths.sub(host)
        count = _write_urls(sub, list(urls))
        stats.per_host[host] = count
        stats.urls += count
        if host not in stats.hosts:
            stats.hosts.append(host)
        if count:
            ui.ok(f"{host}: {count} passive URL(s) -> {sub.passive_file}")

    # Persist the host inventory for later commands.
    inventory = sorted({*stats.hosts, *buckets.keys()})
    with open(target_paths.subdomains_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(inventory) + "\n")

    if stats.errors:
        ui.warn(f"passive recon finished with {len(stats.errors)} warning(s)")
    return stats


def _host_in_scope(host: str, scope: list[str]) -> bool:
    host = host.split(":")[0].lower()
    for domain in scope:
        domain = domain.lower().lstrip(".").rstrip(".")
        if host == domain or host.endswith("." + domain):
            return True
    return False
