"""Active crawling with Katana.

Katana is executed in JSONL mode so that ReconX can capture method, request
body, content type and extracted forms — not just URLs.  This is what enables
POST/JSON parameter fuzzing later in the pipeline.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import tempfile
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from core import ui
from core.config_loader import tool_path, tool_timeout
from core.models import TargetConfig
from core.paths import SubPaths, TargetPaths, Workspace
from core.process import ProcResult, run_to_file, which
from core.recon.urls import (
    DEFAULT_STATIC_EXTENSIONS,
    hostname,
    normalize_url,
    parse_host,
    should_keep_url,
)

KATANA_REQUIRED_FLAGS = ["-jsonl", "-silent", "-nc"]
DEFAULT_KATANA_REQUEST_TIMEOUT = 15
DEFAULT_MAX_SEEDS = 120
#: Kill a host when katana has emitted nothing for this long.  A single
#: response that keeps streaming (SSE, long-poll, chunked video) never trips
#: katana's own -timeout, so the crawler can sit there indefinitely.
DEFAULT_KATANA_STALL_TIMEOUT = 120
#: Hard cap on captured JSONL per host.  Crawler traps (infinite pagination,
#: calendar-style URLs) otherwise write gigabytes and exhaust RAM when parsed.
DEFAULT_KATANA_MAX_OUTPUT_MB = 50


class CrawlInterrupted(Exception):
    """Raised when SIGTERM arrives while a crawl is running."""


def _install_sigterm_handler():
    """Install a SIGTERM handler; return the previous handler or ``None``."""
    if threading.current_thread() is not threading.main_thread():
        return None
    try:
        previous = signal.getsignal(signal.SIGTERM)

        def _handler(signum, frame):  # noqa: ARG001
            raise CrawlInterrupted(f"signal {signum}")

        signal.signal(signal.SIGTERM, _handler)
        return previous
    except (AttributeError, ValueError, OSError):
        return None


def _restore_sigterm_handler(previous) -> None:
    if previous is None:
        return
    try:
        signal.signal(signal.SIGTERM, previous)
    except (TypeError, ValueError, OSError):
        pass


def _interrupt_context(host: str) -> str:
    """Describe the process context that received the signal."""
    try:
        ppid = os.getppid()
        sid = os.getsid(0)
        pgid = os.getpgid(0)
    except (AttributeError, OSError):
        return f"{host}: SIGTERM received"
    parent = ""
    try:
        with open(f"/proc/{ppid}/cmdline", "rb") as handle:
            parent = handle.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        pass
    return (
        f"{host}: SIGTERM received (ppid={ppid} sid={sid} pgid={pgid}"
        + (f" parent={parent}" if parent else "")
        + ")"
    )


def _seed_key(url: str) -> tuple[str, str, str]:
    parts = urlsplit(url)
    return (parts.scheme, parts.netloc, parts.path.rstrip("/") or "/")


def _prioritise_seeds(seeds: list[str], limit: int) -> list[str]:
    """Deduplicate by path (preferring query variants), then cap."""
    best: dict[tuple[str, str, str], str] = {}
    for url in seeds:
        key = _seed_key(url)
        current = best.get(key)
        if current is None:
            best[key] = url
        elif not urlsplit(current).query and urlsplit(url).query:
            # Keep the representative that carries a query string.
            best[key] = url

    def score(url: str) -> tuple[int, int, int]:
        parts = urlsplit(url)
        return (
            0 if parts.query else 1,
            parts.path.rstrip("/").count("/"),
            len(parts.path),
        )

    ordered = sorted(best.values(), key=score)
    if limit > 0:
        ordered = ordered[:limit]
    return ordered


def seed_limit(settings: dict, options: "ActiveOptions") -> int:
    if options.max_seeds is not None:
        return max(0, int(options.max_seeds))
    try:
        value = (settings.get("defaults") or {}).get("max_seeds", DEFAULT_MAX_SEEDS)
        return max(0, int(value))
    except (TypeError, ValueError):
        return DEFAULT_MAX_SEEDS


def host_resolves(host: str) -> bool:
    """Best-effort DNS check used to skip dead subdomains quickly."""
    name = host.split(":")[0].strip("[]")
    if not name:
        return False
    try:
        socket.getaddrinfo(name, None)
        return True
    except socket.gaierror as exc:
        # Only treat "name does not exist" as fatal; transient resolver errors
        # (EAI_AGAIN and friends) should still be crawled.
        missing = {
            getattr(socket, "EAI_NONAME", -2),
            getattr(socket, "EAI_NODATA", -5),
        }
        return exc.errno not in missing
    except OSError:
        return True


@dataclass
class ActiveOptions:
    depth: int = 3
    refresh: bool = False
    timeout: float | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    max_seeds: int | None = None
    automatic_form_fill: bool = True
    js_crawl: bool = True


@dataclass
class ActiveStats:
    host: str
    urls: int = 0
    requests: int = 0
    forms: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "urls": self.urls,
            "requests": self.requests,
            "forms": self.forms,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _lower_headers(raw) -> dict[str, str]:
    headers: dict[str, str] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            headers[str(key).lower()] = str(value)
    return headers


def _field_names(fields) -> list[str]:
    names: list[str] = []
    if isinstance(fields, dict):
        names.extend(str(k) for k in fields)
    elif isinstance(fields, (list, tuple)):
        for item in fields:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("key") or item.get("id")
                if name:
                    names.append(str(name))
    return list(dict.fromkeys(n for n in names if n))


def _normalise_forms(raw, endpoint: str) -> list[dict]:
    if raw is None:
        return []
    forms = raw if isinstance(raw, list) else [raw]
    result: list[dict] = []
    for form in forms:
        if not isinstance(form, dict):
            continue
        action = form.get("action") or form.get("url") or form.get("endpoint") or endpoint
        method = str(form.get("method") or "GET").upper()
        fields = (
            form.get("fields")
            or form.get("inputs")
            or form.get("parameters")
            or form.get("form_fields")
        )
        names = _field_names(fields)
        try:
            action = urljoin(endpoint, str(action))
        except Exception:
            action = str(action)
        if not names:
            continue
        result.append({"action": action, "method": method, "fields": names})
    return result


def _normalise_record(record: dict, fallback_url: str = "") -> dict | None:
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    response = record.get("response") if isinstance(record.get("response"), dict) else {}

    endpoint = (
        request.get("endpoint")
        or request.get("url")
        or record.get("url")
        or record.get("endpoint")
        or fallback_url
    )
    if not endpoint:
        return None
    endpoint = normalize_url(str(endpoint))
    if not endpoint:
        return None

    method = str(request.get("method") or record.get("method") or "GET").upper()
    body = request.get("body") or record.get("body") or ""
    if not isinstance(body, str):
        body = str(body)
    body = body[:20000]
    headers = _lower_headers(request.get("headers") or record.get("headers"))

    forms: list[dict] = []
    for candidate in (
        record.get("form"),
        record.get("forms"),
        response.get("form"),
        response.get("forms"),
        (record.get("knowledgebase") or {}).get("Forms")
        if isinstance(record.get("knowledgebase"), dict)
        else None,
    ):
        forms.extend(_normalise_forms(candidate, endpoint))

    return {
        "url": endpoint,
        "method": method,
        "body": body,
        "headers": headers,
        "status": response.get("status_code") or record.get("status_code") or 0,
        "content_type": headers.get("content-type", ""),
        "forms": forms,
    }


def _parse_katana_line(
    line: str,
    records: list[dict],
    plain: list[str],
    errors: list[str],
    seen: set[tuple],
) -> None:
    line = line.strip()
    if not line:
        return
    if line.startswith("{"):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            errors.append("katana emitted invalid JSON")
            return
        if not isinstance(parsed, dict):
            return
        record = _normalise_record(parsed)
        if not record:
            return
        key = (record["url"], record["method"], record["body"])
        if key in seen:
            return
        seen.add(key)
        records.append(record)
    elif line.startswith("http://") or line.startswith("https://"):
        plain.append(line)


def _parse_katana_output(stdout: str) -> tuple[list[dict], list[str], list[str]]:
    """Return ``(records, plain_urls, errors)`` from katana stdout."""
    records: list[dict] = []
    plain: list[str] = []
    errors: list[str] = []
    seen: set[tuple] = set()

    for raw_line in stdout.splitlines():
        _parse_katana_line(raw_line, records, plain, errors, seen)

    return records, plain, errors


def _parse_katana_file(path: str) -> tuple[list[dict], list[str], list[str]]:
    """Like :func:`_parse_katana_output`, reading incrementally from *path*."""
    records: list[dict] = []
    plain: list[str] = []
    errors: list[str] = []
    seen: set[tuple] = set()

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            _parse_katana_line(raw_line, records, plain, errors, seen)

    return records, plain, errors


# ---------------------------------------------------------------------------
# Crawling
# ---------------------------------------------------------------------------

def katana_request_timeout(settings: dict, cfg: TargetConfig) -> int:
    """Per-request crawl timeout, capped by the target's HTTP timeout."""
    configured = int(tool_timeout(settings, "katana_request", DEFAULT_KATANA_REQUEST_TIMEOUT))
    return max(3, min(int(cfg.timeout), configured))


def katana_stall_timeout(settings: dict) -> float:
    """Seconds without new output before a crawl is considered hung."""
    try:
        value = tool_timeout(settings, "katana_stall", DEFAULT_KATANA_STALL_TIMEOUT)
    except (TypeError, ValueError):
        return float(DEFAULT_KATANA_STALL_TIMEOUT)
    return max(0.0, float(value))


def katana_max_output_bytes(settings: dict) -> int:
    """Byte cap for the per-host JSONL capture (0 disables the cap)."""
    try:
        value = (settings.get("katana") or {}).get(
            "max_output_mb", DEFAULT_KATANA_MAX_OUTPUT_MB
        )
        megabytes = float(value)
    except (TypeError, ValueError):
        megabytes = float(DEFAULT_KATANA_MAX_OUTPUT_MB)
    return max(0, int(megabytes * 1048576))


def _build_katana_command(
    host: str,
    settings: dict,
    cfg: TargetConfig,
    options: ActiveOptions,
) -> list[str]:
    tool = tool_path(settings, "katana")
    extensions = cfg.exclude_extensions or [e.lstrip(".") for e in DEFAULT_STATIC_EXTENSIONS]
    cmd = [
        tool,
        *KATANA_REQUIRED_FLAGS,
        "-or",                       # omit raw request/response blobs
        "-ob",                       # omit response bodies (huge, unused here)
        "-fx",                       # extract form fields into JSONL
    ]
    if options.js_crawl:
        cmd.extend(["-jc", "-jsl"])  # crawl JS endpoints / jsluice parsing
    cmd.extend(
        [
            "-kf", "all",            # robots.txt / sitemap.xml
        ]
    )
    if options.automatic_form_fill:
        cmd.append("-aff")           # automatic form filling
    cmd.extend(
        [
            "-fs", "fqdn",           # scope to this exact subdomain
            "-d", str(max(1, options.depth)),
            "-timeout", str(katana_request_timeout(settings, cfg)),
            "-rl", str(cfg.rl),
            "-c", str(cfg.c),
            "-ef", ",".join(e.lstrip(".") for e in extensions),
        ]
    )
    if cfg.proxy:
        cmd.extend(["-proxy", cfg.proxy])
    for key, value in {**cfg.headers, **options.extra_headers}.items():
        cmd.extend(["-H", f"{key}: {value}"])

    # Optional katana-side budgets.  These flags are only recent releases, so
    # they are omitted unless the operator opts in via settings.yaml.
    katana_cfg = settings.get("katana") or {}
    duration = str(katana_cfg.get("crawl_duration") or "").strip()
    if duration:
        cmd.extend(["-ct", duration])
    try:
        max_pages = int(katana_cfg.get("max_pages") or 0)
    except (TypeError, ValueError):
        max_pages = 0
    if max_pages > 0:
        cmd.extend(["-mdp", str(max_pages)])
    return cmd


def crawl_host(
    target_paths: TargetPaths,
    host: str,
    settings: dict,
    cfg: TargetConfig,
    options: ActiveOptions | None = None,
) -> ActiveStats:
    """Crawl one subdomain and persist URLs + structured requests."""
    options = options or ActiveOptions()
    sub: SubPaths = target_paths.sub(host).ensure()
    stats = ActiveStats(host=host)

    seeds: list[str] = []
    if sub.passive_file.is_file():
        with open(sub.passive_file, "r", encoding="utf-8", errors="replace") as handle:
            seeds = [line.strip() for line in handle if line.strip()]
    if not seeds:
        seeds = [f"https://{host}/"]

    if (
        not options.refresh
        and sub.katana_file.is_file()
        and sub.katana_file.stat().st_size > 0
    ):
        with open(sub.katana_file, "r", encoding="utf-8", errors="replace") as handle:
            count = sum(1 for line in handle if line.strip())
        stats.urls = count
        stats.requests = (
            sum(1 for _ in open(sub.katana_requests_file, encoding="utf-8", errors="replace"))
            if sub.katana_requests_file.is_file()
            else 0
        )
        ui.info(f"{host}: reusing existing katana results ({count} URLs)")
        return stats

    tool = tool_path(settings, "katana")
    if not which(tool):
        stats.errors.append("katana not found on PATH")
        ui.warn("katana is not installed — skipping active crawl (run ./reconx doctor)")
        return stats

    if not cfg.proxy and not host_resolves(host):
        message = f"{host} does not resolve (DNS) — skipping crawl"
        stats.errors.append(message)
        ui.warn(message)
        return stats

    total_seeds = len(seeds)
    seeds = _prioritise_seeds(seeds, seed_limit(settings, options))
    seed_label = f"{len(seeds)} seed URL(s)"
    if len(seeds) != total_seeds:
        seed_label = f"{len(seeds)}/{total_seeds} seed URL(s)"

    ui.info(
        f"katana       {ui.colorize(host, ui.CYAN)} "
        f"({seed_label}, depth {options.depth})"
    )
    cmd = _build_katana_command(host, settings, cfg, options)
    fd, tmp_path = tempfile.mkstemp(prefix="reconx-katana-", suffix=".jsonl")
    os.close(fd)
    stop = threading.Event()
    stall_timeout = katana_stall_timeout(settings)
    max_output = katana_max_output_bytes(settings)

    def _progress() -> None:
        last_size = -1
        last_change = time.monotonic()
        while not stop.wait(15):
            try:
                size = os.path.getsize(tmp_path)
            except OSError:
                continue
            now = time.monotonic()
            if size != last_size:
                last_size = size
                last_change = now
            idle = now - last_change
            suffix = f" — no new output for {int(idle)}s" if idle >= 30 else ""
            ui.info(f"{host}: crawling ... {size / 1048576:.1f} MB captured{suffix}")

    progress = threading.Thread(target=_progress, daemon=True)
    progress.start()
    previous_handler = _install_sigterm_handler()
    interrupted = False
    try:
        try:
            result = run_to_file(
                cmd,
                tmp_path,
                input_text="\n".join(seeds) + "\n",
                timeout=options.timeout or tool_timeout(settings, "katana", 900),
                stall_timeout=stall_timeout,
                max_output_bytes=max_output,
            )
        except CrawlInterrupted:
            interrupted = True
            result = ProcResult(
                args=cmd,
                returncode=143,
                stderr="terminated by SIGTERM",
            )
        except KeyboardInterrupt:
            # Keep whatever katana already wrote instead of throwing the whole
            # host away; the interrupt is re-raised after the results are saved.
            interrupted = True
            result = ProcResult(
                args=cmd,
                returncode=130,
                stderr="interrupted by user",
            )
    finally:
        stop.set()
        _restore_sigterm_handler(previous_handler)

    try:
        captured = os.path.getsize(tmp_path)
    except OSError:
        captured = 0

    try:
        records, plain_urls, parse_errors = _parse_katana_file(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    stats.errors.extend(parse_errors)

    if result.stalled:
        reason = (
            f"capture limit of {max_output / 1048576:.0f} MB reached"
            if max_output and captured >= max_output
            else f"no new output for {stall_timeout:.0f}s"
        )
        message = (
            f"{host}: katana stopped making progress ({reason}) — "
            "killed it and kept the partial results"
        )
        stats.errors.append(message)
        ui.warn(message)
    elif result.timed_out:
        stats.errors.append("katana timed out")
        ui.warn("katana timed out — results captured so far will still be used")
    if result.returncode not in (0, 124, 130, 143) and captured == 0:
        detail = (result.stderr or "").strip().splitlines()
        message = f"katana failed (rc={result.returncode}): {detail[-1] if detail else 'unknown error'}"
        stats.errors.append(message)
        ui.warn(message)

    host_only = parse_host(host).split(":")[0]
    urls: set[str] = {normalize_url(f"https://{host}/") or f"https://{host}/"}
    extensions = cfg.exclude_extensions or [e.lstrip(".") for e in DEFAULT_STATIC_EXTENSIONS]

    for url in plain_urls:
        normalized = normalize_url(url)
        if normalized and hostname(normalized) == host_only and should_keep_url(normalized, extensions=["." + e.lstrip(".") for e in extensions]):
            urls.add(normalized)

    clean_records: list[dict] = []
    for record in records:
        url = record["url"]
        if hostname(url) != host_only:
            continue
        if not should_keep_url(url, extensions=["." + e.lstrip(".") for e in extensions]):
            continue
        urls.add(url)
        clean_records.append(record)
        stats.forms += len(record.get("forms") or [])

    with open(sub.katana_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(sorted(urls)) + "\n")
    with open(sub.katana_requests_file, "w", encoding="utf-8") as handle:
        for record in clean_records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    stats.urls = len(urls)
    stats.requests = len(clean_records)
    if interrupted:
        if result.returncode == 130:
            note = f"{host}: interrupted by user"
            code = 130
        else:
            note = _interrupt_context(host)
            code = 143
        stats.errors.append(note)
        ui.warn(f"{note} — partial crawl results saved")
        raise SystemExit(code)
    if stats.requests:
        ui.ok(
            f"{host}: {stats.urls} URL(s), {stats.requests} structured request(s), "
            f"{stats.forms} form(s)"
        )
    else:
        ui.warn(
            f"{host}: no crawlable URLs — the site may be empty, blocking the "
            "crawler, or all seeds returned errors"
        )
    return stats


def run_active(
    workspace: Workspace,
    target: str,
    settings: dict,
    cfg: TargetConfig,
    options: ActiveOptions | None = None,
) -> list[ActiveStats]:
    """Crawl every subdomain directory that has a passive URL file."""
    options = options or ActiveOptions()
    target_paths = workspace.target(target)
    if not target_paths.subdomains.is_dir():
        raise ValueError(
            f"no recon data for target '{target}' — run './reconx passive' first"
        )

    hosts = target_paths.hosts()
    if cfg.sub:
        hosts = [cfg.sub] if cfg.sub in hosts else []
    if not hosts:
        raise ValueError("no subdomain directories to crawl")

    results: list[ActiveStats] = []
    for host in hosts:
        results.append(crawl_host(target_paths, host, settings, cfg, options))

    return results
