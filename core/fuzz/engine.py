"""Concurrent HTTP fuzzing engine.

Design notes
------------
* ``requests`` is imported lazily so ``reconx --help`` works before installing
  the Python dependencies.
* A thread-local ``requests.Session`` per worker reuses connections.
* A global token-bucket rate limiter enforces the configured requests/second.
* Every job gets a clean baseline request; detectors compare against it.
* Time-based SQLi jobs run serially to keep latency measurements meaningful.
"""

from __future__ import annotations

import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from core import ui
from core.fuzz.detectors import detect
from core.fuzz.payloads import load_payloads, parse_header
from core.fuzz.store import FindingStore
from core.models import Finding, FuzzJob, HttpResult, TargetConfig
from core.paths import SubPaths

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 ReconX/2.0"
)


@dataclass
class EngineStats:
    requests: int = 0
    findings: int = 0
    errors: int = 0
    skipped_jobs: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "findings": self.findings,
            "errors": self.errors,
            "skipped_jobs": self.skipped_jobs,
            "elapsed_seconds": round(self.elapsed, 2),
        }


class RateLimiter:
    """Simple global rate limiter (requests per second)."""

    def __init__(self, rate: int):
        self.interval = 1.0 / max(1, int(rate))
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self._next < now:
                self._next = now
            delay = self._next - now
            self._next += self.interval
        if delay > 0:
            time.sleep(delay)


class HttpClient:
    """Small wrapper around ``requests`` with per-thread sessions."""

    def __init__(self, cfg: TargetConfig):
        try:
            import requests  # noqa: F401
            from requests.adapters import HTTPAdapter  # noqa: F401
        except ImportError as exc:  # pragma: no cover - install-time guidance
            raise RuntimeError(
                "the 'requests' package is required for fuzzing; "
                "run: pip install -r requirements.txt"
            ) from exc

        self.cfg = cfg
        self._local = threading.local()
        self._adapter_cls = HTTPAdapter
        self._requests = requests
        self._proxies = (
            {"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else {}
        )
        self._default_headers = {
            "User-Agent": cfg.user_agent or DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            **cfg.headers,
        }
        if not cfg.verify_tls:
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    def _session(self):
        session = getattr(self._local, "session", None)
        if session is not None:
            return session
        session = self._requests.Session()
        session.headers.update(self._default_headers)
        session.verify = self.cfg.verify_tls
        if self._proxies:
            session.proxies.update(self._proxies)
        adapter = self._adapter_cls(
            pool_connections=max(10, self.cfg.c),
            pool_maxsize=max(10, self.cfg.c),
            max_retries=0,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        return session

    # -- rendering -------------------------------------------------------
    def build_kwargs(self, job: FuzzJob, payload: str | None) -> tuple[str, dict[str, Any]] | None:
        """Return ``(method, kwargs)`` for *payload* (or the baseline)."""
        if job.location == "header":
            if payload is None:
                return job.method.upper(), {}
            parsed = parse_header(payload)
            if not parsed:
                return None
            name, value = parsed
            return job.method.upper(), {"headers": {name: value}}

        values = dict(job.samples)
        for name in job.params:
            values.setdefault(name, "1")
            if payload is not None:
                values[name] = payload

        if job.location == "query":
            pairs = list(values.items())
            return job.method.upper(), {"params": pairs}

        content_type = (job.content_type or "urlencoded").lower()
        if "json" in content_type:
            return job.method.upper(), {"json": values}
        if "multipart" in content_type:
            files = {name: (None, value) for name, value in values.items()}
            return job.method.upper(), {"files": files}
        return job.method.upper(), {"data": list(values.items())}

    # -- request ---------------------------------------------------------
    def request(self, job: FuzzJob, payload: str | None) -> HttpResult:
        built = self.build_kwargs(job, payload)
        if built is None:
            return HttpResult(ok=False, url=job.url, method=job.method, error="invalid payload")
        method, kwargs = built
        session = self._session()
        timeout = (min(15, self.cfg.timeout), self.cfg.timeout)
        # Open-redirect analysis needs the raw Location header, so redirects
        # are never followed for that class regardless of configuration.
        follow = self.cfg.follow_redirects and job.vuln != "open-redirect"
        start = time.perf_counter()
        try:
            response = session.request(
                method,
                job.url,
                timeout=timeout,
                allow_redirects=follow,
                **kwargs,
            )
            elapsed = time.perf_counter() - start
        except self._requests.exceptions.Timeout:
            return HttpResult(
                ok=False,
                url=job.url,
                method=method,
                elapsed=time.perf_counter() - start,
                error="timeout",
            )
        except self._requests.exceptions.RequestException as exc:
            return HttpResult(
                ok=False,
                url=job.url,
                method=method,
                elapsed=time.perf_counter() - start,
                error=str(exc)[:300],
            )
        except Exception as exc:  # pragma: no cover - defensive
            return HttpResult(
                ok=False,
                url=job.url,
                method=method,
                elapsed=time.perf_counter() - start,
                error=str(exc)[:300],
            )

        raw = response.content[: self.cfg.max_response_bytes]
        encoding = response.encoding or "utf-8"
        try:
            body = raw.decode(encoding, errors="replace")
        except LookupError:
            body = raw.decode("utf-8", errors="replace")

        prepared = response.request
        request_body = prepared.body if prepared is not None else None
        if isinstance(request_body, bytes):
            request_body = request_body.decode("utf-8", errors="replace")

        return HttpResult(
            ok=True,
            status=response.status_code,
            headers={str(k).lower(): str(v) for k, v in response.headers.items()},
            body=body,
            elapsed=elapsed,
            url=response.url,
            method=method,
            request_headers={
                str(k): str(v) for k, v in (prepared.headers.items() if prepared else [])
            },
            request_body=str(request_body)[:8000] if request_body is not None else None,
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class FuzzRunner:
    def __init__(
        self,
        cfg: TargetConfig,
        sub: SubPaths,
        store: FindingStore,
        *,
        client: HttpClient | None = None,
    ):
        self.cfg = cfg
        self.sub = sub
        self.store = store
        self.client = client or HttpClient(cfg)
        self.limiter = RateLimiter(cfg.rl)
        self.stats = EngineStats()
        self._stats_lock = threading.Lock()
        self._baseline_cache: dict[tuple, HttpResult] = {}

    # -- baseline --------------------------------------------------------
    def _baseline_key(self, job: FuzzJob) -> tuple:
        return (
            job.url,
            job.method.upper(),
            job.location,
            job.content_type or "",
            tuple(sorted(job.samples.items())),
            tuple(job.params),
        )

    def _baseline(self, job: FuzzJob) -> HttpResult:
        key = self._baseline_key(job)
        cached = self._baseline_cache.get(key)
        if cached is not None:
            return cached

        results: list[HttpResult] = []
        for _ in range(max(1, self.cfg.baseline_samples)):
            self.limiter.wait()
            result = self.client.request(job, None)
            self._count_request(result.ok)
            if not result.ok:
                break
            results.append(result)

        if not results:
            baseline = HttpResult(ok=False, url=job.url, method=job.method, error="baseline failed")
        else:
            baseline = results[-1]
            if len(results) > 1:
                baseline.elapsed = statistics.median(r.elapsed for r in results)
        self._baseline_cache[key] = baseline
        return baseline

    # -- accounting ------------------------------------------------------
    def _count_request(self, ok: bool) -> None:
        with self._stats_lock:
            self.stats.requests += 1
            if not ok:
                self.stats.errors += 1

    def _record(self, job: FuzzJob, payload: str, baseline: HttpResult, result: HttpResult) -> Finding | None:
        finding = detect(job, payload, baseline, result, self.cfg)
        if not finding:
            return None
        added = self.store.add(finding)
        if added:
            with self._stats_lock:
                self.stats.findings += 1
            ui.ok(
                f"{ui.colorize(finding.vuln.upper(), ui.GREEN)} "
                f"{finding.url} "
                f"{('param=' + finding.param) if finding.param else ''} "
                f"[{finding.confidence}/{finding.severity}]"
            )
        return finding if added else None

    # -- one payload -----------------------------------------------------
    def _run_payload(self, job: FuzzJob, payload: str, baseline: HttpResult) -> Finding | None:
        self.limiter.wait()
        result = self.client.request(job, payload)
        self._count_request(result.ok)
        if not result.ok:
            ui.debug(f"{job.vuln}: {job.url} -> {result.error}")
            return None
        return self._record(job, payload, baseline, result)

    # -- one job ---------------------------------------------------------
    def run_job(self, job: FuzzJob, index: int, total: int) -> int:
        payloads = load_payloads(job.payload_file, self.cfg.max_payloads)
        if job.location == "header":
            payloads = [p for p in payloads if parse_header(p)]
        if not payloads:
            with self._stats_lock:
                self.stats.skipped_jobs += 1
            ui.warn(f"no usable payloads for {job.vuln} ({job.payload_file})")
            return 0

        ui.info(
            f"[{index}/{total}] {ui.colorize(job.vuln, ui.CYAN)} "
            f"{job.method} {job.url} "
            f"({len(payloads)} payload(s), param(s): {','.join(job.params) or '-'})"
        )

        baseline = self._baseline(job)
        if not baseline.ok and job.vuln in {"headers-status"}:
            with self._stats_lock:
                self.stats.skipped_jobs += 1
            ui.warn(f"baseline failed for {job.url} — skipping header-status job")
            return 0

        # Respect the global request budget.
        remaining = self.cfg.max_requests - self.stats.requests
        if remaining <= 0:
            with self._stats_lock:
                self.stats.skipped_jobs += 1
            ui.warn(f"request budget ({self.cfg.max_requests}) exhausted — stopping")
            return 0
        if len(payloads) > remaining:
            payloads = payloads[:remaining]

        hits = 0
        if job.serial:
            for payload in payloads:
                if self._run_payload(job, payload, baseline):
                    hits += 1
        else:
            workers = max(1, min(self.cfg.c, len(payloads)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._run_payload, job, payload, baseline): payload
                    for payload in payloads
                }
                try:
                    for future in as_completed(futures):
                        try:
                            if future.result():
                                hits += 1
                        except Exception as exc:  # pragma: no cover - defensive
                            ui.debug(f"worker error: {exc}")
                except KeyboardInterrupt:
                    for future in futures:
                        future.cancel()
                    raise

        return hits

    # -- all jobs --------------------------------------------------------
    def run(self, jobs: list[FuzzJob]) -> EngineStats:
        if not jobs:
            ui.warn(self.sub.host + ": no fuzz jobs to run")
            return self.stats

        ui.info(
            f"Fuzzing {ui.colorize(self.sub.host, ui.CYAN)} — "
            f"{len(jobs)} job(s), {self.cfg.rl} req/s, {self.cfg.c} worker(s)"
        )
        try:
            for index, job in enumerate(jobs, start=1):
                if self.stats.requests >= self.cfg.max_requests:
                    ui.warn("request budget exhausted")
                    break
                hits = self.run_job(job, index, len(jobs))
                if hits:
                    ui.info(f"  → {hits} finding(s) in this job")
        except KeyboardInterrupt:
            ui.warn("interrupted by user — partial results were saved")
            raise

        ui.ok(
            f"{self.sub.host}: {self.stats.findings} finding(s), "
            f"{self.stats.requests} request(s), {self.stats.errors} error(s), "
            f"{self.stats.elapsed:.1f}s"
        )
        return self.stats


def run_fuzz(
    cfg: TargetConfig,
    sub: SubPaths,
    jobs: list[FuzzJob],
) -> tuple[EngineStats, FindingStore]:
    """Convenience wrapper used by the pipeline."""
    store = FindingStore(sub, save_evidence=cfg.save_evidence)
    runner = FuzzRunner(cfg, sub, store)
    stats = runner.run(jobs)
    return stats, store
