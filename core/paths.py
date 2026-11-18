"""Filesystem layout for ReconX results.

Layout::

    results/<target>/
    ├── state.json
    ├── shared_params.json
    ├── subdomains.txt
    ├── subdomains/<host>/
    │   ├── <host>.passive
    │   ├── <host>.katana
    │   ├── <host>.katana.requests.jsonl
    │   ├── params.json
    │   ├── templates/
    │   ├── crawl-parametrized/
    │   └── fuzz/
    │       ├── findings.jsonl
    │       ├── hits.txt
    │       ├── nuclei.jsonl
    │       └── evidence/
    └── output/
        ├── <target>.txt
        ├── <target>.json
        └── <target>.html
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_SAFE_RE = re.compile(r"[^A-Za-z0-9._@-]+")


def safe_component(value: str) -> str:
    """Return a filesystem-safe version of *value*.

    Hostnames (including ``host:port``) and target names are accepted.  Path
    separators and control characters are replaced so a malicious config can
    never escape the results directory.
    """
    value = (value or "").strip().replace(":", "_")
    value = _SAFE_RE.sub("_", value)
    value = value.strip("._") or "unnamed"
    return value[:120]


def project_root() -> Path:
    """Absolute path to the repository root."""
    return Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class TargetPaths:
    """Resolved paths for one target."""

    name: str
    root: Path

    @property
    def subdomains(self) -> Path:
        return self.root / "subdomains"

    @property
    def output(self) -> Path:
        return self.root / "output"

    @property
    def state_file(self) -> Path:
        return self.root / "state.json"

    @property
    def shared_params_file(self) -> Path:
        return self.root / "shared_params.json"

    @property
    def subdomains_file(self) -> Path:
        return self.root / "subdomains.txt"

    def sub(self, host: str) -> "SubPaths":
        return SubPaths(host=host, root=self.subdomains / safe_component(host))

    def ensure(self) -> "TargetPaths":
        self.root.mkdir(parents=True, exist_ok=True)
        self.subdomains.mkdir(parents=True, exist_ok=True)
        return self

    def hosts(self) -> list[str]:
        """Return subdomain directory names, sorted."""
        if not self.subdomains.is_dir():
            return []
        return sorted(
            p.name
            for p in self.subdomains.iterdir()
            if p.is_dir() and not p.name.startswith(".")
        )


@dataclass(frozen=True)
class SubPaths:
    """Resolved paths for one subdomain directory."""

    host: str
    root: Path

    @property
    def passive_file(self) -> Path:
        return self.root / f"{safe_component(self.host)}.passive"

    @property
    def katana_file(self) -> Path:
        return self.root / f"{safe_component(self.host)}.katana"

    @property
    def katana_requests_file(self) -> Path:
        return self.root / f"{safe_component(self.host)}.katana.requests.jsonl"

    @property
    def params_file(self) -> Path:
        return self.root / "params.json"

    @property
    def templates_dir(self) -> Path:
        return self.root / "templates"

    @property
    def crawl_dir(self) -> Path:
        return self.root / "crawl-parametrized"

    @property
    def crawl_urls_file(self) -> Path:
        return self.crawl_dir / "urls.txt"

    @property
    def crawl_targets_file(self) -> Path:
        return self.crawl_dir / "targets.txt"

    @property
    def fuzz_dir(self) -> Path:
        return self.root / "fuzz"

    @property
    def findings_file(self) -> Path:
        return self.fuzz_dir / "findings.jsonl"

    @property
    def hits_file(self) -> Path:
        return self.fuzz_dir / "hits.txt"

    @property
    def evidence_dir(self) -> Path:
        return self.fuzz_dir / "evidence"

    def ensure(self) -> "SubPaths":
        for directory in (self.root, self.crawl_dir, self.fuzz_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self


class Workspace:
    """Root workspace (the project's ``results`` directory by default)."""

    def __init__(self, results_dir: str | os.PathLike[str] | None = None):
        self.results = Path(results_dir) if results_dir else project_root() / "results"

    def target(self, name: str) -> TargetPaths:
        return TargetPaths(name=safe_component(name), root=self.results / safe_component(name))

    def targets(self) -> list[str]:
        if not self.results.is_dir():
            return []
        return sorted(
            p.name for p in self.results.iterdir() if p.is_dir() and not p.name.startswith(".")
        )

    def ensure(self) -> "Workspace":
        self.results.mkdir(parents=True, exist_ok=True)
        return self


def results_dir_from_env() -> Path:
    """Allow ``RECONX_RESULTS`` to override the results directory (tests)."""
    override = os.environ.get("RECONX_RESULTS")
    return Path(override) if override else project_root() / "results"
