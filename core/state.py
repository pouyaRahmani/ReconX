"""Resumable per-target progress state (``results/<target>/state.json``)."""

from __future__ import annotations

import json
from typing import Any

from core.models import utc_now
from core.paths import TargetPaths


class State:
    def __init__(self, target_paths: TargetPaths):
        self.paths = target_paths
        self.data: dict[str, Any] = {
            "target": target_paths.name,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "subdomains": {},
        }
        self._load()

    def _load(self) -> None:
        path = self.paths.state_file
        if not path.is_file():
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (json.JSONDecodeError, OSError):
            return
        if isinstance(data, dict):
            self.data.update(data)
            if not isinstance(self.data.get("subdomains"), dict):
                self.data["subdomains"] = {}

    @property
    def subdomains(self) -> dict[str, dict[str, Any]]:
        return self.data["subdomains"]

    def get(self, host: str) -> dict[str, Any]:
        return dict(self.subdomains.get(host, {}))

    def update(self, host: str, **fields: Any) -> dict[str, Any]:
        entry = dict(self.subdomains.get(host, {}))
        entry.update(fields)
        entry["updated_at"] = utc_now()
        self.subdomains[host] = entry
        self.save()
        return entry

    def mark_done(self, host: str, **fields: Any) -> None:
        self.update(host, status="done", finished_at=utc_now(), **fields)

    def is_done(self, host: str) -> bool:
        return self.get(host).get("status") == "done"

    def save(self) -> None:
        self.paths.ensure()
        self.data["updated_at"] = utc_now()
        with open(self.paths.state_file, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")


def disk_status(target_paths: TargetPaths) -> dict[str, dict[str, Any]]:
    """Read the actual result files so ``reconx status`` works without state."""
    status: dict[str, dict[str, Any]] = {}
    for host in target_paths.hosts():
        sub = target_paths.sub(host)
        findings = 0
        if sub.findings_file.is_file():
            with open(sub.findings_file, "r", encoding="utf-8", errors="replace") as handle:
                findings = sum(1 for line in handle if line.strip())
        status[host] = {
            "passive": _count_lines(sub.passive_file),
            "katana": _count_lines(sub.katana_file),
            "params": sub.params_file.is_file(),
            "crawl_urls": _count_lines(sub.crawl_urls_file),
            "findings": findings,
            "nuclei": sub.fuzz_dir.joinpath("nuclei.jsonl").is_file(),
        }
    return status


def _count_lines(path) -> int:
    if not path.is_file():
        return 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())
