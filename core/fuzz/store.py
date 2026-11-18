"""Thread-safe finding persistence.

Every finding is written to ``fuzz/findings.jsonl`` (machine readable),
``fuzz/hits.txt`` (legacy/human readable) and optionally to an evidence file.
Existing fingerprints are loaded on start so re-running the fuzzer does not
duplicate results.
"""

from __future__ import annotations

import json
import threading

from core import redact, ui
from core.models import Finding
from core.paths import SubPaths


class FindingStore:
    """Append-only finding store for one subdomain."""

    def __init__(self, sub: SubPaths, *, save_evidence: bool = True):
        self.sub = sub
        self.save_evidence = save_evidence
        sub.ensure()
        self._lock = threading.Lock()
        self._fingerprints: set[str] = set()
        self._count = 0
        self._load_existing()

    def _load_existing(self) -> None:
        path = self.sub.findings_file
        if not path.is_file():
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(data, dict):
                        continue
                    fingerprint = data.get("fingerprint")
                    if not fingerprint:
                        try:
                            fingerprint = Finding.from_dict(data).compute_fingerprint()
                        except Exception:
                            continue
                    self._fingerprints.add(str(fingerprint))
                    self._count += 1
        except OSError:
            return

    @property
    def count(self) -> int:
        return self._count

    def exists(self, finding: Finding) -> bool:
        return finding.compute_fingerprint() in self._fingerprints

    def add(self, finding: Finding) -> bool:
        """Persist *finding*; return False when it was a duplicate."""
        finding = redact.redact_finding(finding)
        if not finding.fingerprint:
            finding.fingerprint = finding.compute_fingerprint()

        with self._lock:
            if finding.fingerprint in self._fingerprints:
                return False
            self._fingerprints.add(finding.fingerprint)
            self._count += 1

            self.sub.fuzz_dir.mkdir(parents=True, exist_ok=True)
            with open(self.sub.findings_file, "a", encoding="utf-8") as handle:
                handle.write(finding.to_json() + "\n")
            with open(self.sub.hits_file, "a", encoding="utf-8") as handle:
                handle.write(finding.hit_line() + "\n")

            if self.save_evidence:
                self._write_evidence(finding)

        return True

    def _write_evidence(self, finding: Finding) -> None:
        try:
            self.sub.evidence_dir.mkdir(parents=True, exist_ok=True)
            path = self.sub.evidence_dir / f"{finding.fingerprint}.txt"
            request = finding.request or {}
            response = finding.response or {}
            body_snippet = redact.text(str(response.get("body_snippet") or "")[:4000])
            lines = [
                f"ReconX evidence — {finding.vuln}",
                f"timestamp: {finding.timestamp}",
                f"fingerprint: {finding.fingerprint}",
                f"confidence: {finding.confidence}",
                f"severity: {finding.severity}",
                "",
                f"URL: {redact.url(finding.url)}",
                f"method: {finding.method}",
                f"parameter: {finding.param or '-'}",
                f"payload: {finding.payload or '-'}",
                f"status: {finding.status}",
                "",
                "evidence:",
                redact.text(finding.evidence),
                "",
                "request headers:",
                json.dumps(redact.headers(request.get("headers")) or {}, indent=2),
                "",
                "request body:",
                redact.text(str(request.get("body") or "")[:4000]),
                "",
                "response headers:",
                json.dumps(redact.headers(response.get("headers")) or {}, indent=2),
                "",
                "response body snippet:",
                body_snippet,
                "",
            ]
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines))
        except OSError as exc:  # pragma: no cover - best effort
            ui.debug(f"could not write evidence for {finding.fingerprint}: {exc}")

    def summary(self) -> str:
        return f"{self._count} finding(s) in {self.sub.fuzz_dir}"
