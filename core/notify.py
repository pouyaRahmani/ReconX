"""Telegram and generic webhook notifications.

Python port of ``reconx-go/internal/notify/notify.go``.  Messages are built
from a :class:`ScanSummary` and an optional :class:`DiffSummary`, then scrubbed
with :mod:`core.redact` before delivery.

The Python pipeline does not keep immutable snapshots, so the delta is
approximated by comparing finding fingerprints and host directories before and
after a run.  ``only_on_diff`` therefore means "only notify when the surface
changed", where a change is a new/removed host or a new finding.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from core import redact
from core.models import Finding, NotificationConfig

DEFAULT_TELEGRAM_API_BASE = "https://api.telegram.org"
DEFAULT_TIMEOUT = 10.0


@dataclass
class ScanSummary:
    """Minimal snapshot used to render a notification."""

    target: str
    run_id: str = ""
    hosts: list[str] = field(default_factory=list)
    endpoints: int = 0
    posture_findings: int = 0
    findings: list[Finding] = field(default_factory=list)


@dataclass
class DiffSummary:
    """Surface changes since the previous run."""

    previous_run_id: str = ""
    has_changes: bool = False
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_endpoints: int = 0
    new_posture_issues: int = 0
    new_findings: list[Finding] = field(default_factory=list)

    @classmethod
    def between(
        cls,
        previous_fingerprints: Iterable[str],
        previous_hosts: Iterable[str],
        findings: list[Finding],
        hosts: list[str],
        previous_run_id: str = "",
    ) -> "DiffSummary":
        """Build a delta from pre-run fingerprints/hosts and post-run results."""
        before = {str(fp) for fp in previous_fingerprints if fp}
        old_hosts = {str(host) for host in previous_hosts if host}
        current_hosts = set(hosts)
        new_hosts = [host for host in hosts if host not in old_hosts]
        removed_hosts = [host for host in old_hosts if host not in current_hosts]
        new_findings = [
            finding
            for finding in findings
            if (finding.fingerprint or finding.compute_fingerprint()) not in before
        ]
        has_changes = bool(new_hosts or removed_hosts or new_findings)
        return cls(
            previous_run_id=previous_run_id,
            has_changes=has_changes,
            new_hosts=new_hosts,
            removed_hosts=removed_hosts,
            new_findings=new_findings,
        )


def format_message(summary: ScanSummary, diff: DiffSummary) -> str:
    """Build a concise, redacted notification message."""
    lines = [
        f"[ReconX ASM] Target: {summary.target} (Run: {summary.run_id})",
        (
            f"Hosts: {len(summary.hosts)} | Endpoints: {summary.endpoints} | "
            f"Posture Findings: {summary.posture_findings} | "
            f"Active Findings: {len(summary.findings)}"
        ),
    ]

    for index, finding in enumerate(summary.findings):
        if index >= 5:
            lines.append(f"  ... and {len(summary.findings) - 5} more finding(s)")
            break
        name = finding.template or finding.vuln
        lines.append(
            f"  * [{finding.severity.upper()}/{finding.source}] "
            f"{name} — {redact.url(finding.url)}"
        )

    if diff.has_changes:
        lines.append(f"Delta vs {diff.previous_run_id or 'previous run'}:")
        if diff.new_hosts:
            lines.append(
                f"  + New Hosts ({len(diff.new_hosts)}): {', '.join(diff.new_hosts)}"
            )
        if diff.removed_hosts:
            lines.append(
                f"  - Removed Hosts ({len(diff.removed_hosts)}): "
                f"{', '.join(diff.removed_hosts)}"
            )
        if diff.new_endpoints:
            lines.append(f"  + New Endpoints: {diff.new_endpoints}")
        if diff.new_posture_issues:
            lines.append(f"  ! New Posture Issues: {diff.new_posture_issues}")
        if diff.new_findings:
            lines.append(f"  ! New Active Findings: {len(diff.new_findings)}")
    else:
        lines.append("Delta: No surface changes detected.")

    return redact.text("\n".join(lines)) + "\n"


class Sender:
    """Deliver notifications to Telegram and/or a webhook URL."""

    def __init__(
        self,
        session: Any | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        telegram_api_base: str = DEFAULT_TELEGRAM_API_BASE,
    ):
        self._session = session
        self.timeout = timeout
        self.telegram_api_base = telegram_api_base

    @property
    def session(self) -> Any:
        """Lazily create a ``requests.Session`` so imports stay cheap."""
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def notify(
        self,
        config: NotificationConfig,
        summary: ScanSummary,
        diff: DiffSummary | None = None,
    ) -> list[str]:
        """Dispatch a notification and return any delivery errors."""
        if not config.enabled:
            return []
        diff = diff or DiffSummary()

        if config.only_on_diff and not diff.has_changes:
            return []

        message = format_message(summary, diff)
        errors: list[str] = []

        if config.telegram_bot_token and config.telegram_chat_id:
            try:
                self.send_telegram(
                    config.telegram_bot_token, config.telegram_chat_id, message
                )
            except Exception as exc:  # noqa: BLE001 - surfaced as a warning
                errors.append("telegram: " + redact.text(str(exc)))

        if config.webhook_url:
            try:
                self.send_webhook(config.webhook_url, message, summary, diff)
            except Exception as exc:  # noqa: BLE001 - surfaced as a warning
                errors.append("webhook: " + redact.text(str(exc)))

        return errors

    def send_telegram(self, token: str, chat_id: str, message: str) -> None:
        base = self.telegram_api_base.rstrip("/")
        endpoint = f"{base}/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "disable_web_page_preview": True,
        }
        self._post_json(endpoint, payload, label="telegram")

    def send_webhook(
        self,
        webhook_url: str,
        message: str,
        summary: ScanSummary,
        diff: DiffSummary,
    ) -> None:
        payload = {
            "text": message,
            "content": message,
            "target": summary.target,
            "run_id": summary.run_id,
            "diff": _jsonable(asdict(diff)),
        }
        self._post_json(webhook_url, payload, label="webhook")

    def _post_json(self, endpoint: str, payload: dict[str, Any], *, label: str) -> None:
        response = self.session.post(
            endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=self.timeout,
        )
        status = getattr(response, "status_code", 200)
        if status >= 300:
            raise RuntimeError(f"{label} returned HTTP {status}")


def _jsonable(value: Any) -> Any:
    """Recursively convert dataclasses (including findings) to JSON values."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "to_dict"):
        return _jsonable(value.to_dict())
    return value
