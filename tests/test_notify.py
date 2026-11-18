"""Notification formatting and delivery (fake HTTP session)."""

from __future__ import annotations

import json

from core.models import Finding, NotificationConfig
from core.notify import DiffSummary, ScanSummary, Sender, format_message


class FakeResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code


class FakeSession:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.calls: list[dict] = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(
            {
                "url": url,
                "payload": json.loads(data.decode("utf-8")) if data else None,
                "headers": headers,
                "timeout": timeout,
            }
        )
        return FakeResponse(self.status_code)


def _finding(**overrides) -> Finding:
    data = {
        "vuln": "xss",
        "url": "https://app.example.com/search?q=1",
        "severity": "high",
        "confidence": "confirmed",
        "source": "fuzzer",
        "evidence": "payload reflected",
    }
    data.update(overrides)
    finding = Finding(**data)
    finding.fingerprint = finding.compute_fingerprint()
    return finding


def test_notify_sends_telegram_and_webhook():
    session = FakeSession()
    sender = Sender(session, telegram_api_base="https://telegram.test")
    cfg = NotificationConfig(
        enabled=True,
        only_on_diff=True,
        telegram_bot_token="TEST_TOKEN",
        telegram_chat_id="12345",
        webhook_url="https://hooks.test/webhook",
    )
    summary = ScanSummary(
        target="acme",
        run_id="run-2",
        hosts=["app.example.com"],
        endpoints=4,
        findings=[_finding()],
    )
    diff = DiffSummary(
        previous_run_id="run-1",
        has_changes=True,
        new_hosts=["app.example.com"],
        new_findings=[_finding()],
    )

    errors = sender.notify(cfg, summary, diff)

    assert errors == []
    assert len(session.calls) == 2

    telegram = session.calls[0]
    assert telegram["url"] == "https://telegram.test/botTEST_TOKEN/sendMessage"
    assert telegram["payload"]["chat_id"] == "12345"
    assert telegram["headers"]["Content-Type"] == "application/json"

    webhook = session.calls[1]
    assert webhook["url"] == "https://hooks.test/webhook"
    assert webhook["payload"]["target"] == "acme"
    assert webhook["payload"]["run_id"] == "run-2"
    assert webhook["payload"]["diff"]["has_changes"] is True


def test_only_on_diff_skips_unchanged_runs():
    session = FakeSession()
    sender = Sender(session)
    cfg = NotificationConfig(
        enabled=True,
        only_on_diff=True,
        telegram_bot_token="TEST_TOKEN",
        telegram_chat_id="12345",
    )
    summary = ScanSummary(target="acme", run_id="run-2", hosts=["app.example.com"])
    diff = DiffSummary(has_changes=False)

    assert sender.notify(cfg, summary, diff) == []
    assert session.calls == []


def test_disabled_notifications_do_not_send():
    session = FakeSession()
    sender = Sender(session)
    cfg = NotificationConfig(enabled=False, webhook_url="https://hooks.test/webhook")

    assert sender.notify(cfg, ScanSummary(target="acme")) == []
    assert session.calls == []


def test_format_message_lists_findings_and_delta():
    summary = ScanSummary(
        target="acme",
        run_id="run-2",
        hosts=["app.example.com"],
        endpoints=2,
        findings=[_finding(), _finding(vuln="sqli", severity="critical")],
    )
    diff = DiffSummary(
        previous_run_id="run-1",
        has_changes=True,
        new_hosts=["app.example.com"],
        new_findings=[_finding()],
    )

    message = format_message(summary, diff)

    assert "[ReconX ASM] Target: acme (Run: run-2)" in message
    assert "Hosts: 1 | Endpoints: 2" in message
    assert "Delta vs run-1:" in message
    assert "+ New Hosts (1): app.example.com" in message
    assert "! New Active Findings: 1" in message


def test_format_message_redacts_urls_and_secrets():
    finding = _finding(
        url="https://app.example.com/search?access_token=secret-token",
        evidence="payload reflected",
    )
    summary = ScanSummary(target="acme", run_id="run-2", findings=[finding])
    diff = DiffSummary(has_changes=True)

    message = format_message(summary, diff)

    assert "secret-token" not in message
    assert "access_token=[REDACTED]" in message


def test_delivery_errors_are_reported():
    session = FakeSession(status_code=500)
    sender = Sender(session)
    cfg = NotificationConfig(
        enabled=True,
        only_on_diff=False,
        webhook_url="https://hooks.test/webhook",
    )

    errors = sender.notify(cfg, ScanSummary(target="acme"), DiffSummary(has_changes=False))

    assert len(errors) == 1
    assert errors[0].startswith("webhook:")
    assert "HTTP 500" in errors[0]


def test_diff_between_detects_new_hosts_and_findings():
    existing = _finding()
    added = _finding(vuln="sqli", url="https://api.example.com/login")
    diff = DiffSummary.between(
        [existing.fingerprint],
        ["app.example.com"],
        [existing, added],
        ["app.example.com", "api.example.com"],
        "run-1",
    )

    assert diff.has_changes is True
    assert diff.new_hosts == ["api.example.com"]
    assert diff.new_findings == [added]
