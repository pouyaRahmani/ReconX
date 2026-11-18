"""Detector heuristics (synthetic responses, no network)."""

from __future__ import annotations

from core.fuzz.detectors import (
    detect_cache_poison,
    detect_header_reflection,
    detect_header_status,
    detect_open_redirect,
    detect_sqli,
    detect_xss,
)
from core.fuzz.payloads import parse_header, redirect_hosts, sleep_seconds
from core.models import FuzzJob, HttpResult, TargetConfig


def _job(vuln: str, *, url: str = "https://target.test/search", params=("q",)):
    return FuzzJob(
        vuln=vuln,
        url=url,
        method="GET",
        location="query",
        params=list(params),
        samples={name: "1" for name in params},
        payload_file="",
    )


def _resp(body: str = "", *, status: int = 200, headers=None, elapsed: float = 0.1, url=None):
    return HttpResult(
        ok=True,
        status=status,
        headers=headers or {},
        body=body,
        elapsed=elapsed,
        url=url or "https://target.test/search",
        method="GET",
    )


def test_payload_helpers():
    assert parse_header("X-Test: value") == ("X-Test", "value")
    assert parse_header("not-a-header") is None
    assert parse_header("Bad Name: value") is None
    assert sleep_seconds("' AND SLEEP(15)--") == 15.0
    assert sleep_seconds("'; WAITFOR DELAY '0:0:15'--") == 15.0
    assert sleep_seconds("' OR 1=1--") == 0.0
    assert redirect_hosts("https://evil.com/x") == ["evil.com"]


def test_xss_reflection_confirmed():
    payload = "<script>alert(1)</script>"
    finding = detect_xss(
        _job("xss"),
        payload,
        _resp("<html>clean</html>"),
        _resp(f"<html>{payload}</html>", headers={"content-type": "text/html"}),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.confidence == "confirmed"
    assert finding.severity == "high"


def test_xss_baseline_reflection_is_ignored():
    payload = "<script>alert(1)</script>"
    finding = detect_xss(
        _job("xss"),
        payload,
        _resp(f"<html>{payload}</html>"),
        _resp(f"<html>{payload}</html>", headers={"content-type": "text/html"}),
        TargetConfig(target="acme"),
    )
    assert finding is None


def test_sqli_error_signature():
    finding = detect_sqli(
        _job("sqli"),
        "'",
        _resp("ok"),
        _resp("You have an error in your SQL syntax; check the manual"),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.vuln == "sqli"
    assert finding.confidence == "confirmed"


def test_sqli_time_based_delay():
    finding = detect_sqli(
        _job("sqli"),
        "' AND SLEEP(15)--",
        _resp("ok", elapsed=0.2),
        _resp("ok", elapsed=15.2),
        TargetConfig(target="acme", sleep_threshold=8.0),
    )
    assert finding is not None
    assert finding.severity == "critical"
    assert "time-based" in finding.evidence


def test_sqli_slow_baseline_is_ignored():
    finding = detect_sqli(
        _job("sqli"),
        "' AND SLEEP(15)--",
        _resp("ok", elapsed=12.0),
        _resp("ok", elapsed=20.0),
        TargetConfig(target="acme", sleep_threshold=8.0),
    )
    assert finding is None


def test_open_redirect_location_header():
    finding = detect_open_redirect(
        _job("open-redirect", url="https://target.test/redirect"),
        "//evil.com",
        _resp("", status=302),
        _resp("", status=302, headers={"location": "https://evil.com/"}),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.confidence == "confirmed"


def test_open_redirect_relative_location_is_ignored():
    finding = detect_open_redirect(
        _job("open-redirect", url="https://target.test/redirect"),
        "//evil.com",
        _resp("", status=302),
        _resp("", status=302, headers={"location": "/home"}),
        TargetConfig(target="acme"),
    )
    assert finding is None


def test_open_redirect_javascript_body():
    body = '<script>window.location="https://evil.com/x"</script>'
    finding = detect_open_redirect(
        _job("open-redirect", url="https://target.test/redirect"),
        "//evil.com",
        _resp(""),
        _resp(body, headers={"content-type": "text/html"}),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.confidence == "candidate"


def test_header_reflection():
    finding = detect_header_reflection(
        _job("headers-reflection", params=()),
        "X-Forwarded-Host: reconx1337",
        _resp("clean"),
        _resp("host=reconx1337"),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.param == "X-Forwarded-Host"


def test_header_status_bypass():
    finding = detect_header_status(
        _job("headers-status", params=()),
        "X-Original-URL: /admin",
        _resp("forbidden", status=403),
        _resp("dashboard", status=200),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.severity == "high"


def test_cache_poison_requires_cache_indicator():
    payload = "X-Forwarded-Host: evil.com"
    finding = detect_cache_poison(
        _job("cache-poison", params=()),
        payload,
        _resp("clean"),
        _resp("evil.com", headers={"x-cache": "HIT"}),
        TargetConfig(target="acme"),
    )
    assert finding is not None
    assert finding.severity == "medium"

    no_cache = detect_cache_poison(
        _job("cache-poison", params=()),
        payload,
        _resp("clean"),
        _resp("evil.com"),
        TargetConfig(target="acme"),
    )
    assert no_cache is not None
    assert no_cache.confidence == "candidate"
