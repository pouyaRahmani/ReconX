"""Redaction of headers, URLs, samples and raw HTTP transcripts."""

from __future__ import annotations

from core import redact
from core.models import Finding


def test_headers_and_query_parameters():
    headers = {
        "Authorization": "Bearer super-secret-jwt-token-value",
        "Cookie": "sessionid=abcdef123456; theme=dark",
        "X-API-Key": "ak_live_999888777",
        "Accept": "application/json",
    }
    cleaned = redact.headers(headers)
    assert cleaned["Authorization"] == "Bearer [REDACTED]"
    assert cleaned["Cookie"] == "[REDACTED]"
    assert cleaned["X-API-Key"] == "[REDACTED]"
    assert cleaned["Accept"] == "application/json"

    cleaned_url = redact.url(
        "https://api.example.com/callback?code=123&access_token=sec_98765&page=2"
    )
    assert "sec_98765" not in cleaned_url
    assert "code=123" in cleaned_url
    assert "page=2" in cleaned_url


def test_url_drops_userinfo():
    cleaned = redact.url("https://alice:supersecret@example.com/path?q=1")
    assert "alice" not in cleaned
    assert "supersecret" not in cleaned
    assert "example.com/path" in cleaned


def test_raw_http_redacts_sensitive_header_lines():
    raw = "\r\n".join(
        [
            "POST /login HTTP/1.1",
            "Host: app.example.com",
            "Authorization: Bearer super-secret-value",
            "Cookie: sessionid=abcdef123456; theme=dark",
            "Content-Type: application/json",
            "",
            '{"user":"alice","token":"plain-token-value"}',
        ]
    )

    out = redact.raw_http(raw)
    for leaked in ("super-secret-value", "abcdef123456", "plain-token-value"):
        assert leaked not in out
    for kept in (
        "POST /login HTTP/1.1",
        "Host: app.example.com",
        "Content-Type: application/json",
        "Authorization: [REDACTED]",
    ):
        assert kept in out


def test_text_scrubs_bearer_jwt_and_key_values():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
    secret = "password=hunter2"
    bearer = "Authorization: Bearer abcdef1234567890"

    assert "abcdef1234567890" not in redact.text(bearer)
    assert "eyJ" not in redact.text(jwt)
    assert "hunter2" not in redact.text(secret)


def test_samples_mask_sensitive_names():
    cleaned = redact.samples({"username": "alice", "password": "hunter2", "token": "abc123"})
    assert cleaned["username"] == "alice"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["token"] == "[REDACTED]"


def test_redact_finding_masks_nested_request_and_response():
    finding = Finding(
        vuln="xss",
        url="https://app.example.com/search?q=1&access_token=secret-token",
        evidence="token=plain-token-value reflected",
        request={
            "headers": {"Cookie": "sessionid=abcdef123456", "Accept": "*/*"},
            "body": '{"password":"hunter2"}',
        },
        response={
            "headers": {"Set-Cookie": "sessionid=abcdef123456", "Server": "nginx"},
            "body_snippet": '{"token":"plain-token-value"}',
        },
    )
    finding.fingerprint = finding.compute_fingerprint()

    cleaned = redact.redact_finding(finding)

    assert cleaned.fingerprint == finding.fingerprint
    assert "secret-token" not in cleaned.url
    assert "plain-token-value" not in cleaned.evidence
    assert cleaned.request["headers"]["Cookie"] == "[REDACTED]"
    assert cleaned.request["headers"]["Accept"] == "*/*"
    assert "hunter2" not in cleaned.request["body"]
    assert cleaned.response["headers"]["Set-Cookie"] == "[REDACTED]"
    assert cleaned.response["headers"]["Server"] == "nginx"
    assert "plain-token-value" not in cleaned.response["body_snippet"]
