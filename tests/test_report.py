"""Report aggregation and rendering."""

from __future__ import annotations

import json

from core.models import Finding
from core.paths import Workspace
from core.report import aggregate, render_html, render_json, render_text


def _finding(**overrides) -> Finding:
    data = {
        "vuln": "xss",
        "url": "https://app.example.com/search?q=1",
        "method": "GET",
        "param": "q",
        "payload": "<script>alert(1)</script>",
        "status": 200,
        "evidence": "payload reflected",
        "severity": "high",
        "confidence": "confirmed",
        "source": "fuzzer",
    }
    data.update(overrides)
    finding = Finding(**data)
    finding.fingerprint = finding.compute_fingerprint()
    return finding


def _workspace_with_findings(tmp_path):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub_a = target_paths.sub("app.example.com").ensure()
    sub_b = target_paths.sub("api.example.com").ensure()

    first = _finding()
    duplicate = _finding()
    second = _finding(
        vuln="sqli",
        url="https://api.example.com/login",
        method="POST",
        param="username",
        payload="' OR 1=1--",
        evidence="database error",
        severity="critical",
        confidence="confirmed",
    )

    sub_a.findings_file.write_text(
        first.to_json() + "\n" + duplicate.to_json() + "\n", encoding="utf-8"
    )
    sub_b.findings_file.write_text(second.to_json() + "\n", encoding="utf-8")
    return workspace, target_paths, [first, second]


def test_aggregate_writes_all_formats_and_deduplicates(tmp_path):
    workspace, target_paths, findings = _workspace_with_findings(tmp_path)

    count = aggregate(workspace, "acme", ["txt", "json", "html"])

    assert count == 2
    txt = target_paths.output / "acme.txt"
    data = target_paths.output / "acme.json"
    page = target_paths.output / "acme.html"
    assert txt.is_file() and data.is_file() and page.is_file()

    text = txt.read_text(encoding="utf-8")
    assert "ReconX Report" in text
    assert "xss" in text
    assert "sqli" in text

    payload = json.loads(data.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["confirmed"] == 2
    assert len(payload["findings"]) == 2

    html = page.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "Filter by URL" in html


def test_renderers_handle_empty_results():
    assert "No findings" in render_text("acme", [], ["app.example.com"])
    payload = json.loads(render_json("acme", [], []))
    assert payload["summary"]["total"] == 0
    assert "No findings" in render_html("acme", [], [])


def test_legacy_hits_are_parsed(tmp_path):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub("app.example.com").ensure()
    sub.hits_file.write_text(
        "[XSS] https://app.example.com/x?q=1 | q | <script> | 200 | reflected\n",
        encoding="utf-8",
    )

    count = aggregate(workspace, "acme", ["json"])
    assert count == 1
    payload = json.loads((target_paths.output / "acme.json").read_text(encoding="utf-8"))
    assert payload["findings"][0]["vuln"] == "xss"
    assert payload["findings"][0]["source"] == "legacy"
