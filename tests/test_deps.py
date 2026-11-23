"""Tool resolution: ``config/settings.yaml`` ``tools:`` entries win over PATH."""

from __future__ import annotations

from core.deps import resolve


def test_resolve_uses_configured_absolute_path(tmp_path):
    tool = tmp_path / "gau"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")

    settings = {"tools": {"gau": str(tool)}}

    assert resolve("gau", settings) == str(tool)


def test_resolve_reports_missing_tool():
    assert resolve("reconx-definitely-not-a-real-tool") is None
