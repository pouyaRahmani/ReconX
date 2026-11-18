"""CLI smoke tests."""

from __future__ import annotations

from click.testing import CliRunner

from core.cli import cli
from core.config_loader import write_sample_config


def test_help_lists_commands():
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-color", "--help"])
    assert result.exit_code == 0
    for command in ("passive", "active", "mass-fuzz", "single-fuzz", "aggregate"):
        assert command in result.output


def test_validate_accepts_sample_config(tmp_path):
    path = tmp_path / "acme.json"
    write_sample_config(path, "acme", ["https://acme.test"])

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-color", "validate", str(path)])

    assert result.exit_code == 0, result.output
    assert '"target": "acme"' in result.output
    assert "config is valid" in result.output


def test_validate_rejects_unknown_vulnerability(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"target": "acme", "vulns": ["rce"]}', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-color", "validate", str(path)])

    assert result.exit_code != 0
    assert "invalid vulnerability" in result.output.lower()


def test_clean_refuses_missing_target(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONX_RESULTS", str(tmp_path / "results"))
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-color", "clean", "-t", "missing", "--yes"])
    assert result.exit_code == 0
    assert "nothing to clean" in result.output.lower()
