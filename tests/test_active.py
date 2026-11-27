"""Katana output parsing and host handling."""

from __future__ import annotations

import json

import pytest

from core.config_loader import default_target_config, load_settings
from core.paths import Workspace
from core.process import ProcResult, run_to_file
from core.recon import active
from core.recon.active import (
    ActiveOptions,
    _normalise_record,
    _parse_katana_file,
    _parse_katana_output,
    _prioritise_seeds,
    crawl_host,
    katana_request_timeout,
    seed_limit,
)

HOST = "api.example.com"

KATANA_LINE = json.dumps(
    {
        "request": {
            "method": "GET",
            "endpoint": "https://api.example.com/user/statistics",
            "headers": {"Host": "api.example.com"},
        },
        "response": {"status_code": 401, "headers": {"Content-Type": "application/json"}},
    }
)


def _settings():
    return load_settings()


def _cfg():
    return default_target_config("acme", settings=_settings())


def test_parse_katana_output_builds_records():
    records, plain, errors = _parse_katana_output(
        KATANA_LINE + "\nhttps://api.example.com/plain\nnot-json\n"
    )
    assert errors == []
    assert len(records) == 1
    assert records[0]["url"] == "https://api.example.com/user/statistics"
    assert records[0]["status"] == 401
    assert plain == ["https://api.example.com/plain"]


def test_normalise_record_supports_forms():
    record = _normalise_record(
        {
            "request": {"method": "POST", "endpoint": "https://api.example.com/login"},
            "form": {"action": "/session", "method": "POST", "fields": ["user", "pass"]},
        }
    )
    assert record is not None
    assert record["forms"][0]["action"] == "https://api.example.com/session"
    assert record["forms"][0]["fields"] == ["user", "pass"]


def test_crawl_keeps_records_for_bare_host(tmp_path, monkeypatch):
    """Regression: host "api.example.com" must match crawled URLs."""
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub(HOST).ensure()
    sub.passive_file.write_text(f"https://{HOST}/\n", encoding="utf-8")

    monkeypatch.setattr(active, "which", lambda tool: tool)
    monkeypatch.setattr(active, "host_resolves", lambda host: True)

    def fake_run(cmd, output_path, **kwargs):
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(KATANA_LINE + "\n")
        return ProcResult(args=cmd, returncode=0)

    monkeypatch.setattr(active, "run_to_file", fake_run)

    stats = crawl_host(target_paths, HOST, _settings(), _cfg(), ActiveOptions(depth=1))

    assert stats.requests == 1
    assert stats.urls == 2  # seed root + crawled endpoint
    assert f"https://{HOST}/user/statistics" in sub.katana_file.read_text(encoding="utf-8")
    assert json.loads(sub.katana_requests_file.read_text(encoding="utf-8"))["url"].endswith(
        "/user/statistics"
    )


def test_crawl_skips_unresolvable_host(tmp_path, monkeypatch):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()

    monkeypatch.setattr(active, "which", lambda tool: tool)
    monkeypatch.setattr(active, "host_resolves", lambda host: False)
    monkeypatch.setattr(
        active,
        "run_to_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("katana must not run")),
    )

    stats = crawl_host(target_paths, "dead.example.com", _settings(), _cfg())

    assert stats.requests == 0
    assert any("does not resolve" in error for error in stats.errors)


def test_katana_request_timeout_is_clamped():
    settings = _settings()
    cfg = _cfg()
    assert katana_request_timeout(settings, cfg) == 15
    cfg.timeout = 5
    assert katana_request_timeout(settings, cfg) == 5


def test_prioritise_seeds_dedupes_paths_and_keeps_queries():
    seeds = [
        "https://api.example.com/a",
        "https://api.example.com/a?x=1",
        "https://api.example.com/b/c",
        "https://api.example.com/",
    ]
    ordered = _prioritise_seeds(seeds, 0)
    assert ordered[0] == "https://api.example.com/a?x=1"
    assert len(ordered) == 3
    assert "https://api.example.com/a" not in ordered

    capped = _prioritise_seeds(seeds, 2)
    assert len(capped) == 2


def test_seed_limit_prefers_option_and_settings():
    settings = _settings()
    assert seed_limit(settings, ActiveOptions()) == 120
    assert seed_limit(settings, ActiveOptions(max_seeds=0)) == 0
    settings["defaults"]["max_seeds"] = 7
    assert seed_limit(settings, ActiveOptions()) == 7


def test_parse_katana_file_matches_string_parser(tmp_path):
    path = tmp_path / "katana.jsonl"
    path.write_text(KATANA_LINE + "\nhttps://api.example.com/plain\n", encoding="utf-8")

    from_file = _parse_katana_file(str(path))
    from_string = _parse_katana_output(path.read_text(encoding="utf-8"))

    assert from_file == from_string
    assert len(from_file[0]) == 1


def test_run_to_file_does_not_buffer_output(tmp_path):
    import sys

    output = tmp_path / "out.txt"
    result = run_to_file(
        [sys.executable, "-c", "print('line1'); print('line2')"],
        output,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert output.read_text(encoding="utf-8").split() == ["line1", "line2"]


def test_run_to_file_kills_stalled_process(tmp_path):
    """A child that writes once then hangs must be killed, keeping its output."""
    import sys
    import time

    output = tmp_path / "out.txt"
    started = time.monotonic()
    result = run_to_file(
        [sys.executable, "-c", "print('first', flush=True); import time; time.sleep(60)"],
        output,
        stall_timeout=1,
        poll_interval=0.1,
    )
    elapsed = time.monotonic() - started

    assert result.stalled is True
    assert result.timed_out is True
    assert elapsed < 20
    assert output.read_text(encoding="utf-8").strip() == "first"


def test_run_to_file_stops_at_output_cap(tmp_path):
    import sys

    output = tmp_path / "out.txt"
    result = run_to_file(
        [
            sys.executable,
            "-c",
            "import sys\nwhile True: sys.stdout.write('x' * 4096); sys.stdout.flush()",
        ],
        output,
        max_output_bytes=64 * 1024,
        poll_interval=0.05,
    )

    assert result.stalled is True
    assert output.stat().st_size >= 64 * 1024


def test_katana_watchdog_settings():
    settings = _settings()
    assert active.katana_stall_timeout(settings) == 120.0
    assert active.katana_max_output_bytes(settings) == 50 * 1048576

    settings["timeouts"]["katana_stall"] = 0
    settings["katana"]["max_output_mb"] = 0
    assert active.katana_stall_timeout(settings) == 0.0
    assert active.katana_max_output_bytes(settings) == 0

    settings["timeouts"]["katana_stall"] = "oops"
    settings["katana"]["max_output_mb"] = "oops"
    assert active.katana_stall_timeout(settings) == 120.0
    assert active.katana_max_output_bytes(settings) == 50 * 1048576


def test_katana_command_omits_optional_budgets(tmp_path):
    settings = _settings()
    cmd = active._build_katana_command(
        "api.example.com", settings, _cfg(), ActiveOptions()
    )
    assert "-ob" in cmd
    assert "-ct" not in cmd
    assert "-mdp" not in cmd

    settings["katana"]["crawl_duration"] = "10m"
    settings["katana"]["max_pages"] = 2000
    cmd = active._build_katana_command(
        "api.example.com", settings, _cfg(), ActiveOptions()
    )
    assert cmd[cmd.index("-ct") + 1] == "10m"
    assert cmd[cmd.index("-mdp") + 1] == "2000"


def test_crawl_keeps_partial_results_on_keyboard_interrupt(tmp_path, monkeypatch):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub(HOST).ensure()
    sub.passive_file.write_text(f"https://{HOST}/\n", encoding="utf-8")

    monkeypatch.setattr(active, "which", lambda tool: tool)
    monkeypatch.setattr(active, "host_resolves", lambda host: True)

    def fake_run(cmd, output_path, **kwargs):
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(KATANA_LINE + "\n")
        raise KeyboardInterrupt

    monkeypatch.setattr(active, "run_to_file", fake_run)

    with pytest.raises(SystemExit) as excinfo:
        crawl_host(target_paths, HOST, _settings(), _cfg(), ActiveOptions())

    assert excinfo.value.code == 130
    assert "user/statistics" in sub.katana_file.read_text(encoding="utf-8")
    assert sub.katana_requests_file.is_file()


def test_crawl_keeps_partial_results_on_sigterm(tmp_path, monkeypatch):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub(HOST).ensure()
    sub.passive_file.write_text(f"https://{HOST}/\n", encoding="utf-8")

    monkeypatch.setattr(active, "which", lambda tool: tool)
    monkeypatch.setattr(active, "host_resolves", lambda host: True)

    def fake_run(cmd, output_path, **kwargs):
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(KATANA_LINE + "\n")
        raise active.CrawlInterrupted("signal 15")

    monkeypatch.setattr(active, "run_to_file", fake_run)

    with pytest.raises(SystemExit) as excinfo:
        crawl_host(target_paths, HOST, _settings(), _cfg(), ActiveOptions())

    assert excinfo.value.code == 143
    assert "user/statistics" in sub.katana_file.read_text(encoding="utf-8")
    assert sub.katana_requests_file.is_file()


