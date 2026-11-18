"""Fuzz-job generation."""

from __future__ import annotations

import json

from core.config_loader import validate_config
from core.paths import Workspace
from core.templates import build_jobs, remove_templates


HOST = "app.example.com"


def _prepare(tmp_path, params):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub(HOST).ensure()
    sub.params_file.write_text(
        json.dumps(
            {
                "subdomain": HOST,
                "endpoints": [
                    {
                        "url": "https://app.example.com/search",
                        "method": "GET",
                        "location": "query",
                        "content_type": None,
                        "params": ["q", "page", "lang"],
                        "samples": {"q": "test", "page": "1", "lang": "en"},
                        "sources": ["test"],
                    }
                ],
                "all_params": ["q", "page", "lang"],
                "targets": ["https://app.example.com/"],
                "urls": ["https://app.example.com/search?q=test"],
            }
        ),
        encoding="utf-8",
    )
    return workspace, sub


def test_parameter_jobs_keep_all_samples(tmp_path):
    workspace, sub = _prepare(tmp_path, None)
    cfg = validate_config(
        {
            "target": "acme",
            "vulns": ["xss"],
            "methods": ["GET"],
            "chunk_size": 2,
        }
    )

    jobs, stats = build_jobs(workspace, "acme", HOST, cfg)

    assert len(jobs) == 2
    assert stats.jobs == 2
    assert stats.per_vuln["xss"] == 2
    assert jobs[0].params == ["q", "page"]
    assert jobs[1].params == ["lang"]
    # Every job keeps the full sample map so non-fuzzed parameters survive.
    assert jobs[0].samples == {"q": "test", "page": "1", "lang": "en"}
    assert (sub.templates_dir / "all.jsonl").is_file()
    assert (sub.templates_dir / "xss" / "jobs.jsonl").is_file()


def test_header_jobs_need_no_parameters(tmp_path):
    workspace, _sub = _prepare(tmp_path, None)
    cfg = validate_config(
        {"target": "acme", "vulns": ["headers-reflection"], "methods": ["GET"]}
    )

    jobs, stats = build_jobs(workspace, "acme", HOST, cfg)

    assert jobs
    assert all(job.location == "header" for job in jobs)
    assert all(job.params == [] for job in jobs)
    assert stats.per_vuln["headers-reflection"] == len(jobs)


def test_time_based_sqli_skipped_for_short_timeout(tmp_path):
    workspace, _sub = _prepare(tmp_path, None)
    cfg = validate_config(
        {"target": "acme", "vulns": ["sqli"], "timeout": 10, "methods": ["GET"]}
    )

    jobs, _stats = build_jobs(workspace, "acme", HOST, cfg)

    assert jobs
    assert all(not job.payload_file.endswith("sleep.txt") for job in jobs)
    assert all(not job.serial for job in jobs)


def test_time_based_sqli_is_serial_when_allowed(tmp_path):
    workspace, _sub = _prepare(tmp_path, None)
    cfg = validate_config(
        {"target": "acme", "vulns": ["sqli"], "timeout": 30, "methods": ["GET"]}
    )

    jobs, _stats = build_jobs(workspace, "acme", HOST, cfg)

    sleep_jobs = [job for job in jobs if job.payload_file.endswith("sleep.txt")]
    assert sleep_jobs
    assert all(job.serial for job in sleep_jobs)


def test_remove_templates(tmp_path):
    workspace, sub = _prepare(tmp_path, None)
    cfg = validate_config({"target": "acme", "vulns": ["xss"]})
    build_jobs(workspace, "acme", HOST, cfg)
    assert sub.templates_dir.is_dir()
    remove_templates(sub)
    assert not sub.templates_dir.exists()
