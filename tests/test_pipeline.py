"""End-to-end orchestration without network access."""

from __future__ import annotations

import json

from core.config_loader import load_settings, validate_config
from core.paths import Workspace
from core.pipeline import MassFuzzOptions, run_mass_fuzz
from core.state import State


HOST = "app.example.com"


def test_mass_fuzz_skip_engine_and_nuclei(tmp_path):
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub(HOST).ensure()
    sub.passive_file.write_text(
        "https://app.example.com/search?q=test\n", encoding="utf-8"
    )
    sub.katana_file.write_text(
        "https://app.example.com/list?sort=asc\n", encoding="utf-8"
    )
    sub.katana_requests_file.write_text(
        json.dumps(
            {
                "url": "https://app.example.com/api/login",
                "method": "POST",
                "body": "username=alice&password=secret",
                "headers": {"content-type": "application/x-www-form-urlencoded"},
                "forms": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    cfg = validate_config(
        {
            "target": "acme",
            "seeds": [f"https://{HOST}"],
            "vulns": ["xss"],
            "methods": ["GET", "POST"],
            "timeout": 30,
        }
    )
    options = MassFuzzOptions(
        skip_fuzz=True,
        skip_nuclei=True,
        keep_templates=True,
    )

    result = run_mass_fuzz(workspace, cfg, load_settings(), options)

    assert result.hosts == [HOST]
    assert result.errors == []
    assert result.findings == 0

    state = State(target_paths)
    entry = state.get(HOST)
    assert entry["status"] == "done"
    assert entry["jobs"] >= 1
    assert sub.templates_dir.is_dir()

    assert (target_paths.output / "acme.txt").is_file()
    assert (target_paths.output / "acme.json").is_file()
    assert (target_paths.output / "acme.html").is_file()
