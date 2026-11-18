"""Parameter extraction, merging and single-URL mode."""

from __future__ import annotations

import json

from core.config_loader import validate_config
from core.params import (
    apply_shared_params,
    build_single_params,
    cross_sub_merge,
    extract_params,
)
from core.paths import Workspace


HOST = "app.example.com"


def _workspace(tmp_path) -> tuple[Workspace, object, object]:
    workspace = Workspace(tmp_path)
    target_paths = workspace.target("acme").ensure()
    sub = target_paths.sub(HOST).ensure()
    return workspace, target_paths, sub


def _write_fixtures(sub) -> None:
    sub.passive_file.write_text(
        "\n".join(
            [
                "https://app.example.com/search?q=test&page=1",
                "https://app.example.com/item?id=7",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    sub.katana_file.write_text("https://app.example.com/list?sort=asc\n", encoding="utf-8")
    records = [
        {
            "url": "https://app.example.com/api/login",
            "method": "POST",
            "body": "username=alice&password=secret",
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "forms": [],
        },
        {
            "url": "https://app.example.com/api/user",
            "method": "POST",
            "body": '{"name": "bob", "age": 30}',
            "headers": {"content-type": "application/json"},
            "forms": [],
        },
        {
            "url": "https://app.example.com/form",
            "method": "GET",
            "body": "",
            "headers": {},
            "forms": [
                {
                    "action": "https://app.example.com/submit",
                    "method": "POST",
                    "fields": ["email", "message"],
                }
            ],
        },
    ]
    sub.katana_requests_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def test_extract_params_from_all_sources(tmp_path):
    workspace, _target_paths, sub = _workspace(tmp_path)
    _write_fixtures(sub)

    cfg = validate_config(
        {
            "target": "acme",
            "seeds": [f"https://{HOST}"],
            "cross_page_params": False,
        }
    )
    data = extract_params(workspace, "acme", HOST, cfg, refresh=True)

    assert data["subdomain"] == HOST
    assert len(data["endpoints"]) == 6
    assert set(data["all_params"]) == {
        "q",
        "page",
        "id",
        "sort",
        "username",
        "password",
        "name",
        "age",
        "email",
        "message",
    }
    assert set(data["passive_params"]) == {"q", "page", "id"}
    assert data["stats"]["params"] == 10
    assert "https://app.example.com/search?page=1&q=test" in data["urls"]
    assert sub.params_file.is_file()
    assert sub.crawl_urls_file.is_file()
    assert sub.crawl_targets_file.is_file()

    login = next(e for e in data["endpoints"] if e["url"].endswith("/api/login"))
    assert login["location"] == "body"
    assert login["content_type"] == "urlencoded"
    assert login["samples"]["username"] == "alice"


def test_cross_page_merge_adds_sibling_params(tmp_path):
    workspace, _target_paths, sub = _workspace(tmp_path)
    sub.passive_file.write_text(
        "\n".join(
            [
                "https://app.example.com/a?alpha=1",
                "https://app.example.com/b?beta=2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    cfg = validate_config({"target": "acme", "cross_page_params": True})
    data = extract_params(workspace, "acme", HOST, cfg, refresh=True)

    assert len(data["endpoints"]) == 2
    for endpoint in data["endpoints"]:
        assert endpoint["merged"] is True
        assert set(endpoint["params"]) == {"alpha", "beta"}


def test_ignored_params_are_filtered(tmp_path):
    workspace, _target_paths, sub = _workspace(tmp_path)
    sub.passive_file.write_text(
        "https://app.example.com/x?utm_source=news&q=1\n", encoding="utf-8"
    )
    cfg = validate_config({"target": "acme", "ignore_params": ["utm_*"]})
    data = extract_params(workspace, "acme", HOST, cfg, refresh=True)
    assert data["all_params"] == ["q"]


def test_build_single_params_query_and_body(tmp_path):
    workspace, _target_paths, sub = _workspace(tmp_path)
    cfg = validate_config({"target": "acme", "cross_page_params": False})

    data = build_single_params(
        workspace,
        "acme",
        "https://app.example.com/login?next=%2Fhome",
        cfg,
        method="POST",
        data="username=x&password=y",
        params=["remember"],
        content_type="urlencoded",
    )

    assert data["subdomain"] == HOST
    assert data["mode"] == "single"
    assert set(data["all_params"]) == {"next", "username", "password", "remember"}
    locations = {(e["location"], e["method"]) for e in data["endpoints"]}
    assert ("body", "POST") in locations
    assert sub.params_file.is_file()


def test_cross_sub_merge_and_apply(tmp_path):
    workspace, target_paths, sub_a = _workspace(tmp_path)
    sub_b = target_paths.sub("api.example.com").ensure()
    sub_a.params_file.write_text(
        json.dumps(
            {
                "passive_params": ["q", "page"],
                "endpoints": [
                    {
                        "url": "https://app.example.com/search",
                        "method": "GET",
                        "location": "query",
                        "params": ["page"],
                        "samples": {"page": "1"},
                    }
                ],
                "all_params": ["page"],
            }
        ),
        encoding="utf-8",
    )
    sub_b.params_file.write_text(
        json.dumps({"passive_params": ["q", "sort"], "endpoints": [], "all_params": []}),
        encoding="utf-8",
    )

    cfg = validate_config(
        {
            "target": "acme",
            "cross_sub_passive_params": True,
            "shared_param_limit": 1,
        }
    )
    shared = cross_sub_merge(workspace, "acme", cfg)
    assert shared == ["q"]
    assert target_paths.shared_params_file.is_file()

    added = apply_shared_params(workspace, "acme", HOST, shared, cfg)
    assert added == 1
    data = json.loads(sub_a.params_file.read_text(encoding="utf-8"))
    assert "q" in data["endpoints"][0]["params"]
