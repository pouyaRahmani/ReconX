"""Target configuration validation."""

from __future__ import annotations

import json

import pytest

from core.config_loader import (
    ConfigError,
    default_target_config,
    load_settings,
    load_target_config,
    validate_config,
    write_sample_config,
)


def test_minimal_config_gets_defaults():
    cfg = validate_config({"target": "acme", "seeds": ["acme.test"]})
    assert cfg.target == "acme"
    assert cfg.seeds == ["https://acme.test/"]
    assert cfg.vulns == ["xss"]
    assert cfg.methods == ["GET"]
    assert cfg.content_types == ["urlencoded"]
    assert cfg.scope_domains == ["acme.test"]


def test_string_lists_and_aliases():
    cfg = validate_config(
        {
            "target": "acme",
            "methods": "GET, POST",
            "vulns": "xss, redirect, mysqli",
            "content_types": "json,urlencoded",
        }
    )
    assert cfg.methods == ["GET", "POST"]
    assert cfg.vulns == ["xss", "open-redirect", "sqli"]
    assert cfg.content_types == ["json", "urlencoded"]


def test_invalid_vulnerability_rejected():
    with pytest.raises(ConfigError, match="invalid vulnerability"):
        validate_config({"target": "acme", "vulns": ["rce"]})


def test_invalid_method_rejected():
    with pytest.raises(ConfigError, match="invalid method"):
        validate_config({"target": "acme", "methods": ["BREW"]})


def test_invalid_content_type_rejected():
    with pytest.raises(ConfigError, match="invalid content type"):
        validate_config({"target": "acme", "content_types": ["yaml"]})


def test_missing_target_rejected():
    with pytest.raises(ConfigError, match="target"):
        validate_config({"seeds": ["https://example.com"]})


def test_numeric_validation():
    with pytest.raises(ConfigError, match="rl"):
        validate_config({"target": "acme", "rl": 0})
    with pytest.raises(ConfigError, match="chunk_size"):
        validate_config({"target": "acme", "chunk_size": -1})


def test_sqli_timeout_warning(capsys):
    validate_config({"target": "acme", "vulns": ["sqli"], "timeout": 10})
    captured = capsys.readouterr()
    assert "SLEEP(15)" in captured.out


def test_scope_derivation_from_seed_and_sub():
    cfg = validate_config(
        {
            "target": "acme",
            "seeds": ["https://app.example.com/login"],
            "sub": "api.example.com",
        }
    )
    assert "example.com" in cfg.scope_domains


def test_explicit_scope_is_preserved():
    cfg = validate_config(
        {"target": "acme", "seeds": ["https://app.example.com"], "scope_domains": ["example.org"]}
    )
    assert cfg.scope_domains == ["example.org"]


def test_nested_nuclei_overrides():
    settings = load_settings()
    cfg = validate_config(
        {"target": "acme", "nuclei": {"severity": "critical", "max_urls": 5}},
        settings,
    )
    assert cfg.nuclei["severity"] == "critical"
    assert cfg.nuclei["max_urls"] == 5
    assert cfg.nuclei["enabled"] is True  # inherited from settings


def test_notifications_section_defaults_and_overrides():
    default_cfg = validate_config({"target": "acme"})
    assert default_cfg.notifications.enabled is False
    assert default_cfg.notifications.only_on_diff is True

    cfg = validate_config(
        {
            "target": "acme",
            "notifications": {
                "enabled": True,
                "only_on_diff": False,
                "telegram_bot_token": "token",
                "telegram_chat_id": "42",
                "webhook_url": "https://hooks.test/webhook",
            },
        }
    )
    assert cfg.notifications.enabled is True
    assert cfg.notifications.only_on_diff is False
    assert cfg.notifications.telegram_bot_token == "token"
    assert cfg.notifications.telegram_chat_id == "42"
    assert cfg.notifications.webhook_url == "https://hooks.test/webhook"

    # ``to_dict`` -> ``validate_config`` round trip (used by CLI overrides).
    assert validate_config(cfg.to_dict()).notifications == cfg.notifications


def test_default_target_config_uses_settings():
    settings = load_settings()
    cfg = default_target_config("acme", seeds=["https://acme.test"], settings=settings)
    assert cfg.target == "acme"
    assert cfg.rl == settings["defaults"]["rate_limit"]
    assert cfg.seeds == ["https://acme.test/"]


def test_load_target_config_round_trip(tmp_path):
    path = tmp_path / "acme.json"
    write_sample_config(path, "acme", ["https://acme.test"])
    cfg = load_target_config(path)
    assert cfg.target == "acme"
    assert cfg.seeds == ["https://acme.test/"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["target"] == "acme"


def test_load_target_config_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_target_config(path)
