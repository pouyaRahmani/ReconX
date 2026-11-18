"""URL parsing, normalisation and parameter helpers."""

from __future__ import annotations

from core.recon.urls import (
    add_query,
    in_scope,
    is_static_asset,
    normalize_url,
    parse_host,
    query_params,
    query_samples,
    root_domain_guess,
)


def test_parse_host_forms():
    assert parse_host("https://App.Example.com/path?q=1") == "app.example.com"
    assert parse_host("example.com") == "example.com"
    assert parse_host("example.com:8443") == "example.com:8443"
    assert parse_host("//app.example.com/path") == "app.example.com"
    assert parse_host("") == ""
    assert parse_host("://bad") == ""


def test_normalize_url_canonicalises():
    url = normalize_url("HTTPS://Example.COM:443/a//b?z=2&a=1#fragment")
    assert url == "https://example.com/a/b?a=1&z=2"

    assert normalize_url("javascript:alert(1)") is None
    assert normalize_url("ftp://example.com/file") is None
    assert normalize_url("") is None
    assert normalize_url("http://example.com") == "http://example.com/"


def test_normalize_url_drops_default_port_but_keeps_custom():
    assert normalize_url("http://example.com:80/x") == "http://example.com/x"
    assert normalize_url("https://example.com:8443/x") == "https://example.com:8443/x"


def test_normalize_url_keeps_blank_query_values():
    assert normalize_url("https://example.com/?a=&b=2") == "https://example.com/?a=&b=2"


def test_static_asset_detection():
    assert is_static_asset("https://example.com/logo.png") is True
    assert is_static_asset("https://example.com/app.js") is True
    assert is_static_asset("https://example.com/search.php") is False
    assert is_static_asset("https://example.com/api/users") is False


def test_scope_matching():
    scope = ["example.com"]
    assert in_scope("https://example.com/", scope) is True
    assert in_scope("https://app.example.com/x", scope) is True
    assert in_scope("https://evil.com/x", scope) is False
    assert in_scope("https://example.com.evil.com/", scope) is False
    assert in_scope("https://anything.test/", []) is True


def test_root_domain_guess():
    assert root_domain_guess("app.example.com") == "example.com"
    assert root_domain_guess("example.com:8443") == "example.com"
    assert root_domain_guess("shop.example.co.uk") == "example.co.uk"


def test_query_helpers():
    url = "https://example.com/search?b=2&a=1&a=3"
    assert query_params(url) == ["b", "a"]
    assert query_samples(url) == {"b": "2", "a": "1"}


def test_add_query_merges_parameters():
    assert add_query("https://example.com/p?a=1", {"b": "2"}) == "https://example.com/p?a=1&b=2"
