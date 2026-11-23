"""gau argument construction from the ``gau:`` settings block."""

from __future__ import annotations

from core.config_loader import DEFAULT_SETTINGS
from core.recon.passive import gau_args


def test_gau_args_use_defaults():
    args = gau_args("example.com", DEFAULT_SETTINGS)

    assert args[:2] == ["example.com", "--subs"]
    assert args[args.index("--threads") + 1] == "5"
    assert args[args.index("--timeout") + 1] == "20"
    assert args[args.index("--providers") + 1] == "otx,urlscan"


def test_gau_args_can_restore_wayback_and_extra_flags():
    settings = {
        "gau": {
            "providers": ["wayback", "otx"],
            "threads": 2,
            "timeout": 0,
            "extra_args": ["--fp"],
        }
    }
    args = gau_args("example.com", settings)

    assert args[args.index("--providers") + 1] == "wayback,otx"
    assert args[args.index("--threads") + 1] == "2"
    assert "--timeout" not in args
    assert args[-1] == "--fp"


def test_gau_args_omit_providers_when_empty():
    args = gau_args("example.com", {"gau": {"providers": []}})

    assert "--providers" not in args
