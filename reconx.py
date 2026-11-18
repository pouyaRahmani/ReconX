#!/usr/bin/env python3
"""ReconX entry point.

This file exists so the framework can be started with either::

    ./reconx ...
    python reconx.py ...
    python -m core.cli ...

The real implementation lives in :mod:`core.cli`.
"""

from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from core.cli import main  # noqa: E402  (path setup must happen first)
except ModuleNotFoundError as exc:  # missing third-party dependency
    missing = exc.name or "dependency"
    sys.stderr.write(
        f"ReconX: missing Python dependency '{missing}'.\n"
        "Run ./setup.sh to create the virtual environment and install requirements.\n"
        f"Manual alternative: python3 -m pip install -r {PROJECT_ROOT}/requirements.txt\n"
    )
    raise SystemExit(1) from None


if __name__ == "__main__":
    main()
