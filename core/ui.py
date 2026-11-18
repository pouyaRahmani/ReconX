"""Console output helpers.

All modules print through this module so that colour handling, timestamps and
``--no-color`` behave consistently.  No third-party dependency is required.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

# ANSI sequences -------------------------------------------------------------
BOLD = "\033[1m"
DIM = "\033[2m"
GRAY = "\033[90m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

_COLOR = True
_VERBOSE = False
_UNICODE: bool | None = None


def _supports_unicode() -> bool:
    """Whether the current stdout encoding can render box-drawing characters."""
    global _UNICODE
    if _UNICODE is None:
        encoding = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
        normalised = encoding.replace("-", "").replace("_", "").replace(".", "")
        _UNICODE = "utf" in normalised or normalised == "cp65001"
        if normalised in {"ascii", "usascii", "cp1252", "latin1", "iso88591", "ansix341968"}:
            _UNICODE = False
    return _UNICODE


def configure(*, color: bool | None = None, verbose: bool = False) -> None:
    """Configure global output settings (called once by the CLI)."""
    global _COLOR, _VERBOSE, _UNICODE
    if color is not None:
        _COLOR = color
    else:
        _COLOR = (
            sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM", "") != "dumb"
        )
    _VERBOSE = verbose
    _UNICODE = None  # re-evaluate against the current stdout


def colorize(text: str, colour: str) -> str:
    """Wrap *text* in an ANSI colour when colour output is enabled."""
    if not _COLOR:
        return text
    return f"{colour}{text}{RESET}"


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    print(f"{colorize('[ * ]', BLUE)} {colorize(_stamp(), GRAY)} {msg}")


def ok(msg: str) -> None:
    print(f"{colorize('[ + ]', GREEN)} {colorize(_stamp(), GRAY)} {msg}")


def warn(msg: str) -> None:
    print(f"{colorize('[ ! ]', YELLOW)} {colorize(_stamp(), GRAY)} {msg}")


def error(msg: str) -> None:
    print(f"{colorize('[ - ]', RED)} {colorize(_stamp(), GRAY)} {msg}")


def debug(msg: str) -> None:
    if _VERBOSE:
        print(f"{colorize('[ d ]', DIM)} {colorize(_stamp(), GRAY)} {msg}")


def step(msg: str) -> None:
    """Print a section heading."""
    line = "─" if _supports_unicode() else "-"
    print()
    print(colorize(f"{line}{line} {msg} ", BOLD + CYAN) + colorize(line * max(0, 60 - len(msg)), GRAY))


def kv(key: str, value: object) -> None:
    """Print an aligned key/value pair."""
    print(f"  {colorize(str(key) + ':', GRAY)} {value}")


def banner(version: str = "2.0.0") -> None:
    """Print the ReconX banner (ASCII fallback for legacy terminals)."""
    if _supports_unicode():
        art = rf"""
{colorize('  ██████╗ ███████╗ ██████╗ ██████╗  ███╗   ██╗██╗  ██╗', CYAN + BOLD)}
{colorize('  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝', CYAN + BOLD)}
{colorize('  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ ', CYAN + BOLD)}
{colorize('  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ ', CYAN + BOLD)}
{colorize('  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗', CYAN + BOLD)}
{colorize('  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝', CYAN + BOLD)}
{colorize('  Modular Web Vulnerability Reconnaissance Framework', GRAY)}
{colorize(f'  v{version}', GRAY)}
"""
    else:
        lines = [
            r"  ____  _____ ____  _   _ __  __",
            r" |  _ \| ____|  _ \| \ | |\ \/ /",
            r" | |_) |  _| | | | |  \| | \  / ",
            r" |  _ <| |___| |_| | |\  | /  \ ",
            r" |_| \_\_____|____/|_| \_|/_/\_\ ",

        ]
        for line in lines:
            print(colorize(line, CYAN + BOLD))
        print(colorize("  Modular Web Vulnerability Reconnaissance Framework", GRAY))
        print(colorize(f"  v{version}", GRAY))
    if _supports_unicode():
        print(art)


def rule(char: str = "═", width: int = 64) -> None:
    if not _supports_unicode():
        char = "="
    print(colorize(char * width, GRAY))


def table(rows: list[tuple[str, str, str]], headers: tuple[str, str, str] | None = None) -> None:
    """Print a simple three-column table."""
    widths = [max(len(str(r[i])) for r in rows + ([headers] if headers else [])) for i in range(3)]
    separator = "─" if _supports_unicode() else "-"
    if headers:
        print("  " + "  ".join(colorize(str(h).ljust(widths[i]), BOLD) for i, h in enumerate(headers)))
        print("  " + colorize("  ".join(separator * w for w in widths), GRAY))
    for row in rows:
        print("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
