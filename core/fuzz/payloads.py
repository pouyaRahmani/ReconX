"""Payload file loading and small payload-analysis helpers."""

from __future__ import annotations

import re
from pathlib import Path

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_SLEEP_RE = re.compile(r"(?:pg_)?sleep\s*\(\s*(\d+(?:\.\d+)?)\s*\)", re.IGNORECASE)
_WAITFOR_RE = re.compile(
    r"waitfor\s+delay\s*'(\d{1,2}):(\d{1,2}):(\d{1,2})'", re.IGNORECASE
)
_REDIRECT_HOST_RE = re.compile(
    r"(?:https?:)?//([A-Za-z0-9.\-]+)|(?:^|[\s=/])((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})",
    re.IGNORECASE,
)


def load_payloads(path: str | Path, limit: int | None = None) -> list[str]:
    """Load a payload file, skipping blanks and ``#`` comments.

    Order is preserved and duplicates are removed.  When *limit* is set and the
    file is larger, the first *limit* payloads are used (the fuzzer enforces the
    same limit so this keeps the two in sync).
    """
    file_path = Path(path)
    if not file_path.is_file():
        return []
    payloads: list[str] = []
    seen: set[str] = set()
    try:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                payload = line.rstrip("\r\n").strip()
                if not payload or payload.startswith("#"):
                    continue
                if payload in seen:
                    continue
                seen.add(payload)
                payloads.append(payload)
    except OSError:
        return []
    if limit is not None and limit > 0:
        payloads = payloads[:limit]
    return payloads


def parse_header(payload: str) -> tuple[str, str] | None:
    """Parse ``Name: value`` header payloads.  Invalid lines return ``None``."""
    if ":" not in payload:
        return None
    name, value = payload.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not _HEADER_NAME_RE.match(name) or not value:
        return None
    if "\r" in value or "\n" in value:
        return None
    return name, value


def sleep_seconds(payload: str) -> float:
    """Return the delay requested by a time-based SQLi payload, else ``0``."""
    match = _SLEEP_RE.search(payload)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return 0.0
    match = _WAITFOR_RE.search(payload)
    if match:
        hours, minutes, seconds = (int(part) for part in match.groups())
        return float(hours * 3600 + minutes * 60 + seconds)
    return 0.0


def redirect_hosts(payload: str) -> list[str]:
    """Extract candidate redirect target hosts from an open-redirect payload."""
    hosts: list[str] = []
    for match in _REDIRECT_HOST_RE.finditer(payload):
        host = (match.group(1) or match.group(2) or "").lower().strip(".")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def is_time_based(payload: str) -> bool:
    return sleep_seconds(payload) > 0
