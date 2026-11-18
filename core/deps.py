"""External dependency catalogue and ``reconx doctor`` implementation."""

from __future__ import annotations

from dataclasses import dataclass

from core import ui
from core.process import which


@dataclass(frozen=True)
class ToolSpec:
    name: str
    purpose: str
    install: str
    group: str = "recon"


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "waybackurls",
        "Passive URLs from the Wayback Machine",
        "go install github.com/tomnomnom/waybackurls@latest",
        "recon",
    ),
    ToolSpec(
        "gau",
        "Passive URLs from AlienVault, Common Crawl, URLScan…",
        "go install github.com/lc/gau/v2/cmd/gau@latest",
        "recon",
    ),
    ToolSpec(
        "uro",
        "URL de-duplication and noise filtering",
        "pipx install uro   # or: pip3 install --user uro",
        "recon",
    ),
    ToolSpec(
        "katana",
        "JavaScript-aware active crawler",
        "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "recon",
    ),
    ToolSpec(
        "subfinder",
        "Passive subdomain enumeration",
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "recon",
    ),
    ToolSpec(
        "unfurl",
        "URL field extraction (optional)",
        "go install github.com/tomnomnom/unfurl@latest",
        "optional",
    ),
    ToolSpec(
        "httpx",
        "HTTP probing (optional)",
        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "optional",
    ),
    ToolSpec(
        "nuclei",
        "Template-based vulnerability scanning",
        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "scan",
    ),
)

TOOL_MAP = {spec.name: spec for spec in TOOLS}

# Tools required by each subcommand.  ``unfurl``/``httpx`` are intentionally
# absent: ReconX implements their role natively.
REQUIRED = {
    "passive": ["waybackurls", "gau"],
    "active": ["katana"],
    "mass-fuzz": [],
    "single-fuzz": [],
    "aggregate": [],
}


def check(tools: list[str], *, quiet: bool = False) -> tuple[list[str], list[str]]:
    """Return ``(found, missing)`` for the requested tool names."""
    found: list[str] = []
    missing: list[str] = []
    for name in tools:
        path = which(name)
        if path:
            found.append(name)
            if not quiet:
                ui.debug(f"{name} -> {path}")
        else:
            missing.append(name)
    return found, missing


def doctor(*, show_optional: bool = True) -> bool:
    """Print a dependency report.  Returns True when all core tools exist."""
    ui.step("Dependency check")
    rows: list[tuple[str, str, str]] = []
    core_ok = True
    for spec in TOOLS:
        if spec.group == "optional" and not show_optional:
            continue
        path = which(spec.name)
        status = "OK" if path else "MISSING"
        rows.append((spec.name, status, spec.purpose))
        if spec.group == "recon" and not path:
            core_ok = False
    ui.table(rows, ("tool", "status", "purpose"))

    missing = [spec for spec in TOOLS if spec.group == "recon" and not which(spec.name)]
    if missing:
        print()
        ui.warn("Missing core tools — install them with:")
        for spec in missing:
            print(f"    {spec.install}")

    print()
    ui.info("Python engine needs: requests, click, PyYAML (pip install -r requirements.txt)")
    ui.info("Run './reconx doctor' after installing the Go tools to verify your PATH.")
    return core_ok
