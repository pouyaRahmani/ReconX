"""Aggregation and reporting.

Findings are collected from every subdomain, deduplicated by fingerprint and
rendered as:

* ``<target>.txt``  – terminal-friendly report
* ``<target>.json`` – machine-readable export
* ``<target>.html`` – self-contained dashboard with client-side filtering
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from core import redact, ui
from core.models import Finding, SEVERITY_RANK, utc_now
from core.paths import TargetPaths, Workspace


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not path.is_file():
        return findings
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                try:
                    findings.append(Finding.from_dict(data))
                except Exception:
                    continue
    return findings


def _parse_legacy_hit(line: str) -> Finding | None:
    line = line.strip()
    if not line.startswith("[") or "]" not in line:
        return None
    prefix, _, rest = line.partition("]")
    vuln = prefix.lstrip("[").strip()
    if vuln.upper().startswith("NUCLEI:"):
        vuln = vuln.split(":", 1)[1]
    parts = [p.strip() for p in rest.strip().split("|")]
    while len(parts) < 5:
        parts.append("")
    url = parts[0]
    if not url.startswith(("http://", "https://")):
        return None
    try:
        status = int(parts[3]) if parts[3].isdigit() else 0
    except ValueError:
        status = 0
    finding = Finding(
        vuln=vuln.lower(),
        url=url,
        param=parts[1],
        payload=parts[2],
        status=status,
        evidence=" | ".join(parts[4:]) or "legacy hit",
        severity="medium",
        confidence="candidate",
        source="legacy",
    )
    finding.fingerprint = finding.compute_fingerprint()
    return finding


def collect_findings(target_paths: TargetPaths) -> tuple[list[Finding], list[str]]:
    """Return deduplicated findings and the list of scanned hosts."""
    findings: list[Finding] = []
    seen: set[str] = set()
    hosts = target_paths.hosts()

    for host in hosts:
        sub = target_paths.sub(host)
        for finding in _load_jsonl(sub.findings_file):
            finding = redact.redact_finding(finding)
            key = finding.fingerprint or finding.compute_fingerprint()
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    # Legacy files created by the draft implementation.
    for host in hosts:
        sub = target_paths.sub(host)
        if not sub.hits_file.is_file():
            continue
        with open(sub.hits_file, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                finding = _parse_legacy_hit(line)
                if not finding:
                    continue
                finding = redact.redact_finding(finding)
                key = finding.fingerprint or finding.compute_fingerprint()
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

    findings.sort(
        key=lambda f: (
            SEVERITY_RANK.get(f.severity.lower(), 9),
            f.vuln,
            f.url,
            f.param,
        )
    )
    return findings, hosts


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

def render_text(target: str, findings: list[Finding], hosts: list[str]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    severity_counts = Counter(f.severity.lower() for f in findings)
    vuln_counts = Counter(f.vuln for f in findings)
    confirmed = sum(1 for f in findings if f.confidence == "confirmed")

    lines: list[str] = []
    rule = "=" * 78
    lines += [
        rule,
        f" ReconX Report — {target}",
        rule,
        f" Generated : {now}",
        f" Scope     : {len(hosts)} subdomain(s)",
        f" Findings  : {len(findings)} ({confirmed} confirmed)",
        "",
        " Summary",
        " -------",
    ]
    for vuln, count in vuln_counts.most_common():
        lines.append(f"   {vuln:<24} {count}")
    lines.append("")
    lines.append(
        " Severity: "
        + ", ".join(
            f"{sev}={severity_counts.get(sev, 0)}"
            for sev in ("critical", "high", "medium", "low", "info")
        )
    )
    lines.append("")

    if not findings:
        lines.append(" No findings were recorded.")
        lines.append(rule)
        return "\n".join(lines)

    by_vuln: dict[str, list[Finding]] = {}
    for finding in findings:
        by_vuln.setdefault(finding.vuln, []).append(finding)

    for vuln, items in by_vuln.items():
        lines.append("-" * 78)
        lines.append(f" [{vuln}] — {len(items)} finding(s)")
        lines.append("-" * 78)
        for index, finding in enumerate(items, start=1):
            lines.append(
                f" {index:>3}. [{finding.severity.upper()}/{finding.confidence}] "
                f"{finding.method} {redact.url(finding.url)}"
            )
            if finding.param:
                lines.append(f"      parameter : {finding.param}")
            if finding.payload:
                lines.append(f"      payload   : {redact.text(finding.payload)[:200]}")
            if finding.template:
                lines.append(f"      template  : {finding.template}")
            lines.append(f"      source    : {finding.source}  status: {finding.status}")
            lines.append(f"      evidence  : {redact.text(finding.evidence)[:300]}")
            lines.append("")
    lines.append(rule)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def render_json(target: str, findings: list[Finding], hosts: list[str]) -> str:
    severity_counts = Counter(f.severity.lower() for f in findings)
    vuln_counts = Counter(f.vuln for f in findings)
    payload = {
        "target": target,
        "generated_at": utc_now(),
        "scope": {"subdomains": hosts, "subdomain_count": len(hosts)},
        "summary": {
            "total": len(findings),
            "confirmed": sum(1 for f in findings if f.confidence == "confirmed"),
            "by_severity": dict(severity_counts),
            "by_vuln": dict(vuln_counts),
        },
        "findings": [redact.redact_finding(f).to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconX Report — __TITLE__</title>
<style>
  :root {
    --bg:#0d1117; --panel:#161b22; --panel2:#1f2630; --border:#30363d;
    --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --pink:#ff7b9c;
    --critical:#ff4d6d; --high:#ff8c42; --medium:#e3b341; --low:#58a6ff; --info:#8b949e;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .wrap { max-width:1500px; margin:0 auto; padding:28px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin-bottom:22px; }
  .accent { color:var(--pink); }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
           gap:12px; margin-bottom:22px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px;
          padding:14px 16px; }
  .card .n { font-size:26px; font-weight:700; }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase;
             letter-spacing:.08em; }
  .controls { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
  input, select { background:var(--panel); color:var(--text); border:1px solid var(--border);
                  border-radius:8px; padding:9px 12px; font:inherit; }
  input { flex:1; min-width:240px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  th, td { padding:10px 12px; border-bottom:1px solid var(--border);
           vertical-align:top; text-align:left; }
  th { color:var(--muted); font-size:12px; text-transform:uppercase;
       letter-spacing:.06em; position:sticky; top:0; background:var(--panel2); }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:#1b222c; }
  .sev { font-weight:700; text-transform:uppercase; font-size:11px; }
  .critical { color:var(--critical); } .high { color:var(--high); }
  .medium { color:var(--medium); } .low { color:var(--low); } .info { color:var(--info); }
  .vuln { color:var(--pink); font-weight:600; }
  .muted { color:var(--muted); }
  code { color:#79c0ff; word-break:break-all; }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .pill { border:1px solid var(--border); border-radius:999px; padding:1px 8px;
          font-size:11px; color:var(--muted); }
  .empty { text-align:center; color:var(--muted); padding:40px; }
  @media (max-width:800px){ .wrap{padding:14px;} td,th{padding:8px;} }
</style>
</head>
<body><div class="wrap">
"""

_HTML_FOOT = """
</div>
<script>
const q = document.getElementById('q');
const sev = document.getElementById('sev');
const rows = Array.from(document.querySelectorAll('tbody tr[data-sev]'));
function apply() {
  const text = (q.value || '').toLowerCase();
  const wanted = sev.value;
  rows.forEach(row => {
    const okText = !text || row.innerText.toLowerCase().includes(text);
    const okSev = !wanted || row.dataset.sev === wanted;
    row.style.display = (okText && okSev) ? '' : 'none';
  });
}
q.addEventListener('input', apply);
sev.addEventListener('change', apply);
</script>
</body></html>
"""


def _esc(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def render_html(target: str, findings: list[Finding], hosts: list[str]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    severity_counts = Counter(f.severity.lower() for f in findings)
    vuln_counts = Counter(f.vuln for f in findings)
    confirmed = sum(1 for f in findings if f.confidence == "confirmed")

    cards = [
        (len(findings), "total findings"),
        (confirmed, "confirmed"),
        (severity_counts.get("critical", 0), "critical"),
        (severity_counts.get("high", 0), "high"),
        (len(vuln_counts), "vulnerability types"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="n">{n}</div><div class="l">{_esc(label)}</div></div>'
        for n, label in cards
    )

    por_vuln = " · ".join(
        f'<span class="vuln">{_esc(v)}</span> <span class="muted">×{c}</span>'
        for v, c in vuln_counts.most_common()
    ) or '<span class="muted">no findings</span>'

    options = "".join(
        f'<option value="{sev}">{sev}</option>'
        for sev in ("critical", "high", "medium", "low", "info")
    )

    rows: list[str] = []
    for finding in findings:
        url = redact.url(finding.url)
        safe_url = _esc(url)
        link = (
            f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_url}</a>'
            if url.startswith(("http://", "https://"))
            else safe_url
        )
        rows.append(
            "<tr data-sev=\"{sev}\">"
            "<td class=\"sev {sev}\">{sev}</td>"
            "<td class=\"vuln\">{vuln}</td>"
            "<td>{method}</td>"
            "<td>{url}</td>"
            "<td><code>{param}</code></td>"
            "<td><code>{payload}</code></td>"
            "<td class=\"muted\">{evidence}</td>"
            "<td><span class=\"pill\">{confidence}</span><br><span class=\"muted\">{source}</span></td>"
            "</tr>".format(
                sev=_esc(finding.severity.lower()),
                vuln=_esc(finding.vuln),
                method=_esc(finding.method),
                url=link,
                param=_esc(redact.text(finding.param)),
                payload=_esc(redact.text(finding.payload or "")[:160]),
                evidence=_esc(redact.text(finding.evidence or "")[:300]),
                confidence=_esc(finding.confidence),
                source=_esc(finding.source),
            )
        )

    table = (
        "<table><thead><tr>"
        "<th>Severity</th><th>Type</th><th>Method</th><th>URL</th>"
        "<th>Parameter</th><th>Payload</th><th>Evidence</th><th>Confidence</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    if not findings:
        table = '<div class="card empty">No findings were recorded for this target.</div>'

    head = _HTML_HEAD.replace("__TITLE__", _esc(target))
    body = (
        f'<h1><span class="accent">ReconX</span> Report — {_esc(target)}</h1>'
        f'<div class="sub">Generated {_esc(now)} · {len(hosts)} subdomain(s) · {por_vuln}</div>'
        f'<div class="cards">{card_html}</div>'
        '<div class="controls">'
        '<input id="q" type="search" placeholder="Filter by URL, parameter, payload…">'
        f'<select id="sev"><option value="">all severities</option>{options}</select>'
        "</div>"
        f"{table}"
    )
    return head + body + _HTML_FOOT


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def aggregate(
    workspace: Workspace,
    target: str,
    formats: list[str] | tuple[str, ...] | None = None,
) -> int:
    """Collect findings and write the configured report formats."""
    target_paths = workspace.target(target)
    findings, hosts = collect_findings(target_paths)
    formats = [f.lower() for f in (formats or ["txt", "json", "html"])]

    output_dir = target_paths.output
    output_dir.mkdir(parents=True, exist_ok=True)

    if "txt" in formats:
        path = output_dir / f"{target}.txt"
        path.write_text(render_text(target, findings, hosts), encoding="utf-8")
        ui.ok(f"text report  → {path}")
    if "json" in formats:
        path = output_dir / f"{target}.json"
        path.write_text(render_json(target, findings, hosts), encoding="utf-8")
        ui.ok(f"json report  → {path}")
    if "html" in formats:
        path = output_dir / f"{target}.html"
        path.write_text(render_html(target, findings, hosts), encoding="utf-8")
        ui.ok(f"html report  → {path}")

    _print_summary(target, findings, hosts)
    return len(findings)


def _print_summary(target: str, findings: list[Finding], hosts: list[str]) -> None:
    severity_counts = Counter(f.severity.lower() for f in findings)
    vuln_counts = Counter(f.vuln for f in findings)
    confirmed = sum(1 for f in findings if f.confidence == "confirmed")

    print()
    ui.rule()
    print(f"{ui.colorize('  ReconX summary', ui.BOLD)} — {target}")
    ui.rule()
    ui.kv("subdomains", len(hosts))
    ui.kv("findings", f"{len(findings)} ({confirmed} confirmed)")
    ui.kv(
        "severity",
        ", ".join(f"{s}={severity_counts.get(s, 0)}" for s in ("critical", "high", "medium", "low")),
    )
    if vuln_counts:
        print()
        for vuln, count in vuln_counts.most_common():
            colour = ui.RED if vuln in {"sqli", "xss"} else ui.YELLOW
            print(f"  {ui.colorize(f'[{vuln}]', colour)} {count} finding(s)")
    else:
        print("  no findings were recorded")
    ui.rule()
    print()
