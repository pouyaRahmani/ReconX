# ReconX

**ReconX** is a modular web-vulnerability reconnaissance framework for authorised
security testing. It combines passive/active URL discovery with a native,
rate-limited fuzzing engine and a curated Nuclei template set.

ReconX is the implementation of the framework described in
[`project_proposal.tex`](project_proposal.tex). It replaces the earlier
shell-pipeline drafts with a single Python package (`core/`) that is safe to run
against real scopes.

> **Authorised testing only.** You must have explicit permission to test every
> host you point ReconX at. The default rate limit is deliberately conservative;
> do not raise it beyond what your scope allows.

📖 **New to ReconX?** Read the [complete usage guide](USAGE.md) for every command,
switch, configuration field, workflow, detection rule, and troubleshooting step.
It is the reference for the Python edition described below.

---

## Highlights

- **Passive recon** — `waybackurls` + `gau` + `uro`, normalised and filtered in
  Python (static assets, duplicates, out-of-scope hosts).
- **Active crawl** — `katana` in JSONL mode, capturing methods, POST bodies,
  JSON content types and HTML forms, not just URLs.
- **Parameter intelligence** — extracts query/body/form parameters, merges them
  across pages of the same subdomain, and (opt-in) across subdomains.
- **Native fuzzing engine** — threaded `requests` engine with a global
  token-bucket rate limiter, baseline comparison, request budgets, and
  per-subdomain resumable state.
- **Vulnerability classes** — `xss`, `sqli`, `open-redirect`,
  `headers-reflection`, `headers-status`, `cache-poison`.
- **Nuclei integration** — runs the project’s own optimised templates
  (`nuclei-templates/`), optionally with community tags, and stores findings in
  the same JSONL store.
- **Reporting** — text, JSON and a self-contained dark HTML dashboard with
  client-side filtering.
- **Safe by construction** — every external tool is executed with an argument
  list (never a shell), target data cannot escape `results/`, and methods /
  vulnerabilities are validated before a request is sent.

---

## Requirements

| Component | Version |
|-----------|---------|
| Python | 3.9+ |
| `click` | 8.1+ |
| `requests` | 2.31+ |
| `PyYAML` | 6.0+ |
| Go tools | current releases |

ReconX shells out to these tools when the relevant command is used:

| Tool | Used by | Install |
|------|---------|---------|
| `waybackurls` | `passive` | `go install github.com/tomnomnom/waybackurls@latest` |
| `gau` | `passive` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `uro` | `passive` (optional) | `pipx install uro` |
| `katana` | `active` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `subfinder` | `passive --enumerate` (optional) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `nuclei` | `mass-fuzz` / `single-fuzz` (optional) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

---

## Installation (WSL Kali)

```bash
cd ~/ReconX

# 1. Python environment + dependencies
./setup.sh

# 2. Verify the external tools
./reconx doctor
```

`setup.sh` creates `.venv/`, installs the Python dependencies and makes the
launcher executable. The launcher automatically prefers `.venv/bin/python`, so
you can run `./reconx` without activating the environment.

Manual installation:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x reconx
```

---

## Quick start

```bash
# 1. Discover archived URLs for a domain.
./reconx passive -t acme acme.test

# 2. Crawl every discovered subdomain with Katana (JS + forms).
./reconx active -t acme

# 3. Create and edit a target config.
./reconx init acme --seed https://acme.test
$EDITOR target-configs/acme.json

# 4. Run the full pipeline (params -> templates -> fuzz -> nuclei -> report).
./reconx mass-fuzz -c target-configs/acme.json

# 5. Check progress at any time.
./reconx status -t acme

# 6. Re-generate reports.
./reconx aggregate -t acme
```

Fuzz one URL directly (useful for a single endpoint):

```bash
./reconx single-fuzz \
  -c target-configs/acme.json \
  --method POST \
  --data 'username=test&password=test' \
  https://acme.test/login
```

---

## CLI reference

```
./reconx [--no-color] [--debug] <command> ...

passive      Gather archived URLs (waybackurls + gau + uro).
             ./reconx passive -t NAME SEED [--subs FILE] [--enumerate]
                              [--no-wayback] [--no-gau] [--no-uro]
                              [--max-hosts N] [-c CONFIG]

active       Crawl subdomains with Katana (JS + forms).
             ./reconx active -t NAME [--sub HOST] [--depth N] [--refresh]
                            [--header 'Name: value'] [-c CONFIG]

mass-fuzz    Full pipeline over all subdomains of a target.
             ./reconx mass-fuzz -c CONFIG [--only HOST] [--resume]
                                [--keep-templates] [--skip-fuzz]
                                [--skip-nuclei] [--refresh-params]
                                [--refresh-fuzz] [--max-hosts N]
                                [--rl N] [--workers N] [--timeout N]
                                [--vulns LIST] [--methods LIST]
                                [--chunk-size N]

single-fuzz  Fuzz an arbitrary URL through the same pipeline.
             ./reconx single-fuzz -c CONFIG URL [--method M] [--data BODY]
                                  [--param NAME] [--content-type CT]
                                  [--skip-nuclei] [--keep-templates/--no-keep-templates]

aggregate    Rebuild reports for a target.
             ./reconx aggregate -t NAME [--format txt|json|html]...

status       Show per-target / per-subdomain progress.
             ./reconx status [-t NAME]

clean        Delete all results (or one subdomain) for a target.
             ./reconx clean -t NAME [--sub HOST] [--yes]

doctor       Check external tool availability.
             ./reconx doctor [--no-optional] [--json]

init         Create a starter target config.
             ./reconx init NAME [--seed URL]... [--force]

validate     Validate a target config and print the normalised form.
             ./reconx validate CONFIG
```

Global options:

- `--no-color` — disable ANSI colours (also honours `NO_COLOR`).
- `--debug` / `-d` — verbose tool and request logging.
- `--version` / `-V` — print the version.

Every command and switch is documented in detail in [`USAGE.md`](USAGE.md),
including defaults, resume semantics, recipes, and troubleshooting.

---

## Target configuration

Every target has a JSON file in `target-configs/`. Minimal file:

```json
{
  "target": "acme",
  "seeds": ["https://acme.test"],
  "vulns": ["xss", "sqli", "open-redirect"],
  "methods": ["GET", "POST"],
  "content_types": ["urlencoded", "json"],
  "rl": 20,
  "c": 10,
  "timeout": 60
}
```

The full schema is in [`target-configs/schema.json`](target-configs/schema.json)
and a documented example is in
[`target-configs/sample.json`](target-configs/sample.json).

Important fields:

| Field | Meaning |
|-------|---------|
| `target` | Results directory name (`results/<target>/`). |
| `sub` | Limit the pipeline to one subdomain. |
| `seeds` | Seed URLs; used to derive scope when `scope_domains` is empty. |
| `vulns` | Any of `xss`, `sqli`, `open-redirect`, `headers-reflection`, `headers-status`, `cache-poison`. |
| `methods` | Methods eligible for parameter fuzzing. |
| `content_types` | Body encodings used for body parameters. |
| `chunk_size` | Parameters sent per fuzz request. |
| `rl` / `c` | Global requests per second / worker threads. |
| `timeout` | Per-request timeout. Use **>= 20 s** for time-based SQLi (`SLEEP(15)`). |
| `max_requests` | Hard request budget per subdomain (default 20 000). |
| `cross_page_params` | Merge parameters across endpoints of the same method/location. |
| `cross_sub_passive_params` | Also merge passive parameters across subdomains. |
| `ignore_params` | `fnmatch` patterns excluded from fuzzing (`utm_*`, `fbclid`, …). |
| `scope_domains` | Explicit scope. When empty, the registrable seed domain is used. |
| `nuclei` | Per-target Nuclei overrides (`enabled`, `dast`, `severity`, `max_urls`, …). |
| `notifications` | Telegram/webhook delta alerts (`enabled`, `only_on_diff`, bot token/chat id, webhook URL). |
| `output.formats` | Report formats (`txt`, `json`, `html`). |

The loader warns about unknown keys, validates methods/vulnerabilities/content
types, and refuses invalid numeric values.

### Notifications

`mass-fuzz` and `single-fuzz` can send a summary after aggregation. Configure
the global defaults in `config/settings.yaml`:

```yaml
notifications:
  enabled: true
  only_on_diff: true          # only notify when hosts/findings changed
  telegram_bot_token: "123456:ABC..."
  telegram_chat_id: "123456789"
  webhook_url: "https://hooks.example.com/reconx"
```

Both channels are optional; when both are set the same redacted message is
delivered to each. The webhook receives JSON with `text`, `content`, `target`,
`run_id` and a `diff` object. Delivery failures are warnings, never fatal.

---

## Results layout

```
results/<target>/
├── state.json                      # resumable progress
├── shared_params.json              # cross-subdomain parameter merge (opt-in)
├── subdomains.txt
├── subdomains/<host>/
│   ├── <host>.passive              # archived URLs
│   ├── <host>.katana               # crawled URLs
│   ├── <host>.katana.requests.jsonl# structured requests (method/body/forms)
│   ├── params.json                 # endpoints, parameters, samples
│   ├── crawl-parametrized/
│   │   ├── urls.txt
│   │   └── targets.txt
│   ├── templates/                  # generated jobs (kept with --keep-templates)
│   │   ├── all.jsonl
│   │   ├── summary.txt
│   │   └── <vuln>/jobs.jsonl
│   └── fuzz/
│       ├── findings.jsonl          # canonical machine-readable store
│       ├── hits.txt                # legacy human-readable lines
│       ├── nuclei_targets.txt
│       ├── nuclei.jsonl
│       └── evidence/<fingerprint>.txt
└── output/
    ├── <target>.txt
    ├── <target>.json
    └── <target>.html
```

Set `RECONX_RESULTS=/some/dir` to use a different results root (useful for
tests and for keeping scopes separate).

---

## How the pipeline works

```
passive ──► <host>.passive ─┐
                            ├─► params.json ─► templates ─► fuzz engine ─┐
active  ──► <host>.katana ──┘       │                                   ├─► findings.jsonl
        └─► .requests.jsonl ────────┘                                   │
                                                                        ├─► nuclei.jsonl
nuclei  ─────────────────────────────────────────────────────────────────┘
                                                                        │
                                                             aggregate ─┴─► output/*
```

1. **Parameter extraction** builds `Endpoint` objects:
   `(url, method, location=query|body|header, content_type, params, samples)`.
   Query parameters come from passive/crawled URLs; body parameters come from
   Katana request records (urlencoded, JSON, multipart) and forms.
2. **Cross-page merge** (default on) adds parameters observed on sibling
   endpoints with the same method/location/body type. The original sample value
   is preserved so non-fuzzed parameters keep working.
3. **Cross-subdomain merge** (opt-in) counts passive parameters across hosts and
   injects the most frequent `shared_param_limit` names into GET endpoints.
4. **Template generation** creates JSONL jobs: one per
   `(vuln, endpoint, parameter chunk, payload file)`, plus header jobs for
   `headers-*` / `cache-poison`.
5. **Fuzzing** fetches a clean baseline per job, then sends payloads with a
   global rate limiter. Time-based SQLi jobs run serially so latency is
   meaningful. Findings are deduplicated by fingerprint.
6. **Nuclei** runs against a bounded URL list, using `nuclei-templates/` by
   default. JSONL results are merged into the same finding store.
7. **Aggregation** deduplicates across subdomains and writes txt/json/html.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module-level details.

---

## Detection notes

| Class | Evidence used |
|-------|---------------|
| `xss` | Payload appears in the response body (and not in the baseline); HTML/text content types increase confidence. |
| `sqli` | Database error signatures or a measured `SLEEP(15)` / `pg_sleep(15)` / `WAITFOR DELAY` delay relative to baseline. |
| `open-redirect` | `Location`/`Refresh` header or body redirect points to the payload host, which differs from the request host. |
| `headers-reflection` | An injected header canary appears in the response body or response headers, but not in the baseline. |
| `headers-status` | A protected path changes from `401/403/404/405` to `200/2xx/3xx` (or a large body change) after a bypass header. |
| `cache-poison` | An unkeyed header canary is reflected **and** a cache indicator (`X-Cache`, `CF-Cache-Status`, `Age`, …) is present. |

Findings carry `confidence` (`confirmed`, `candidate`, `info`) and `severity` so
you can triage quickly. Always verify candidates manually before reporting them.

### Time-based SQLi

`sleep.txt` uses 15-second delays. ReconX skips those jobs when
`timeout < 18` and warns during config validation. The detector also compares
against the baseline latency and ignores responses that are not slower than the
configured `sleep_threshold`. Run one target at a time and keep `rl` low when
testing time-based payloads.

---

## Nuclei templates

`nuclei-templates/` contains six project templates:

- `reconx-xss.yaml` — reflected XSS in query/body parameters.
- `reconx-sqli.yaml` — SQL error signatures.
- `reconx-open-redirect.yaml` — off-site `Location`/`Refresh`/body redirects.
- `reconx-headers-reflection.yaml` — proxy header canary reflection.
- `reconx-headers-status.yaml` — `/admin` access-control bypass comparison.
- `reconx-cache-poison.yaml` — unkeyed header reflection + cache indicators.

They require Nuclei’s DAST mode; ReconX adds `-dast` automatically when
`nuclei.dast` is true. Disable Nuclei for a run with `--skip-nuclei`, or
globally with `"nuclei": {"enabled": false}`.

---

## Safety controls

- External tools run via `subprocess` with argument lists — no `shell=True`.
- Target/host names are sanitised before becoming directory names; `clean`
  refuses to delete outside `results/`.
- `rl`, `c`, `timeout`, `max_requests`, `max_jobs` and `max_payloads` bound the
  work.
- Methods and vulnerability names are validated against allow-lists.
- Static assets and ignored tracking parameters are filtered before fuzzing.
- Open-redirect checks never follow redirects, so the raw `Location` is visible.
- Findings, evidence files, reports and notifications pass through
  `core/redact.py`: `Authorization`/`Cookie`/API-key headers, sensitive query
  parameters, Bearer tokens, JWTs and `password=...` pairs are masked. The
  fingerprint is preserved so deduplication stays stable.
- Use `proxy` in the target config to route traffic through Burp/ZAP.

---

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

python -m py_compile $(find core -name '*.py') reconx.py
pytest
```

Tests use `tmp_path` and `RECONX_RESULTS`, so they do not touch real results.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `tool not found on PATH` | Install the Go tool and add `$(go env GOPATH)/bin` to `PATH`; run `./reconx doctor`. |
| `PyYAML is required` | `pip install -r requirements.txt` (or use `./setup.sh`). |
| `timeout=... too short for SLEEP(15)` | Set `timeout` to at least 20. |
| No subdomain directories | Run `passive` first, then `active`. |
| No parameters found | The scope may have no archived query strings; use `single-fuzz` or provide `--param`. |
| Nuclei finds nothing | Check `nuclei-templates/` exists, `nuclei` is installed, and `-dast` is enabled. |
| Too many requests | Lower `rl` and `c`, reduce `max_requests`, or narrow `scope_domains`. |

---

## Project layout

```
.
├── reconx                  # bash launcher (prefers .venv)
├── reconx.py               # python entry point
├── USAGE.md                # complete usage guide
├── README.md               # project overview
├── core/
│   ├── cli.py              # Click commands
│   ├── config_loader.py    # settings + target validation
│   ├── deps.py             # tool catalogue / doctor
│   ├── models.py           # dataclasses (Endpoint, FuzzJob, Finding…)
│   ├── nuclei.py           # nuclei runner + JSONL parser
│   ├── params.py           # parameter extraction / merging
│   ├── paths.py            # results layout
│   ├── pipeline.py         # mass-fuzz / single-fuzz orchestration
│   ├── process.py          # safe subprocess helpers
│   ├── report.py           # txt/json/html reports
│   ├── state.py            # resumable state
│   ├── templates.py        # fuzz job generation
│   ├── ui.py               # console output
│   ├── recon/              # passive, active (Katana), URL utilities
│   └── fuzz/               # engine, detectors, payloads, finding store
├── config/
│   ├── settings.yaml
│   └── payloads/           # xss, sqli, sleep, open-redirect, headers, cache
├── nuclei-templates/       # project templates
├── target-configs/         # per-target JSON + schema
├── scripts/                # original reference scripts
├── tests/                  # pytest suite
└── results/                # generated output (git-ignored)
```

---

## Credits

Framework design and implementation for the ReconX proposal by
**Pouya Rahmani** and **Samaneh Mirhosseini**. The passive/active behaviour is
inspired by the original `nice_passive.py` and `nice_katana` scripts in
`scripts/`.

Use ReconX responsibly and only within an authorised scope.
