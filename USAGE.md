# ReconX usage guide

This is the complete user guide for the **Python edition** of ReconX (version
`2.0.0`). It explains every command, every switch, both configuration layers,
the five-stage workflow, the detection rules, the output files, and a set of
copy-paste recipes.

If you only read one paragraph, read this one:

> ReconX is an authorised-testing tool. Point it only at systems you own or have
> explicit written permission to test. The default settings are deliberately
> conservative, but the bundled SQLi payloads include destructive statements and
> cache-poison checks can affect shared caches. Read
> [Safety and scope](#2-safety-and-scope) before your first run.

---

## Contents

1. [What ReconX does](#1-what-reconx-does)
2. [Safety and scope](#2-safety-and-scope)
3. [Installation](#3-installation)
4. [Five-minute walkthrough](#4-five-minute-walkthrough)
5. [Command reference](#5-command-reference)
6. [Configuration reference](#6-configuration-reference)
7. [How the pipeline behaves](#7-how-the-pipeline-behaves)
8. [Vulnerability classes and findings](#8-vulnerability-classes-and-findings)
9. [Results, reports, notifications, redaction](#9-results-reports-notifications-redaction)
10. [Rate limits, budgets, and performance](#10-rate-limits-budgets-and-performance)
11. [Practical recipes](#11-practical-recipes)
12. [Troubleshooting](#12-troubleshooting)
13. [Limitations and FAQ](#13-limitations-and-faq)
14. [Environment variables and exit codes](#14-environment-variables-and-exit-codes)

---

## 1. What ReconX does

ReconX takes a target domain through five stages:

```
  1. PASSIVE              2. ACTIVE               3. PARAMETERS
  waybackurls + gau  ──►  katana (JS + forms) ──► params.json
  + uro                   structured requests      (endpoints, samples)

  4. FUZZ                                          5. REPORT
  generated jobs ──► HTTP engine ──► findings  ──► output/<target>.{txt,json,html}
                    + Nuclei templates
```

The important idea is that ReconX does not fuzz a list of URLs blindly. It
builds an **endpoint model**:

```text
(url without query, method, location=query|body|header, content_type,
 parameter names, original sample values)
```

That model is what makes POST bodies, JSON APIs, HTML forms, and header-based
checks work with the same pipeline. Parameters are fuzzed in chunks; every
non-fuzzed parameter keeps its original sample value so requests stay valid.

ReconX stores everything under `results/<target>/`, can resume per subdomain,
deduplicates findings by fingerprint, and produces a self-contained HTML
dashboard as well as text and JSON reports.

---

## 2. Safety and scope

### Authorisation

Only test hosts that are in scope for you. "In scope" means you own them or you
have explicit permission from the owner. A bug-bounty program page is not a
blanket permission; read its scope and rules.

### Intrusive checks

The built-in payload sets are real attack strings, not harmless placeholders:

| File | What it contains | Risk |
|------|------------------|------|
| `config/payloads/xss.txt` | script/img/svg payloads | Stored or reflected XSS may fire in a browser that later views the page. |
| `config/payloads/sqli.txt` | error, UNION, `DROP TABLE`, `INSERT`, `xp_cmdshell` payloads | A vulnerable database could be modified or damaged. |
| `config/payloads/sleep.txt` | 15-second time delays | Loads the target; noisy in logs and monitoring. |
| `config/payloads/open-redirect.txt` | off-site redirect payloads | Low impact, but can poison links if the app stores them. |
| `config/payloads/headers-*.txt` | proxy/IP/override headers | Can bypass access controls or reveal internal routing. |
| `config/payloads/cache-poison.txt` | unkeyed header canaries | Can poison a shared CDN or reverse-proxy cache. |

For a first pass, restrict `vulns` to `xss`, `open-redirect`, and
`headers-reflection`, keep `rl` low, and use a proxy. Add `sqli`, `headers-status`,
and `cache-poison` only when your authorisation and the target's criticality
allow it. You can also edit or replace the payload files; ReconX reads them at
job-generation time.

### Practical guardrails

- Keep `scope_domains` explicit. The automatic scope guess is intentionally
  simple and can be wrong for multi-level suffixes (`co.uk`, `com.au`, ...).
- Do not raise `rl` or `c` beyond what the target or program allows.
- Use `max_requests` and `max_jobs` as hard stops.
- Use `proxy` (Burp/ZAP) when you need a record of every request.
- Never commit real cookies, bearer tokens, or target configs containing them.
- Treat every finding as a lead, not a confirmed vulnerability. Verify manually.
- Run one fuzzing process per target at a time; `rl` is enforced *inside* one
  process, not across processes.

---

## 3. Installation

### Requirements

| Component | Version / notes |
|-----------|-----------------|
| Python | 3.9 or newer |
| `click` | 8.1+ |
| `requests` | 2.31+ |
| `PyYAML` | 6.0+ |
| Go | current release, for the external recon tools |
| OS | Linux/WSL is the supported path; the Python engine also runs on native Windows |

### Supported install: WSL Kali / Linux

```bash
cd ~/ReconX

# Creates .venv, installs Python dependencies, makes ./reconx executable,
# fixes the shell PATH (Go bin + ~/.local/bin) and the oh-my-zsh `gau` alias,
# then prints a dependency report. `bash setup.sh` also works when the script
# is not executable (git clones from Windows stores mode 100644).
bash setup.sh

# Optional: `go install` waybackurls, gau, katana, subfinder, nuclei
# and `pipx install uro`.
bash setup.sh --install-tools

# Verify external tools at any time.
./reconx doctor
```

The `./reconx` launcher prefers `$RECONX_VENV/bin/python`, then `.venv/bin/python`,
then `python3` on `PATH`. You do not need to activate the virtual environment.

> **oh-my-zsh `gau` alias.** The oh-my-zsh `git` plugin defines
> `alias gau='git add --update'`, which shadows the `gau` URL collector.
> `setup.sh` appends `unalias gau` to `~/.zshrc` after oh-my-zsh has loaded;
> open a new shell (or run `unalias gau`) if you configured your shell before
> this run.

### Manual install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x reconx
./reconx doctor
```

If `python3 -m venv` fails on Kali/Debian:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

### Native Windows

The Python engine can be started without the bash launcher:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python reconx.py doctor
.\.venv\Scripts\python reconx.py passive -t acme acme.test
```

The Go tools must be installed separately and be on `PATH`. WSL is still the
least surprising environment for Katana and the passive tooling.

### External tools

ReconX shells out to these tools. Every command runs with an argument list, never
through a shell.

| Tool | Used by | Install |
|------|---------|---------|
| `waybackurls` | `passive` | `go install github.com/tomnomnom/waybackurls@latest` |
| `gau` | `passive` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `uro` | `passive` (optional filter) | `pipx install uro` |
| `katana` | `active` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `subfinder` | `passive --enumerate` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `nuclei` | `mass-fuzz` / `single-fuzz` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

Add the Go bin directory to `PATH` (put it **first** so the real binaries win):

```bash
export PATH="$(go env GOPATH)/bin:$HOME/.local/bin:$PATH"   # add to ~/.bashrc or ~/.zshrc
```

`setup.sh` does this for you and also appends `unalias gau` so that
oh-my-zsh's `gau='git add --update'` alias cannot shadow the tool.

`unfurl` and `httpx` appear in `doctor` as optional tools, but ReconX implements
their roles natively and does not need them.

### Check the install

```bash
./reconx doctor                 # human-readable table
./reconx doctor --no-optional   # core tools only
./reconx doctor --json          # machine-readable; path is null when missing
./reconx --version
```

`doctor` reports a tool as `MISSING` when it is not on `PATH`. A missing optional
tool is fine; a missing core tool degrades `passive` or `active`.

---

## 4. Five-minute walkthrough

This example uses the fictional authorised scope `acme.test`. Replace it with a
host you are allowed to test.

### Step 1 - passive URL discovery

```bash
./reconx passive -t acme acme.test
```

This runs `waybackurls` and `gau`, filters the output through `uro` when
available, normalises and de-duplicates URLs, drops static assets and
out-of-scope hosts, and writes:

```text
results/acme/subdomains.txt
results/acme/subdomains/acme.test/acme.test.passive
```

Every requested host also gets an implicit `https://<host>/` entry, so later
stages always have a starting point.

### Step 2 - active crawl

```bash
./reconx active -t acme
```

Katana crawls every subdomain directory under `results/acme/subdomains/`. It
captures plain URLs, methods, request bodies, content types, and HTML forms:

```text
results/acme/subdomains/acme.test/acme.test.katana
results/acme/subdomains/acme.test/acme.test.katana.requests.jsonl
```

Crawl output is reused on the next run unless you pass `--refresh`.

### Step 3 - create a target config

```bash
./reconx init acme --seed https://acme.test
$EDITOR target-configs/acme.json
./reconx validate target-configs/acme.json
```

`init` writes a starter file from the documented sample. `validate` prints the
normalised configuration, including derived scope and merged nested settings.

### Step 4 - run the fuzzing pipeline

```bash
./reconx mass-fuzz -c target-configs/acme.json
```

For every subdomain, `mass-fuzz` extracts parameters, generates fuzz jobs, runs
the HTTP engine, runs Nuclei (unless disabled), removes generated templates by
default, records progress in `state.json`, and finally aggregates the findings.

Useful first-pass variants:

```bash
# Inspect generated jobs without sending payloads.
./reconx mass-fuzz -c target-configs/acme.json --skip-fuzz --skip-nuclei --keep-templates

# One host only.
./reconx mass-fuzz -c target-configs/acme.json --only acme.test

# Resume a run that was interrupted.
./reconx mass-fuzz -c target-configs/acme.json --resume
```

### Step 5 - inspect and report

```bash
./reconx status -t acme
./reconx aggregate -t acme
```

Reports are written to `results/acme/output/acme.{txt,json,html}`. Open the HTML
file in a browser for the filterable dashboard.

### Fuzz one URL directly

```bash
./reconx single-fuzz \
  -c target-configs/acme.json \
  --method POST \
  --data 'username=test&password=test' \
  --content-type urlencoded \
  https://acme.test/login
```

This does not require a prior passive/active run. It synthesises a one-host
`params.json`, records the host in `subdomains.txt`, fuzzes it, runs Nuclei
unless `--skip-nuclei` is passed, prints the hit list, and aggregates.

---

## 5. Command reference

### Global options

```text
./reconx [--no-color] [--debug] [--version] <command> ...
```

| Option | What it does |
|--------|--------------|
| `--no-color` | Disable ANSI colour. The `NO_COLOR` environment variable is also honoured. |
| `--debug`, `-d` | Verbose output: external commands, loaded config paths, request errors, worker errors. Useful for diagnosis; avoid sharing debug logs blindly. |
| `--version`, `-V` | Print `reconx, version 2.0.0` and exit. |
| `-h`, `--help` | Help for the group or any subcommand. |

Running `./reconx` with no subcommand prints the group help.

---

### `passive`

Gather archived URLs from the Wayback Machine and public sources.

```text
./reconx passive SEED [options]
```

| Argument / option | Default | Meaning |
|-------------------|---------|---------|
| `SEED` | required | Domain or URL to start from. `acme.test` and `https://acme.test` are both accepted. |
| `-t`, `--target NAME` | seed host | Results directory name. |
| `--subs FILE` | none | File of additional subdomains, one per line. |
| `--enumerate` | off | Run `subfinder` to discover more subdomains. |
| `--no-wayback` | off | Skip `waybackurls`. |
| `--no-gau` | off | Skip `gau`. |
| `--no-uro` | off | Skip the `uro` filter. |
| `--max-hosts N` | `500` | Cap the number of hosts processed. |
| `-c`, `--config FILE` | none | Target config used for `scope_domains`, `exclude_extensions`, seeds, and `sub`. |

Behaviour:

1. Builds the host list from the seed, the config seeds and `sub`, `--subs`,
   the existing `subdomains.txt`, and (with `--enumerate`) `subfinder`.
2. Runs `waybackurls` with the host on stdin and `gau <host> --threads 1 --subs`.
3. Optionally pipes the combined output through `uro`.
4. Normalises every URL: lower-case host, IDNA, default-port removal, sorted
   query parameters, fragment removal.
5. Drops non-HTTP(S), static-asset, malformed, and out-of-scope URLs.
6. Buckets URLs by host, including hosts discovered by `gau --subs`, and writes
   one `<host>.passive` file per host.
7. Writes the host inventory to `results/<target>/subdomains.txt`.

If a tool is missing or times out, the run continues with the remaining tools
and prints a warning. A failed refresh does **not** overwrite an existing
`<host>.passive` with an empty file.

With `-c`, the config's `target` must match `-t` if both are given. The config is
only used for scope and filtering in this stage; rate limits and fuzzing options
do not affect `passive`.

Examples:

```bash
./reconx passive -t acme acme.test
./reconx passive -t acme acme.test --enumerate --max-hosts 200
./reconx passive -t acme acme.test --subs scoped-subdomains.txt
./reconx passive -t acme acme.test -c target-configs/acme.json
```

---

### `active`

Actively crawl subdomains with Katana, including JavaScript endpoints and forms.

```text
./reconx active -t NAME [options]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-t`, `--target NAME` | required | Target whose subdomain directories should be crawled. |
| `--sub HOST` | all | Limit to one or more specific subdomains. Repeatable. |
| `--depth N` | `3` | Katana crawl depth. Minimum 1. |
| `--refresh` | off | Re-crawl even when existing Katana output is present. |
| `--max-seeds N` | settings `max_seeds` (`120`) | Cap seed URLs per host after prioritisation. `0` means no cap. |
| `--no-forms` | off | Disable Katana automatic form filling (`-aff`). Faster. |
| `--no-js` | off | Disable JavaScript crawling (`-jc`, `-jsl`). Faster, but misses JS endpoints. |
| `--duration N` | none | Abort the crawl after N seconds. Partial results are kept. |
| `--header 'Name: value'` | none | Extra request header. Repeatable. Merged over config headers. |
| `-c`, `--config FILE` | none | Target config for rate limit, concurrency, timeout, proxy, headers, and extensions. |

Behaviour:

- Requires at least one subdomain directory. Run `passive` first.
- Katana runs in JSONL mode with `-or` (omit raw blobs) and `-fx` (extract form
  fields). It captures method, body, content type, status, and forms.
- Only URLs and records whose host exactly matches the crawled subdomain are
  kept.
- Seeds come from `<host>.passive`; if that is empty, `https://<host>/` is used.
  Seeds are de-duplicated by path (preferring variants with a query string),
  ordered shallow-first, then capped.
- If a host does not resolve and no proxy is configured, it is skipped with a
  warning.
- Existing non-empty Katana output is reused unless `--refresh` is passed.
- `SIGTERM` or `--duration` leaves partial output in place.
- Crawl results overwrite the previous `.katana` and `.katana.requests.jsonl`
  files.

Examples:

```bash
./reconx active -t acme
./reconx active -t acme --sub app.acme.test --depth 5 --refresh
./reconx active -t acme --no-js --no-forms --duration 120
./reconx active -t acme -c target-configs/acme.json --header 'Cookie: session=...'
```

> `--header` is for the crawl only. To send the same header during fuzzing and
> Nuclei, put it in the target config's `headers` object instead.

---

### `init`

Create a starter target configuration.

```text
./reconx init NAME [--seed URL]... [--force]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `NAME` | required | Target name; also the results directory and default filename. |
| `--seed URL` | none | Seed URL. Repeatable. Bare domains are normalised to `https://`. |
| `--force` | off | Overwrite an existing `target-configs/<name>.json`. |

The file is written to `target-configs/<safe-name>.json` in the project root,
regardless of your current directory. The starter enables XSS, SQLi,
open-redirect, and all three header classes, with `methods: ["GET", "POST"]`,
`content_types: ["urlencoded", "json"]`, `rl: 20`, `c: 10`, and `timeout: 60`.

Examples:

```bash
./reconx init acme
./reconx init acme --seed https://acme.test --seed https://app.acme.test
./reconx init acme --seed https://acme.test --force
```

---

### `validate`

Validate a target config and print the normalised result.

```text
./reconx validate CONFIG
```

It performs the same checks as the pipeline: unknown keys are reported and
ignored, methods/vulnerabilities/content types are allow-listed, numeric fields
are checked, scope is derived when missing, and nested `nuclei`, `notifications`,
and `output` sections are merged over the global settings.

The printed JSON is the exact configuration the pipeline would use. That makes
it a good debugging tool, but it also contains any secrets in `headers`,
`notifications`, or `proxy`. **Do not paste `validate` output into a public
issue or chat.**

Example:

```bash
./reconx validate target-configs/acme.json
```

---

### `mass-fuzz`

Run the full pipeline over every selected subdomain of a target.

```text
./reconx mass-fuzz -c CONFIG [options]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-c`, `--config FILE` | required | Target config JSON. |
| `--only HOST` | all | Process only these subdomains. Repeatable. |
| `--resume` | off | Skip hosts whose state is `done` (unless a refresh flag is also set). |
| `--keep-templates` | off | Keep `templates/` after each host. |
| `--skip-fuzz` | off | Generate jobs but send no fuzzing requests. Nuclei still runs unless `--skip-nuclei`. |
| `--skip-nuclei` | off | Do not run Nuclei. |
| `--refresh-params` | off | Re-extract `params.json` even if it exists. Also defeats `--resume` skipping. |
| `--refresh-fuzz` | off | Fuzz even when the host is marked `done`. |
| `--max-hosts N` | none | Process at most N subdomains (after filtering, in sorted order). |
| `--rl N` | config `rl` | Override global requests per second. |
| `--workers N` | config `c` | Override worker threads. |
| `--timeout N` | config `timeout` | Override per-request timeout in seconds. |
| `--vulns LIST` | config `vulns` | Comma-separated vulnerability classes. |
| `--methods LIST` | config `methods` | Comma-separated HTTP methods. |
| `--chunk-size N` | config `chunk_size` | Parameters sent per fuzz request. |

The pipeline, per host:

1. **Parameter extraction** - reuses `params.json` unless it is missing or
   `--refresh-params` is set.
2. **Cross-subdomain merge** - only when `cross_sub_passive_params` is true.
3. **Job generation** - one job per vulnerability, endpoint, parameter chunk,
   and payload file; plus header jobs for header classes.
4. **Fuzzing** - baseline then payloads, bounded by `max_payloads`,
   `max_requests`, and `max_jobs`.
5. **Nuclei** - unless disabled or `--skip-nuclei`.
6. **Template cleanup** - `templates/` is removed unless `--keep-templates`.
7. **State update** - `state.json` gets counts and status.

After all hosts it aggregates the configured report formats and sends
notifications if enabled. If any host failed, the pipeline still aggregates, then
exits with an error message and a non-zero status.

Host selection order:

```text
all subdomain directories (sorted)
  -> cfg.sub, if set
  -> --only names, if given
  -> first N, if --max-hosts is given
```

If no host matches, the command fails with `no matching subdomain directories to
fuzz`.

Resume and refresh semantics:

| Situation | `--resume` | Result |
|-----------|------------|--------|
| Host status `done` | on | Skipped. |
| Host status `done` | off | Re-run. |
| Host status `done`, `--refresh-fuzz` | on | Re-run fuzzing. |
| Host status `done`, `--refresh-params` | on | Re-run, including extraction. |
| Host status `error` or `interrupted` | on | Re-run. |

Findings are append-only and deduplicated, so re-running does not duplicate the
same finding. It also does not update an existing finding whose evidence changed.
To reset a host's findings, delete `fuzz/findings.jsonl`, `fuzz/hits.txt`, and
`fuzz/evidence/` together; deleting only `findings.jsonl` lets the legacy
`hits.txt` lines reappear during aggregation.

Examples:

```bash
# Normal run.
./reconx mass-fuzz -c target-configs/acme.json

# Low-noise first pass over one host.
./reconx mass-fuzz -c target-configs/acme.json --only acme.test \
  --vulns xss,open-redirect --rl 5 --workers 3 --max-hosts 1

# Inspect jobs only.
./reconx mass-fuzz -c target-configs/acme.json --skip-fuzz --skip-nuclei --keep-templates

# Re-crawl-independent parameter refresh after a deploy.
./reconx mass-fuzz -c target-configs/acme.json --refresh-params --refresh-fuzz

# Resume an interrupted run.
./reconx mass-fuzz -c target-configs/acme.json --resume
```

---

### `single-fuzz`

Fuzz one arbitrary URL through the same job/fuzz/Nuclei/report pipeline.

```text
./reconx single-fuzz -c CONFIG URL [options]
```

| Argument / option | Default | Meaning |
|-------------------|---------|---------|
| `URL` | required | Target URL. Query parameters are extracted automatically. |
| `-c`, `--config FILE` | required | Target config JSON. Determines target, vulns, methods, limits. |
| `--method M` | `POST` with `--data`, else `GET` | HTTP method for the request. Choices: `get`, `post`, `put`, `patch`, `delete`, `head`, `options` (case-insensitive). |
| `--data BODY` | none | Request body. Parsed as urlencoded, JSON, or multipart based on `--content-type` or content sniffing. |
| `--param NAME` | none | Explicit parameter name. Repeatable. Added to the query for GET/HEAD, otherwise to the body. |
| `--content-type CT` | `urlencoded` | Body encoding: `urlencoded`, `json`, or `multipart`. |
| `--skip-nuclei` | off | Do not run Nuclei. |
| `--keep-templates/--no-keep-templates` | keep | Keep generated template JSONL files. |
| `--rl N` | config `rl` | Override requests per second. |
| `--workers N` | config `c` | Override worker threads. |
| `--timeout N` | config `timeout` | Override request timeout. |

Behaviour:

- Normalises the URL, derives the host, creates `results/<target>/subdomains/<host>/`,
  and records the host in `subdomains.txt`.
- Uses query parameters from the URL. If `--method` is omitted and `--data` is
  given, the method is `POST`; otherwise `GET`.
- Parses `--data` as JSON when `--content-type json` is used **or** when the body
  starts with `{` or `[`. Otherwise urlencoded, with multipart detection when
  requested.
- Writes a single-mode `params.json`, overwriting any previous `params.json` for
  that host. This is important: `single-fuzz` is not additive with a prior
  `mass-fuzz` parameter model for the same host.
- Runs the normal job generator, fuzzer, Nuclei, print of `hits.txt`, aggregation,
  and notifications.
- If no parameters and no header-based class are selected, no jobs are generated;
  the command warns and still aggregates.

Examples:

```bash
# GET with query parameters.
./reconx single-fuzz -c target-configs/acme.json \
  'https://acme.test/search?q=test&page=1'

# POST urlencoded.
./reconx single-fuzz -c target-configs/acme.json --method POST \
  --data 'username=test&password=test' \
  https://acme.test/login

# JSON API body (content type inferred from the leading brace).
./reconx single-fuzz -c target-configs/acme.json --method POST \
  --data '{"email":"test@example.com","role":"user"}' \
  https://api.acme.test/v1/users

# No body; fuzz a named parameter on a POST endpoint.
./reconx single-fuzz -c target-configs/acme.json --method POST \
  --param redirect_uri \
  https://acme.test/oauth/authorize

# Header checks only, fast.
./reconx single-fuzz -c target-configs/acme.json \
  --skip-nuclei --no-keep-templates \
  https://acme.test/
```

---

### `aggregate`

Rebuild reports from stored findings.

```text
./reconx aggregate -t NAME [--format txt|json|html]...
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-t`, `--target NAME` | required | Target to aggregate. |
| `--format F` | all three | Report format. Repeatable: `--format txt --format html`. |

`aggregate` reads every host's `fuzz/findings.jsonl`, adds legacy `hits.txt`
lines, deduplicates by fingerprint, sorts by severity/type/URL/parameter, and
writes `results/<target>/output/<target>.<format>`.

Note: the CLI command ignores the config's `output.formats`; it writes all three
formats unless you pass `--format`. The `mass-fuzz` and `single-fuzz` pipelines do
use `output.formats` from the config.

Examples:

```bash
./reconx aggregate -t acme
./reconx aggregate -t acme --format html
./reconx aggregate -t acme --format json --format txt
```

---

### `status`

Show progress and finding counts.

```text
./reconx status [-t NAME]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-t`, `--target NAME` | none | Show one target. Omit to list all targets. |

Without `-t`, it prints one line per target: subdomain count and total findings
from `state.json`. With `-t`, it prints a table built from the files on disk
(passive URL count, crawled URL count, findings, and recorded state), then the
total and the report directory.

`status` works even when `state.json` is missing, because counts are read from
the result files. The state column then shows `unknown`.

Examples:

```bash
./reconx status
./reconx status -t acme
```

---

### `clean`

Delete results for a target or one subdomain.

```text
./reconx clean -t NAME [--sub HOST] [--yes]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-t`, `--target NAME` | required | Target to clean. |
| `--sub HOST` | none | Delete only this subdomain directory. |
| `--yes`, `-y` | off | Do not ask for confirmation. |

Safety: the resolved destination must be inside the results root. The command
refuses to delete anything outside it. Target and host names are sanitised the
same way as everywhere else, so `--sub host:8443` maps to the stored directory
`host_8443`.

Examples:

```bash
./reconx clean -t acme
./reconx clean -t acme --sub app.acme.test
./reconx clean -t acme --sub app.acme.test --yes
```

---

### `doctor`

Check external tool availability.

```text
./reconx doctor [--optional|--no-optional] [--json]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--optional` / `--no-optional` | optional shown | Include or hide optional tools (`unfurl`, `httpx`). |
| `--json` | off | Print a JSON array with `name`, `group`, `path`, `purpose`, `install`. `path` is `null` when missing. |

`doctor` warns when a core (recon) tool is missing, but does not stop the CLI.

Examples:

```bash
./reconx doctor
./reconx doctor --no-optional
./reconx doctor --json | jq '.[] | select(.path == null)'
```

---

## 6. Configuration reference

ReconX has two configuration layers:

1. **Global settings** - `config/settings.yaml`, merged over built-in defaults
   in `core/config_loader.py`.
2. **Target config** - `target-configs/<name>.json`, validated by
   `core/config_loader.py`.

Precedence, from lowest to highest:

```text
built-in defaults
  -> config/settings.yaml
  -> target-configs/<name>.json
  -> CLI overrides (--rl, --workers, --timeout, --vulns, --methods, --chunk-size)
```

Nested `nuclei`, `notifications`, and `output` objects are deep-merged, so a
target file only needs the keys it changes.

### Global settings (`config/settings.yaml`)

#### `tools`

Command name or absolute path for each external tool.

```yaml
tools:
  waybackurls: waybackurls
  gau: gau
  uro: uro
  katana: katana
  subfinder: subfinder
  nuclei: nuclei
```

Use this when a tool is installed under a different name or outside `PATH`.

#### `defaults`

| Key | Default | Meaning |
|-----|---------|---------|
| `rate_limit` | `20` | Global requests per second. |
| `concurrency` | `10` | Worker threads. |
| `timeout` | `60` | Per-request timeout in seconds. |
| `chunk_size` | `25` | Parameters per fuzz request. |
| `max_payloads` | `100` | Payloads per job. |
| `max_requests` | `20000` | Hard request budget per subdomain per run. |
| `max_jobs` | `20000` | Generated jobs per subdomain. |
| `max_header_targets` | `25` | URLs used for header checks. |
| `max_seeds` | `120` | Katana seed URLs per host. `0` = no cap. |
| `baseline_samples` | `1` | Baseline requests per job. Values > 1 use the median elapsed time. |
| `sleep_threshold` | `8.0` | Seconds before a time-based payload is considered suspicious. |
| `verify_tls` | `true` | Verify TLS certificates. |
| `follow_redirects` | `false` | Follow redirects. Ignored for open-redirect jobs. |
| `save_evidence` | `true` | Write `fuzz/evidence/<fingerprint>.txt`. |
| `max_response_bytes` | `1000000` | Body read cap per response. |
| `user_agent` | Chrome + ReconX UA | Empty in a target config means use the built-in UA. |
| `proxy` | empty | Example: `http://127.0.0.1:8080`. |
| `headers` | `{}` | Extra headers for the fuzzer, Katana, and Nuclei. |
| `cross_page_params` | `true` | Merge parameters across sibling endpoints. |
| `cross_sub_passive_params` | `false` | Merge passive parameters across subdomains. |
| `shared_param_limit` | `15` | Shared parameters injected per endpoint. |
| `ignore_params` | tracking list | Case-insensitive `fnmatch` patterns excluded from fuzzing. |
| `exclude_extensions` | static list | Extensions dropped from recon and crawling. |
| `scope_domains` | `[]` | Explicit scope. Empty means derive from seeds. |

#### `timeouts`

| Key | Default | Meaning |
|-----|---------|---------|
| `waybackurls` | `180` | Whole-tool timeout. |
| `gau` | `240` | Whole-tool timeout. |
| `uro` | `120` | Whole-tool timeout. |
| `katana` | `900` | Whole crawl timeout. |
| `katana_request` | `15` | Per-request crawl timeout, capped by the target `timeout`. |
| `subfinder` | `180` | Enumeration timeout. |
| `nuclei` | `1800` | Whole Nuclei run timeout. |

#### `nuclei`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Run Nuclei in the pipeline. |
| `templates` | `nuclei-templates` | Project-relative directory, absolute path, or list of paths. |
| `dast` | `true` | Add Nuclei's `-dast` flag. Required by the bundled templates. |
| `severity` | `low,medium,high,critical` | `-severity` value. |
| `extra_tags` | empty | `-tags` value for community templates. |
| `max_urls` | `200` | Maximum URLs passed to Nuclei per host. |
| `extra_args` | `[]` | Extra raw arguments appended to the command. Advanced. |

#### `notifications`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Send a summary after `mass-fuzz` / `single-fuzz`. |
| `only_on_diff` | `true` | Only send when hosts or findings changed. |
| `telegram_bot_token` | empty | Telegram bot token. |
| `telegram_chat_id` | empty | Telegram chat ID. |
| `webhook_url` | empty | Generic JSON webhook. |

#### `output`

| Key | Default | Meaning |
|-----|---------|---------|
| `formats` | `["txt", "json", "html"]` | Formats written at the end of a pipeline run. |
| `html_theme` | `dark` | Accepted for compatibility; the bundled renderer is the dark theme. |

### Target config (`target-configs/<name>.json`)

Minimal file:

```json
{
  "target": "acme",
  "seeds": ["https://acme.test"],
  "vulns": ["xss", "open-redirect"],
  "methods": ["GET", "POST"],
  "content_types": ["urlencoded", "json"],
  "rl": 10,
  "c": 5,
  "timeout": 60
}
```

#### Core fields

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `target` | string | required | Results directory name: `results/<target>/`. |
| `sub` | string | `""` | Limit `mass-fuzz` to one subdomain (and add it as a host during `passive`). |
| `seeds` | string / list | `[]` | Seed URLs. Bare domains get `https://`. Used for scope derivation. |
| `scope_domains` | string / list | `[]` | Explicit scope. When empty, derived from seeds and `sub`. |
| `methods` | string / list | `["GET"]` | Methods eligible for parameter fuzzing. |
| `content_types` | string / list | `["urlencoded"]` | Body encodings: `urlencoded`, `json`, `multipart`. |
| `vulns` | string / list | `["xss"]` | Classes to test. See the table below. |
| `chunk_size` | integer | `25` | Parameters fuzzed per request. |
| `rl` | integer | `20` | Global requests per second. |
| `c` | integer | `10` | Worker threads. |
| `timeout` | integer | `60` | Per-request timeout. Use `>= 20` for time-based SQLi. |

#### Limits and behaviour

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `max_payloads` | integer | `100` | Payloads per job. |
| `max_requests` | integer | `20000` | Request budget per subdomain per run. Baselines count. |
| `max_jobs` | integer | `20000` | Jobs per subdomain before truncation. |
| `max_header_targets` | integer | `25` | URLs used for header checks. |
| `baseline_samples` | integer | `1` | Baseline requests per job. |
| `sleep_threshold` | number | `8.0` | Time-based SQLi suspicion threshold in seconds. |
| `cross_page_params` | boolean | `true` | Merge parameters across sibling endpoints. |
| `cross_sub_passive_params` | boolean | `false` | Merge passive parameters across subdomains. |
| `shared_param_limit` | integer | `15` | Shared parameters per endpoint (`0` disables injection). |
| `ignore_params` | string / list | tracking list | Case-insensitive `fnmatch` patterns. |
| `exclude_extensions` | string / list | static list | Extensions removed from recon and crawling. |

#### HTTP and transport

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `verify_tls` | boolean | `true` | Verify TLS. |
| `follow_redirects` | boolean | `false` | Follow redirects globally. Open-redirect jobs never follow. |
| `save_evidence` | boolean | `true` | Write evidence files. |
| `max_response_bytes` | integer | `1000000` | Response body cap. |
| `user_agent` | string | `""` | Empty uses the built-in Chrome/ReconX UA. |
| `proxy` | string | `""` | HTTP(S) proxy for the fuzzer, Katana, and Nuclei. |
| `headers` | object | `{}` | Extra headers for the fuzzer, Katana, and Nuclei. |

#### Nested sections

`nuclei`, `notifications`, and `output` accept the same keys as the global
settings. Target values override global values key by key.

```json
{
  "nuclei": {
    "enabled": true,
    "dast": true,
    "severity": "medium,high,critical",
    "max_urls": 100
  },
  "notifications": {
    "enabled": true,
    "only_on_diff": true
  },
  "output": {
    "formats": ["html", "json"]
  }
}
```

### Valid values and aliases

| Field | Accepted values |
|-------|-----------------|
| `vulns` | `xss`, `sqli`, `open-redirect`, `headers-reflection`, `headers-status`, `cache-poison` |
| `methods` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` |
| `content_types` | `urlencoded`, `json`, `multipart` |
| `vulns` aliases | `mysqli` -> `sqli`, `redirect` -> `open-redirect`, `crlf` -> `headers-reflection` |

Strings and lists are both accepted for list fields. A comma-separated string is
split, so `"vulns": "xss, sqli"` works.

Parameter names are accepted only when they match
`[A-Za-z0-9_.\-\[\]]{1,64}`. Invalid names are skipped silently.

### Scope derivation

When `scope_domains` is empty, ReconX derives scope from every seed and from
`sub` using a best-effort registrable-domain guess: it keeps the last two labels,
with special handling for common two-level suffixes such as `co.uk`. This is not
a full public-suffix list. For any scope with a multi-level suffix, set
`scope_domains` explicitly:

```json
{
  "target": "acme",
  "seeds": ["https://acme.co.uk"],
  "scope_domains": ["acme.co.uk"]
}
```

`scope_domains` affects passive-recon filtering. Active crawling is restricted to
the exact subdomain being crawled. The fuzzer only visits URLs that came from
recon or that you pass to `single-fuzz`.

### Config hygiene

- Keep secrets in the target config or a private settings file, never in a public
  repo.
- `validate` prints the full normalised config, including secrets.
- `notifications.telegram_bot_token`, `headers.Cookie`, and `headers.Authorization`
  are the most common accidental leaks.
- `.gitignore` excludes `results/` but not every user target config. Check
  `git status` before publishing.

---

## 7. How the pipeline behaves

### Parameter extraction

`params.json` is built from three sources per host:

| Source | What is read |
|--------|--------------|
| `<host>.passive` | Archived GET URLs and their query parameters. |
| `<host>.katana` | Crawled URLs and their query parameters. |
| `<host>.katana.requests.jsonl` | Structured requests: query strings, urlencoded bodies, JSON bodies, multipart bodies, and HTML forms. |

The output contains `endpoints`, `all_params`, `passive_params`, `targets`,
`urls`, `sources`, and `stats`. Each endpoint is keyed by
`(url, method, location, content_type)`, so `GET /search?q=` and
`POST /search` with a form body are separate endpoints.

`ignore_params` patterns are applied case-insensitively. Sample values are
truncated to 120 characters and stripped of newlines. Missing samples default to
`"1"`.

### Cross-page merge

When `cross_page_params` is true (the default), endpoints are grouped by
`(method, location, content_type)`. The union of parameter names in a group is
applied to every endpoint in that group. The original sample value is kept; a
parameter that did not exist on an endpoint gets `"1"`. This models frameworks
where the same parameter is meaningful across several routes, at the cost of more
requests and some false positives.

### Cross-subdomain merge

When `cross_sub_passive_params` is true, ReconX counts `passive_params` across
all host `params.json` files, writes `shared_params.json`, and injects the top
`shared_param_limit` names into GET/HEAD query endpoints that do not already have
them. This is opt-in because it increases volume and can surface unrelated
parameters.

### Job generation

Parameter-based classes:

| Class | Payload files |
|-------|---------------|
| `xss` | `xss.txt` (65 payloads) |
| `sqli` | `sqli.txt` (46) and `sleep.txt` (25) |
| `open-redirect` | `open-redirect.txt` (35) |

Header-based classes (no parameters required):

| Class | Payload file |
|-------|--------------|
| `headers-reflection` | `headers-reflection.txt` (25) |
| `headers-status` | `headers-status.txt` (20) |
| `cache-poison` | `cache-poison.txt` (26) |

For each endpoint, parameters are split into chunks of `chunk_size`. One job is
created per vulnerability, endpoint, chunk, and payload file. Header classes
create one job per target URL (root plus endpoints plus `targets`, capped by
`max_header_targets`).

`sleep.txt` jobs are serial and are skipped when `timeout < 18`.
`headers-status` jobs are also serial because they compare status codes against
a baseline.

Jobs are written to `templates/all.jsonl`, `templates/<vuln>/jobs.jsonl`, and
`templates/summary.txt` for inspection. The engine uses the in-memory list, not
those files, so editing the JSONL does not change the run.

### Fuzzing

For each job:

1. Load payloads (up to `max_payloads`). Header payloads must parse as
   `Name: value`.
2. Fetch a clean baseline. Baselines are cached by URL, method, location,
   content type, samples, and parameter list. With `baseline_samples > 1`, the
   median elapsed time is used for timing comparisons.
3. Truncate the payload list to the remaining `max_requests` budget.
4. Run serially for time-based SQLi and `headers-status`, otherwise through a
   thread pool of at most `c` workers.
5. Call the detector. New findings are appended to the store.

A global token bucket enforces `rl` across all workers. Each worker has its own
`requests.Session` with connection pooling. Response bodies are capped at
`max_response_bytes`. Redirects are never followed for open-redirect jobs, so the
raw `Location` header remains visible.

### Nuclei

Nuclei runs against up to `nuclei.max_urls` URLs collected from
`crawl-parametrized/urls.txt`, `crawl-parametrized/targets.txt`, `.katana`, and
`.passive`. Command shape:

```text
nuclei -l targets.txt -jsonl -o nuclei.jsonl -silent -nc -or -ot
       -rl R -c C -timeout T [-severity ...] [-tags ...] [-t template]...
       [-dast] [-proxy ...] [-H 'Name: value'] [extra_args...]
```

Results are parsed from `nuclei.jsonl`, mapped to ReconX classes, and merged into
the same finding store. If an old Nuclei only emits text, the parser falls back
to the `[template] [severity] url` format. A missing Nuclei binary, a timeout, or
a template error is a warning, not a fatal pipeline error.

### Reporting

`aggregate` reads every `findings.jsonl`, adds legacy `hits.txt` lines,
deduplicates by fingerprint, and writes the selected formats. Findings are sorted
by severity (`critical`, `high`, `medium`, `low`, `info`), then vulnerability,
URL, and parameter.

---

## 8. Vulnerability classes and findings

### Classes

| Class | What it sends | Evidence required | Typical severity / confidence |
|-------|---------------|-------------------|-------------------------------|
| `xss` | Script/img/svg payloads in parameters. | Exact payload appears in the response body and not in the baseline. HTML content type -> `confirmed`; text or unknown -> `candidate`. | `high` / `confirmed` for HTML, `medium` / `candidate` otherwise. |
| `sqli` | Error, UNION, time-delay payloads. | Known database error signature not present in the baseline, or a measured delay. | Error: `high` / `confirmed`. Time: `critical` / `confirmed`. |
| `open-redirect` | Off-site URL payloads. | `Location`/`Refresh` points to a different host and contains the intended host, or a meta/JS redirect in the body contains it. | `medium` / `confirmed` for headers, `medium` / `candidate` for body redirects. |
| `headers-reflection` | Proxy/IP header canaries. | Canary appears in the response body or headers but not in the baseline. | Body: `medium` / `confirmed`. Header: `low` / `candidate`. |
| `headers-status` | Access-control bypass headers. | `401/403/404/405` -> `200/201/202/204/301/302/307/308`, any `>=400` -> `200`, or a >50% body-size change on a bypass header. | `high` or `medium` / `confirmed`; body-size change `low` / `candidate`. |
| `cache-poison` | Unkeyed header canaries. | Canary reflected in body/headers **and** a cache indicator. | `medium` / `confirmed` with cache indicators; `low` / `candidate` without. |

### Confidence

| Value | Meaning | What to do |
|-------|---------|------------|
| `confirmed` | The detector found direct evidence (reflection, error signature, status change, measured delay). | Reproduce manually before reporting. |
| `candidate` | Evidence exists but is weaker (text reflection, header-only reflection, body redirect, uncached reflection, body-size change). | Treat as a lead; verify with a browser/proxy. |
| `info` | Informational. | Triage. |

### Severity

Severity is a triage hint, not a CVSS score:

| Value | Use |
|-------|-----|
| `critical` | Time-based SQLi with a measured delay. |
| `high` | Reflected XSS in HTML, error-based SQLi, access-control bypass. |
| `medium` | Text-context XSS, open redirect, body reflection, cache poison with cache indicators. |
| `low` | Header-only reflection, uncached reflection, body-size change. |
| `info` | Imported informational results. |

### Time-based SQLi details

`sleep.txt` asks for 15-second delays. A job is skipped when `timeout < 18`, and
config validation warns. The detector requires:

```text
response.elapsed >= max(sleep_threshold, 0.7 * requested_delay)
response.elapsed >= baseline.elapsed + 0.6 * requested_delay
baseline.elapsed < sleep_threshold
```

The default `sleep_threshold` is `8.0` seconds. If the baseline is already slow,
the check is skipped to avoid false positives. Run time-based SQLi jobs with low
concurrency and a generous timeout.

### Fingerprints and deduplication

A finding fingerprint is the first 20 hex characters of a SHA-1 over:

```text
vuln | method | normalised URL | parameter | payload | template
```

Findings with the same fingerprint are ignored on later runs. This makes resume
idempotent, but it also means a finding whose evidence or severity changed will
not be updated in place. To reset one host's findings, delete
`fuzz/findings.jsonl`, `fuzz/hits.txt`, and `fuzz/evidence/` together (deleting
only `findings.jsonl` lets legacy `hits.txt` lines reappear), or run
`clean --sub` to remove the whole host directory. Redaction preserves the
fingerprint, so deduplication stays stable.

---

## 9. Results, reports, notifications, redaction

### Results layout

```text
results/<target>/
├── state.json                         # resumable progress
├── shared_params.json                 # cross-subdomain merge (opt-in)
├── subdomains.txt                     # host inventory
├── subdomains/<host>/
│   ├── <host>.passive                 # archived URLs
│   ├── <host>.katana                  # crawled URLs
│   ├── <host>.katana.requests.jsonl   # structured requests
│   ├── params.json                    # endpoint/parameter model
│   ├── crawl-parametrized/
│   │   ├── urls.txt                   # real URLs with query strings
│   │   └── targets.txt                # base URLs for header/Nuclei checks
│   ├── templates/                     # generated jobs (removed unless kept)
│   │   ├── all.jsonl
│   │   ├── summary.txt
│   │   └── <vuln>/jobs.jsonl
│   └── fuzz/
│       ├── findings.jsonl             # canonical finding store
│       ├── hits.txt                   # human-readable legacy lines
│       ├── nuclei_targets.txt         # URL list given to Nuclei
│       ├── nuclei.jsonl               # raw Nuclei JSONL for this host
│       └── evidence/<fingerprint>.txt # optional evidence
└── output/
    ├── <target>.txt
    ├── <target>.json
    └── <target>.html
```

Host and target names are sanitised for the filesystem: `:` becomes `_`, and
other unsafe characters are replaced. This prevents a config from escaping the
results directory.

### `state.json`

The state file tracks, per host:

| Field | Meaning |
|-------|---------|
| `status` | `params`, `done`, `error`, or `interrupted`. |
| `params_endpoints` | Number of extracted endpoints. |
| `jobs` | Generated job count. |
| `templates` | Per-vulnerability job counts and truncation flag. |
| `fuzz` | Requests, findings, errors, skipped jobs, elapsed seconds. |
| `nuclei` | URLs, templates, findings, errors. |
| `findings` | Finding count recorded at completion. |
| `mode` | `single` for `single-fuzz` runs. |
| `error` | Error message when status is `error`. |
| `updated_at`, `finished_at` | Timestamps. |

`state.json` is a convenience, not the source of truth. `status` and reports read
the result files.

### Reports

| Format | Contents |
|--------|----------|
| `txt` | Header, summary, severity counts, findings grouped by vulnerability. |
| `json` | `target`, `generated_at`, `scope`, `summary` (`total`, `confirmed`, `by_severity`, `by_vuln`), and full `findings`. |
| `html` | Self-contained dark dashboard with severity cards, a text filter, a severity selector, and a findings table. |

Reports are written to `results/<target>/output/`. The HTML file has no external
dependencies and can be opened directly or attached to a report.

### Notifications

After `mass-fuzz` or `single-fuzz` aggregation, ReconX can send a summary to
Telegram and/or a webhook. Both channels are optional; when both are configured,
the same message is sent to each. Delivery failures are warnings.

Message shape:

```text
[ReconX ASM] Target: acme (Run: 20261118T101500Z)
Hosts: 4 | Endpoints: 120 | Posture Findings: 0 | Active Findings: 7
  * [HIGH/fuzzer] xss — https://app.acme.test/search?q=...
  ...
Delta vs 20261118T090000Z:
  + New Hosts (1): api.acme.test
  ! New Active Findings: 2
```

Details:

- Only the first five findings are previewed.
- A separate "posture" count is not tracked in the Python edition; it is shown as
  `0`. All findings are counted as active findings.
- `only_on_diff: true` (default) sends only when a host was added/removed or a new
  finding appeared. Removed findings alone do not count as a change.
- The delta is approximated by comparing finding fingerprints and host
  directories from before and after the run. The Python edition does not keep
  immutable snapshots.
- The webhook receives JSON with `text`, `content`, `target`, `run_id`, and a
  `diff` object (including new finding objects).
- No channel configured means no delivery, even when `enabled` is true.

Configure globally:

```yaml
notifications:
  enabled: true
  only_on_diff: true
  telegram_bot_token: "123456:ABC..."
  telegram_chat_id: "123456789"
  webhook_url: "https://hooks.example.com/reconx"
```

Or per target:

```json
{
  "notifications": {
    "enabled": true,
    "only_on_diff": false,
    "webhook_url": "https://hooks.example.com/reconx"
  }
}
```

### Redaction

Findings, evidence files, reports, and notification text pass through
`core/redact.py`:

- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API-key,
  auth-token, CSRF, session, and similar headers are masked.
- Header names containing `token`, `secret`, `password`, `session`, `cookie`,
  `apikey`, `credential`, `private`, or `auth` are masked.
- Query/body parameters with names such as `password`, `token`, `api_key`,
  `sessionid`, `jwt`, or `client_secret` are masked.
- Bearer/Basic/Token credentials, JWTs, and `password=...`-style pairs in text are
  scrubbed.
- URL userinfo (`user:password@host`) is dropped.
- Raw HTTP transcripts have sensitive header values masked.
- Fingerprints are preserved.

Redaction is defence in depth, not a guarantee. Check reports before sharing them,
and never publish a target config that contains credentials.

---

## 10. Rate limits, budgets, and performance

### What the knobs mean

| Knob | Scope | Effect |
|------|-------|--------|
| `rl` | One ReconX process | Global requests per second across all workers. |
| `c` | One fuzzing job | Maximum concurrent payload requests inside that job. |
| `chunk_size` | Endpoint | Fewer, larger requests versus more, smaller requests. |
| `max_payloads` | Job | Caps payloads sent per job. |
| `max_requests` | Subdomain, per run | Hard stop across baselines and payloads. |
| `max_jobs` | Subdomain | Hard stop on generated jobs. |
| `max_header_targets` | Subdomain | Caps URLs used for header checks. |
| `timeout` | Request | Per-request limit. Also gates time-based SQLi. |
| `baseline_samples` | Job | Extra baseline requests; median elapsed time. |

`rl` is enforced inside one process. Two concurrent `reconx mass-fuzz` runs can
each send `rl` requests per second. Do not run the same scope twice at once.

### Rough request estimate

For a parameter job:

```text
requests ≈ baseline_samples + min(payload_count, max_payloads)
```

For example, one GET endpoint with 3 parameters and `chunk_size: 25` produces one
chunk. With `xss` enabled, that is about `1 + 65 = 66` requests. With `sqli`
enabled as well, add `1 + 46` for `sqli.txt` and `1 + 25` for `sleep.txt`
(serial). Header classes add roughly `1 + payload_count` per target URL, capped by
`max_header_targets`.

At `rl: 20`, a 1,000-request run needs at least 50 seconds of pacing, plus
response latency and any serial jobs.

### Tuning

| Goal | Change |
|------|--------|
| Be quieter | Lower `rl` to 3-5, `c` to 2-3, restrict `vulns`, lower `max_requests`. |
| Cover more parameters | Raise `max_requests`, keep `chunk_size` moderate. |
| Reduce request count | Raise `chunk_size` (more parameters per request, less granular attribution). |
| Improve time-based SQLi | Raise `timeout` to 30+, keep `rl` low, use `baseline_samples: 2`. |
| Avoid noisy endpoints | Add `ignore_params` patterns. |
| Skip header work | Remove `headers-*` and `cache-poison` from `vulns`. |
| Faster crawl | `active --no-js --no-forms`, lower `max_seeds`, lower `depth`. |

`headers-status` compares a baseline against injected headers, so it is serial per
job. `sleep.txt` jobs are serial for the same reason. Expect those to dominate
runtime.

---

## 11. Practical recipes

### 1. First assessment of a single authorised domain

```bash
./reconx passive -t acme acme.test
./reconx active -t acme
./reconx init acme --seed https://acme.test
./reconx validate target-configs/acme.json
./reconx mass-fuzz -c target-configs/acme.json --vulns xss,open-redirect,headers-reflection
./reconx status -t acme
./reconx aggregate -t acme --format html
```

Start with a narrow class set and a low rate, review the HTML report, then widen
the scope of testing if authorisation allows.

### 2. Low-noise pass with a hard budget

```json
{
  "target": "acme",
  "seeds": ["https://acme.test"],
  "vulns": ["xss", "open-redirect"],
  "methods": ["GET"],
  "rl": 5,
  "c": 2,
  "timeout": 30,
  "max_requests": 1500,
  "max_jobs": 500,
  "max_payloads": 25
}
```

```bash
./reconx mass-fuzz -c target-configs/acme.json --only app.acme.test
```

### 3. JSON API endpoint

```bash
./reconx single-fuzz -c target-configs/acme.json --method POST \
  --data '{"email":"test@example.com","role":"user"}' \
  https://api.acme.test/v1/users
```

The leading `{` makes the parser treat the body as JSON even without
`--content-type`. Add `--content-type json` if you prefer to be explicit.

### 4. Authenticated application through Burp

```json
{
  "target": "acme",
  "seeds": ["https://app.acme.test"],
  "vulns": ["xss", "sqli", "headers-reflection"],
  "methods": ["GET", "POST"],
  "content_types": ["urlencoded", "json"],
  "rl": 8,
  "c": 4,
  "timeout": 30,
  "proxy": "http://127.0.0.1:8080",
  "headers": {
    "Cookie": "session=REPLACE_ME",
    "Authorization": "Bearer REPLACE_ME"
  }
}
```

```bash
./reconx active -t acme -c target-configs/acme.json --refresh
./reconx mass-fuzz -c target-configs/acme.json
```

The proxy applies to the fuzzer, Katana, and Nuclei. Passive tools do not use it.
Keep this config private; redaction masks the values in findings but the file
itself still contains them.

### 5. Header-only posture check

```json
{
  "target": "acme",
  "seeds": ["https://acme.test"],
  "vulns": ["headers-reflection", "headers-status", "cache-poison"],
  "rl": 5,
  "c": 2,
  "max_header_targets": 10
}
```

```bash
./reconx mass-fuzz -c target-configs/acme.json --skip-nuclei
```

Header classes need no parameters, so this works even on a host with no query
strings.

### 6. Re-run only one host

```bash
./reconx mass-fuzz -c target-configs/acme.json --only api.acme.test --refresh-fuzz
```

Findings are still deduplicated. If you want a clean record for that host:

```bash
./reconx clean -t acme --sub api.acme.test --yes
./reconx mass-fuzz -c target-configs/acme.json --only api.acme.test
```

### 7. Refresh after a deployment

```bash
./reconx passive -t acme acme.test
./reconx active -t acme --refresh
./reconx mass-fuzz -c target-configs/acme.json --refresh-params --refresh-fuzz
```

### 8. Inspect jobs before sending anything

```bash
./reconx mass-fuzz -c target-configs/acme.json \
  --skip-fuzz --skip-nuclei --keep-templates --only app.acme.test
cat results/acme/subdomains/app.acme.test/templates/summary.txt
head -n 5 results/acme/subdomains/app.acme.test/templates/all.jsonl
```

This is a good way to confirm that the parameter model and chunking are sensible
before a large run.

### 9. Rebuild reports without scanning

```bash
./reconx aggregate -t acme --format html
```

### 10. Notify a chat only when something new appears

```yaml
# config/settings.yaml
notifications:
  enabled: true
  only_on_diff: true
  telegram_bot_token: "123456:ABC..."
  telegram_chat_id: "123456789"
```

```bash
./reconx mass-fuzz -c target-configs/acme.json
```

### 11. Keep scopes separate

```bash
RECONX_RESULTS=$HOME/reconx-runs/acme ./reconx mass-fuzz -c target-configs/acme.json
```

Use a separate results root per client or engagement. Reports, state, and
findings all follow it.

### 12. Lab practice

Run the same commands against a local lab you control (for example a deliberately
vulnerable VM) and point `proxy` at Burp. Start with:

```bash
./reconx single-fuzz -c target-configs/lab.json \
  --param q 'http://lab.local/search?q=test'
```

Then compare the detector output with what you see in Burp's history.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `permission denied: ./setup.sh` | Git stored mode `100644` (repo committed from Windows). | `bash setup.sh` once; it re-applies `chmod +x` (and `git update-index --chmod=+x setup.sh reconx` fixes the repo). |
| `gau` runs `git add --update` | oh-my-zsh's `git` plugin aliases `gau`. | `bash setup.sh` (appends `unalias gau` to `~/.zshrc`), then open a new shell or run `unalias gau`. |
| `tool not found on PATH` | Go bin directory missing from `PATH`. | Add `$(go env GOPATH)/bin` (first), restart the shell, run `./reconx doctor`. |
| `PyYAML is required` | Python dependencies not installed. | `./setup.sh` or `pip install -r requirements.txt`. |
| `python3 -m venv` fails | `python3-venv` missing. | `sudo apt install python3-venv python3-pip`. |
| `target 'x' has no results yet` | `active`, `aggregate`, or `status` ran before `passive`. | Run `./reconx passive ...` first. |
| `no subdomain directories to crawl` | `passive` produced no hosts, or the target name differs. | Check `results/<target>/subdomains.txt` and `-t`. |
| `no matching subdomain directories to fuzz` | `--only`, `cfg.sub`, or `--max-hosts` filtered everything out. | List `results/<target>/subdomains/` and use exact names. |
| No parameters found | Scope has no archived query strings and no forms/JS APIs. | Use `single-fuzz`, or provide `--param` explicitly. |
| `no fuzz jobs generated` | No parameters and no header class selected. | Add a header class to `vulns`, or use `single-fuzz --param`. |
| `timeout=... too short for SLEEP(15)` | `timeout < 18` with `sqli` enabled. | Set `timeout` to at least 20 (30 is safer). |
| Time-based SQLi never fires | Baseline is slow, or `sleep_threshold` is too high. | Lower `sleep_threshold`, raise `timeout`, reduce `rl`. |
| Nuclei finds nothing | Binary missing, templates missing, or DAST disabled. | `./reconx doctor`, check `nuclei-templates/`, set `nuclei.dast: true`. |
| Nuclei skipped silently | `nuclei.enabled` false or `--skip-nuclei`. | Check the config and CLI flags. |
| Katana produces nothing | Site blocks the crawler, DNS fails, or all seeds error. | Use a proxy, check `host_resolves`, try `--refresh`, inspect warnings. |
| Crawl is very slow | Deep crawl plus JS plus forms on a large site. | Lower `--depth`, `--max-seeds`, use `--no-js --no-forms`, set `--duration`. |
| Too many requests | `rl`/`c` too high or budgets too large. | Lower `rl`, `c`, `max_requests`, `max_jobs`, `max_payloads`; narrow scope. |
| `pipeline completed with N error(s)` | Per-host failures; aggregation still ran. | Scroll up for the per-host messages, fix the host, then `--resume`. |
| `refusing to delete outside the results directory` | `clean --sub` resolved outside the target. | Use the exact stored host name. |
| `pip` install works but `./reconx` uses the wrong Python | Launcher found `python3` before your venv. | Set `RECONX_VENV` or create `.venv` in the project root. |
| TLS errors against a lab | Self-signed certificate. | Set `"verify_tls": false` for that lab only. |
| Findings look stale after a code change | Fingerprint dedupe kept the old record. | Delete `fuzz/findings.jsonl`, `fuzz/hits.txt`, and `fuzz/evidence/`, or run `clean --sub`, then re-run. |
| Config key ignored | Unknown keys are warned and ignored. | Compare with `target-configs/schema.json`; run `validate`. |
| `validate` prints secrets | It prints the fully merged config. | Do not share the output; redact before pasting. |

### Diagnostic sequence

```bash
./reconx --version
./reconx doctor
./reconx status -t acme
./reconx validate target-configs/acme.json
./reconx --debug mass-fuzz -c target-configs/acme.json --only app.acme.test --max-hosts 1
```

`--debug` shows external commands and request-level errors. It is the fastest way
to see whether a failure is in recon, parameter extraction, job generation, the
HTTP engine, or Nuclei.

---

## 13. Limitations and FAQ

### Does ReconX verify findings automatically?

No. It records evidence and confidence, but you must reproduce a finding manually.
`confirmed` means the detector saw direct evidence, not that the issue is
exploitable in every context.

### Does it handle JavaScript-rendered apps?

Katana's `-jc` and `-jsl` flags extract endpoints from JavaScript and crawl them.
ReconX does not run a headless browser itself, so runtime-only routes and
client-side auth flows may be missed. Seed the important URLs with
`single-fuzz` if needed.

### Does it support blind or out-of-band vulnerabilities?

No. There is no OAST/collaborator integration. The engine looks at responses it
receives (body, headers, status, timing). Blind SSRF, blind XSS, and out-of-band
SQLi are out of scope for this edition.

### Can I add a vulnerability class?

Yes. Add a payload file, a `PARAM_PAYLOADS` or `HEADER_PAYLOADS` entry in
`core/templates.py`, a detector in `core/fuzz/detectors.py`, register it in
`_DETECTORS`, and add the name to `VALID_VULNS`. Update the schema and sample
config if you want validation and docs to match. See `docs/ARCHITECTURE.md`.

### Can I use a different payload set?

Yes. Replace or edit the files in `config/payloads/`. The filename is referenced
by `core/templates.py`; the file contents are read at runtime.

### Why did a re-run not add a finding I expected?

The fingerprint already exists. Remove `fuzz/findings.jsonl`, `fuzz/hits.txt`,
and `fuzz/evidence/` for a findings-only reset, or use `clean --sub` for a fresh
host directory.

### Can I run multiple targets at once?

Run separate processes with separate target configs. They can share the same
results root because each target has its own directory. Remember that `rl` is
per process.

### Where are the reports?

`results/<target>/output/<target>.txt`, `.json`, and `.html`.

### Does `aggregate` follow `output.formats`?

No. The `aggregate` command writes all three formats unless you pass `--format`.
The pipeline commands use `output.formats`.

### What happens if a tool is missing?

`passive` and `active` warn and continue with whatever tools are available.
`nuclei` warns and skips. The fuzzer itself only needs Python's `requests`.

### Is the JSON schema enforced?

`target-configs/schema.json` is documentation and editor support. The runtime
validator in `core/config_loader.py` is authoritative and is slightly more
permissive in places (for example, list fields accept comma-separated strings).

### Which edition does this guide cover?

Only the Python edition in `core/`. The `reconx-go` tree is a separate reference
implementation and is not documented here.

---

## 14. Environment variables and exit codes

### Environment variables

| Variable | Effect |
|----------|--------|
| `RECONX_RESULTS` | Override the results root. Useful for per-client separation and tests. |
| `RECONX_VENV` | Venv directory the `./reconx` launcher should prefer. |
| `NO_COLOR` | Disable ANSI colour, in addition to `--no-color`. |

External tools are also run with `NO_COLOR=1` so their output can be parsed
reliably.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | A pipeline that completed with per-host errors, or another explicit command failure. |
| `2` | Usage error (bad option/argument) or configuration/value error (`ConfigError`, `ValueError`). |
| `130` | Interrupted (`Ctrl-C`) or aborted confirmation. |
| `143` | The active crawl received `SIGTERM`; partial crawl output was saved. |

A pipeline that hits per-host errors still aggregates partial results before
returning non-zero. That is intentional: you keep the data and can resume.

---

## Quick reference

```text
./reconx passive -t NAME SEED [--subs FILE] [--enumerate]
                 [--no-wayback] [--no-gau] [--no-uro]
                 [--max-hosts N] [-c CONFIG]

./reconx active -t NAME [--sub HOST]... [--depth N] [--refresh]
                [--max-seeds N] [--no-forms] [--no-js]
                [--duration N] [--header 'Name: value']... [-c CONFIG]

./reconx init NAME [--seed URL]... [--force]
./reconx validate CONFIG

./reconx mass-fuzz -c CONFIG [--only HOST]... [--resume]
                   [--keep-templates] [--skip-fuzz] [--skip-nuclei]
                   [--refresh-params] [--refresh-fuzz] [--max-hosts N]
                   [--rl N] [--workers N] [--timeout N]
                   [--vulns LIST] [--methods LIST] [--chunk-size N]

./reconx single-fuzz -c CONFIG URL [--method M] [--data BODY]
                     [--param NAME]... [--content-type CT]
                     [--skip-nuclei] [--keep-templates/--no-keep-templates]
                     [--rl N] [--workers N] [--timeout N]

./reconx aggregate -t NAME [--format txt|json|html]...
./reconx status [-t NAME]
./reconx clean -t NAME [--sub HOST] [--yes]
./reconx doctor [--optional/--no-optional] [--json]
```

Use ReconX responsibly, only within an authorised scope, and verify every finding
before you report it.
