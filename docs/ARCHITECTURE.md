# ReconX architecture

This document describes the internal design of ReconX 2.0. The goal is a
predictable pipeline that is safe to run against production scopes, easy to
debug, and straightforward to extend.

---

## Layers

```
┌─────────────────────────────────────────────────────────────┐
│ core.cli                 Click commands / options            │
├─────────────────────────────────────────────────────────────┤
│ core.pipeline            mass-fuzz / single-fuzz orchestration│
├───────────────┬───────────────────┬─────────────────────────┤
│ core.recon    │ core.params       │ core.templates          │
│ passive/active│ extraction/merge  │ job generation          │
├───────────────┴───────────────────┴─────────────────────────┤
│ core.fuzz        engine · detectors · store · payloads      │
├─────────────────────────────────────────────────────────────┤
│ core.nuclei      runner + JSONL parser                      │
├─────────────────────────────────────────────────────────────┤
│ core.report      txt / json / html aggregation              │
├─────────────────────────────────────────────────────────────┤
│ core.paths · core.state · core.process · core.config_loader │
└─────────────────────────────────────────────────────────────┘
```

Only `core.cli` imports Click. Only `core.fuzz.engine` imports `requests`
(lazily, so `--help` works before dependencies are installed). External tools
are reached through `core.process.run`, which never uses a shell.

---

## Data model

`core.models` defines the objects passed between layers:

- **`TargetConfig`** — validated per-target options. `to_dict()` /
  `from_dict()` make it easy to clone with CLI overrides.
- **`Endpoint`** — a fuzzable location:
  `(url without query, method, location, content_type, params, samples)`.
  `location` is `query`, `body` or `header`.
- **`FuzzJob`** — one unit of work:
  `(vuln, url, method, location, params chunk, samples, payload_file, …)`.
  `samples` always contains *all* endpoint parameters, so non-fuzzed values are
  preserved when a chunk is replaced.
- **`HttpResult`** — normalised request/response data used by detectors.
- **`Finding`** — deduplicated result with severity, confidence, evidence,
  request/response excerpts, source (`fuzzer` / `nuclei`) and a fingerprint.

Fingerprints are SHA-1 over `(vuln, method, normalised URL, param, payload,
template)` truncated to 20 hex characters. They make finding storage idempotent
across resumed runs.

---

## Configuration

Two layers, merged deeply:

1. `config/settings.yaml` → `DEFAULT_SETTINGS` in `core/config_loader.py`.
2. `target-configs/<name>.json` → `validate_config()`.

`validate_config` performs allow-list validation for methods, vulnerabilities
and content types, converts numeric fields, derives scope domains from seeds
when necessary, and merges nested `nuclei` / `output` sections. Unknown keys are
reported but ignored, so old configs remain usable.

`default_target_config()` is used by `passive` and `active`, which do not need a
full target file.

---

## Results layout and state

`core.paths` is the single source of truth for every path. It sanitises target
and host names (`safe_component`) so that user input cannot escape
`results/<target>/`.

```
results/<target>/
  state.json
  shared_params.json
  subdomains.txt
  subdomains/<host>/
    <host>.passive
    <host>.katana
    <host>.katana.requests.jsonl
    params.json
    crawl-parametrized/{urls,targets}.txt
    templates/…
    fuzz/{findings.jsonl,hits.txt,nuclei.jsonl,evidence/}
  output/<target>.{txt,json,html}
```

`core.state.State` is a JSON-backed progress tracker. `mass-fuzz --resume`
skips hosts whose status is `done`. `disk_status()` reconstructs counts from
the files themselves, so `reconx status` works even without `state.json`.

---

## Passive recon (`core.recon.passive`)

For each host:

1. Run `waybackurls` with the host on stdin.
2. Run gau with the host and the flags from the `gau:` settings block
   (`--providers`, `--threads`, `--timeout`, `--subs`).
3. Pipe the combined output through `uro` (when available).
4. Normalise each URL (`core.recon.urls.normalize_url`): lower-case host,
   IDNA, default-port removal, query sorting, fragment removal.
5. Filter static assets and out-of-scope hosts.
6. Bucket URLs by host, including hosts discovered by `gau --subs`, and write
   one `<host>.passive` file per subdomain.

`--enumerate` optionally runs `subfinder` to expand the host list. A
`subdomains.txt` inventory is persisted for later commands.

## Active crawl (`core.recon.active`)

Katana is run with:

```
-jsonl -silent -nc -or -ob -fx -jc -jsl -kf all -aff -fs fqdn -d N
-timeout T -rl R -c C -ef <static extensions>
```

`-jsonl` gives structured records; `_normalise_record` extracts
`request.endpoint`, `request.method`, `request.body`, headers, status and forms.
`-or` drops the raw request/response blobs and `-ob` drops response bodies —
ReconX never reads them, and they are what makes a single host produce tens of
megabytes of JSONL. Only records whose host matches the target subdomain are
kept. Both plain URLs (`<host>.katana`) and structured requests
(`<host>.katana.requests.jsonl`) are written. Existing crawl output is reused
unless `--refresh` is passed.

`run_to_file` supervises katana with two guards, because katana can stop
emitting output without exiting:

- `timeouts.katana_stall` (default 120s) kills the process when the capture
  file has not grown for that long. Katana's own `-timeout` covers the request
  handshake, not a body that streams forever (SSE, long-poll, chunked video),
  so a single such endpoint can otherwise wedge the whole host.
- `katana.max_output_mb` (default 50) stops a crawl that falls into a crawler
  trap before it writes gigabytes.

Both cases keep the partial results. `SIGINT` (Ctrl+C) and `SIGTERM` also save
whatever was captured before exiting, and the temporary JSONL is always
removed.

---

## Parameter extraction and merging (`core.params`)

`extract_params(workspace, target, host, cfg, refresh=…)` reads:

- `<host>.passive` and `<host>.katana` for query parameters;
- `<host>.katana.requests.jsonl` for:
  - query strings on structured requests,
  - urlencoded / JSON / multipart bodies,
  - HTML forms (action, method, fields).

It builds `Endpoint` objects and writes `params.json` with:

```json
{
  "subdomain": "app.example.com",
  "endpoints": [ … ],
  "all_params": [ … ],
  "passive_params": [ … ],
  "targets": [ … ],
  "urls": [ … ],
  "stats": { … }
}
```

Parameter names are validated (`[A-Za-z0-9_.\-\[\]]`, max 64 chars) and filtered
with `ignore_params` glob patterns. Samples are truncated and stripped of
newlines.

### Cross-page merge

When `cross_page_params` is true, endpoints are grouped by
`(method, location, content_type)`. The union of their parameters is applied to
every endpoint in the group. This models frameworks where the same parameter
name is meaningful on several routes. Original sample values are preserved;
missing samples default to `"1"`.

### Cross-subdomain merge (opt-in)

`cross_sub_merge()` counts `passive_params` across all host `params.json` files,
writes `shared_params.json`, and `apply_shared_params()` injects the top
`shared_param_limit` names into GET/HEAD query endpoints. This is opt-in because
it increases request volume and can create false positives.

### Single-URL mode

`build_single_params()` accepts a URL plus optional `--method`, `--data`,
`--param` and `--content-type`, synthesises the same `params.json`, records the
host in `subdomains.txt`, and lets `single-fuzz` reuse the normal pipeline.

---

## Job generation (`core.templates`)

Parameter-based jobs are generated per configured vulnerability:

| Vulnerability | Payload files |
|---------------|---------------|
| `xss` | `config/payloads/xss.txt` |
| `sqli` | `config/payloads/sqli.txt`, `config/payloads/sleep.txt` |
| `open-redirect` | `config/payloads/open-redirect.txt` |

Header-based jobs (no parameters needed):

| Vulnerability | Payload file |
|---------------|--------------|
| `headers-reflection` | `headers-reflection.txt` |
| `headers-status` | `headers-status.txt` |
| `cache-poison` | `cache-poison.txt` |

Each endpoint's parameters are split into chunks of `chunk_size`. A job carries
the full sample map plus the chunk to replace. Time-based SQLi jobs are marked
`serial` and skipped when `timeout < 18`. `headers-status` jobs are serial
because they compare status codes against a baseline.

Jobs are written as JSONL (`templates/all.jsonl` and per-vuln files) for
transparency, but the engine consumes the in-memory list directly.

---

## Fuzzing engine (`core.fuzz.engine`)

- **`HttpClient`** — thread-local `requests.Session`, connection pooling,
  configured proxy/headers/TLS, response size cap. Redirects are not followed
  for `open-redirect` jobs.
- **`RateLimiter`** — global token bucket. `wait()` reserves a slot under a lock
  and sleeps outside it, so workers do not serialise unnecessarily.
- **`FuzzRunner`** — for each job:
  1. Load payloads (limit `max_payloads`); header payloads are validated as
     `Name: value`.
  2. Fetch a baseline (cached by URL/method/location/content-type/samples/params).
  3. Truncate payloads to the remaining global request budget.
  4. Run payloads serially for time-based/status jobs, otherwise through a
     thread pool of at most `c` workers.
  5. Call the detector; store newly confirmed findings.

Baselines are repeated `baseline_samples` times when configured; the median
elapsed time is used for time-based comparisons.

## Detectors (`core.fuzz.detectors`)

Each detector returns a `Finding` or `None`; exceptions are swallowed so one
malformed response cannot stop a run.

- **XSS** — exact payload reflection in the body, absent from the baseline.
  HTML content types → `confirmed/high`; text/unknown → `candidate/medium`.
- **SQLi** — time-based: response delay ≥ `max(sleep_threshold, 0.7×delay)` and
  ≥ baseline + `0.6×delay`, with a non-slow baseline. Error-based: known DB
  error signatures absent from the baseline.
- **Open redirect** — extract intended host(s) from the payload; require the
  response `Location`/`Refresh` host to differ from the request host, or a
  meta/JS redirect containing the intended host in the body.
- **Header reflection** — canary from a `Name: value` payload appears in the
  body or response headers but not in the baseline.
- **Header status** — baseline `401/403/404/405` → `2xx/3xx`, or any `>=400` →
  `200`, or a >50 % body-size change on a bypass header.
- **Cache poison** — canary reflected in body/headers **and** cache indicators
  (`X-Cache`, `CF-Cache-Status`, `Age > 0`, `Cache-Control: public/max-age`, …).

## Finding storage (`core.fuzz.store`)

`FindingStore` loads existing fingerprints, then appends to
`fuzz/findings.jsonl`, `fuzz/hits.txt` and (optionally)
`fuzz/evidence/<fingerprint>.txt`. Writes are protected by a lock; duplicates
are ignored. The same store is used by the Nuclei integration, so reports have a
single source of truth.

---

## Nuclei integration (`core.nuclei`)

- Templates default to `nuclei-templates/` (project-relative); a list or an
  absolute path is accepted.
- URLs come from `crawl-parametrized/urls.txt`, `targets.txt`, `.katana` and
  `.passive`, capped at `nuclei.max_urls`.
- Command shape:

```
nuclei -l targets.txt -jsonl -o nuclei.jsonl -silent -nc -or -ot
       -rl R -c C -timeout T [-severity …] [-tags …] [-t template]...
       [-dast] [-proxy …] [-H 'Name: value'] [extra_args...]
```

- JSONL findings are parsed into `Finding` objects. Template IDs/tags are mapped
  to ReconX vulnerability classes. If a very old Nuclei only emits text, the
  parser falls back to the `[template] [severity] url` format.

---

## Reporting (`core.report`)

`collect_findings()` reads every host's `findings.jsonl`, deduplicates by
fingerprint, then adds legacy `hits.txt` lines for backwards compatibility. The
result is sorted by severity, vulnerability, URL and parameter.

- **Text** — summary + grouped findings.
- **JSON** — summary, scope and full finding objects.
- **HTML** — self-contained dark dashboard with severity cards, a text filter
  and a severity selector. All values are HTML-escaped and links use
  `rel="noopener noreferrer"`.

Reports are written to `results/<target>/output/`.

---

## Concurrency and safety

- One fuzz job at a time; payloads within a job use a bounded thread pool.
- Baselines are cached per job shape, not globally, to avoid cross-parameter
  contamination.
- Global request budget (`max_requests`) and job cap (`max_jobs`) prevent
  runaway scans.
- Target/host names are sanitised for filesystem paths; `clean` verifies the
  destination is inside `results/`.
- No shell is used for external tools, so target data cannot inject commands.
- `verify_tls` defaults to true; `proxy` is available for Burp/ZAP.

---

## Extension points

- **New vulnerability** — add a payload file, a `PARAM_PAYLOADS` or
  `HEADER_PAYLOADS` entry in `core/templates.py`, and a detector function in
  `core/fuzz/detectors.py`; register it in `_DETECTORS` and add the name to
  `VALID_VULNS`.
- **New tool** — add a `ToolSpec` in `core/deps.py`, a timeout in
  `DEFAULT_SETTINGS`, and a caller using `core.process.run`.
- **New report format** — add a renderer in `core/report.py` and extend the
  `formats` choice in `core/cli.py`.
- **New config field** — add it to `TargetConfig`, `DEFAULT_SETTINGS`,
  `validate_config`, the JSON schema and the sample config.

---

## Testing philosophy

The test suite avoids network access:

- URL normalisation / scope / parameter parsing are pure functions.
- Config validation is tested with explicit dicts.
- Parameter extraction uses a temporary `Workspace` populated with fixture
  files.
- Detectors are exercised with synthetic `HttpResult` objects.
- Reports are rendered into `tmp_path` and checked for expected strings.

Run `pytest` from the project root. `RECONX_RESULTS` can redirect results for
manual experiments.
