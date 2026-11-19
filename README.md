# Subdomain Analyzer

Subdomain Analyzer is a concurrent, cache-aware scoring system that prioritises
subdomains for security research. It combines hostname keywords, live HTTP
status, missing security headers, historical URL paths, technology
fingerprints, and subdomain age into a single deterministic **0–100 score**.

The CLI is backwards compatible with v1:

```bash
python3 subdomain.py -i subs.txt -o report.txt -f txt -t 10
```

## Features

- **Hostname keyword analysis** — detects high-value tokens such as `admin`,
  `api`, `dev`, `staging`, and `vpn`.
- **HTTP liveness and header posture** — records status codes and scores
  missing security headers and permissive CORS.
- **Historical URL analysis** — uses `gau` (optional) to find sensitive paths
  such as `/.git/config`, `/admin`, and `/api`.
- **Technology fingerprinting** — optional Wappalyzer integration.
- **Subdomain age** — earliest capture from the Wayback Machine, with a
  `crt.sh` fallback.
- **Deterministic scoring** — every signal is broken out, the total is clamped
  to 0–100, and `--explain` shows exactly where the points came from.
- **Disk cache** — Wayback, crt.sh, and `gau` results are cached with a TTL so
  repeated runs do not re-query the same hosts.
- **Offline mode** — `--offline` makes zero network calls and scores from the
  hostname alone.
- **Machine-friendly output** — versioned JSON, CSV (header always present),
  and a human-readable TXT report.
- **Thread-safe** — thread-local HTTP sessions, a single shared rate limiter,
  and locks around the cache and Wappalyzer.

## Installation

Requires Python 3.9 or newer.

```bash
python3 -m pip install -r requirements.txt
```

For an editable install with the test and lint tooling:

```bash
python3 -m pip install -e ".[dev]"
```

Optional extras:

```bash
python3 -m pip install -e ".[wappalyzer]"   # technology fingerprinting
```

### External dependency

Historical URL analysis requires [gau](https://github.com/lc/gau) in `PATH`.
If it is missing, the analyzer logs a warning and continues without that
signal. `gau` is executed without a shell, with a `--` argument guard, and
with a 180-second timeout.

## Usage

```bash
subdomain-analyzer -i subs.txt -o report.txt
subdomain-analyzer -i subs.txt -o report.json -f json --explain
subdomain-analyzer -i - -o - -f json --offline < subs.txt
```

`-i -` reads from stdin and `-o -` writes the report to stdout. Progress and
logs always go to stderr, so piped output stays machine-readable.

### Arguments

| Argument | Description | Default |
|---|---|---|
| `-i`, `--input` | Input file, or `-` for stdin | required |
| `-o`, `--output` | Report path, or `-` for stdout | required |
| `-f`, `--format` | `txt`, `json`, or `csv` | `txt` |
| `-t`, `--threads` | Concurrent worker threads | `10` |
| `--top N` | Also write `<output>_topN.txt`; reflected in JSON | `0` |
| `--timeout` | HTTP timeout in seconds | `10` |
| `--retries` | Retries for transient HTTP failures | `2` |
| `--rate` | Outbound requests per second, shared by all calls | `5` |
| `--cache-dir` | Cache directory | `~/.cache/subdomain-analyzer` |
| `--cache-ttl` | Cache TTL in seconds; `0` disables expiry | `86400` |
| `--no-cache` | Disable the disk cache | off |
| `--offline` | Skip all network calls; score hostname only | off |
| `--explain` | Print per-signal score explanations to stderr | off |
| `--skip-wappalyzer`, `--no-wappalyzer` | Skip technology detection | off |
| `--skip-age` | Skip Wayback/crt.sh age lookups | off |
| `--skip-gau`, `--no-gau` | Skip historical URL fetching | off |
| `--skip-liveness` | Skip the HTTP liveness check | off |
| `-v`, `--verbose` | Debug logging on stderr | off |
| `-q`, `--quiet` | Suppress progress output | off |
| `--version` | Print the version and exit | — |

## Input handling

Each input line is normalised before analysis:

- schemes (`https://`), userinfo, ports, paths, queries, and fragments are
  stripped;
- wildcards such as `*.dev.example.com` become `dev.example.com`;
- trailing dots are removed, hosts are lowercased, and IDNA labels are
  converted to ASCII;
- blank lines and comments (`#`, `;`, `//`) are skipped;
- duplicates are removed and the result is sorted;
- invalid hosts are rejected with a warning instead of aborting the run.

## Scoring model

All signal points are deterministic. The total is clamped to **0–100**.

| Signal | Points | Cap |
|---|---|---|
| `keywords` | +5 per high-value token, +3 per other known token | 30 |
| `paths` | +7 per high-risk path, +5 per medium, +2 per low | 50 / 30 / 10 |
| `technology` | per-technology table, default +2 | 25 |
| `age` | ≥10y: 10, ≥5y: 5, ≥2y: 3, otherwise 1 | 10 |
| `status_code` | 401: 8, 403: 7, 405: 5, 500: 6, 502: 4, 503: 3, 301/302/307: 2 | 8 |
| `security_headers` | missing HSTS +5, CSP +5, X-Frame-Options +3, etc.; CORS `*` +5 or credentialed +8 | 28 |

Severity is a monotonic step function of the score:

| Severity | Score |
|---|---|
| `CRITICAL` | ≥ 50 |
| `HIGH` | ≥ 30 |
| `MEDIUM` | ≥ 15 |
| `LOW` | ≥ 5 |
| `INFO` | < 5 |
| `DEAD` | no HTTP response (liveness state, not a score tier) |
| `ERROR` | analysis failed for that host (not a score tier) |

A higher score never maps to a lower severity. `DEAD` and `ERROR` are
execution states and are listed after scored results; they are excluded from
top-N output.

## Output

### JSON

JSON output is a top-level object with a stable schema:

```json
{
  "tool": "subdomain-analyzer",
  "version": "2.0.0",
  "schema_version": 2,
  "generated_at": "2026-11-19T12:00:00Z",
  "total_analyzed": 1,
  "results": [
    {
      "subdomain": "admin.example.com",
      "score": 87,
      "severity": "CRITICAL",
      "signals": [
        {"name": "status_code", "points": 7, "detail": "HTTP 403"},
        {"name": "keywords", "points": 5, "detail": "admin"}
      ],
      "status_code": 403,
      "tech": ["nginx", "php"],
      "age_years": 6,
      "is_live": true,
      "final_url": "https://admin.example.com/",
      "matched_keywords": ["admin"],
      "matched_paths": {"high": [], "medium": [], "low": []},
      "security_header_issues": ["content-security-policy"],
      "score_breakdown": {"keywords": 5, "paths": 0, "technology": 12, "age": 5, "status_code": 7, "security_headers": 5},
      "total_points": 87
    }
  ]
}
```

`total_points` is a deprecated alias for `score`, kept for v1 consumers.
When `--top N` is used, the object also contains `top_n` and `top` (a list of
hostnames).

`--offline` uses `null` for unknown `status_code`, `is_live`, and `age_years`.

### CSV

The CSV writer always emits a header, including when there are zero results.
Signals are flattened into `name=points` pairs in the `signals` column.

### TXT

The TXT report includes the severity summary and a per-host score breakdown
with every signal, its points, and a short detail string.

## Caching

Wayback, crt.sh, and `gau` results are stored as one JSON file per key under
`~/.cache/subdomain-analyzer` (override with `--cache-dir`). Entries expire
after `--cache-ttl` seconds (default 86400). `--cache-ttl 0` keeps entries
indefinitely and `--no-cache` disables reads and writes.

HTTP liveness and headers are deliberately **not** cached, so status changes
are picked up on the next run.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Fatal error (missing input file, write failure, unexpected error) |
| `2` | No valid inputs after normalisation |

## Development

```bash
python3 -m pytest -q
ruff check .
```

The test suite makes no internet requests. Network-facing code paths are
tested with monkeypatching, fake clocks, and local fixtures.

## Known limitations

- The score is a heuristic prioritisation aid, not a vulnerability finding.
- No DNS resolution or port scanning is performed; liveness is HTTP(S) only.
- `gau` is an external dependency. Its output is capped at 50,000 URLs and a
  180-second run time.
- Wayback and crt.sh can rate-limit or return 5xx responses. Failures are
  treated as “age unknown” and cached as a negative result for the TTL.
- Technology detection uses Wappalyzer if installed; otherwise the signal is
  skipped. It inspects a single page and does not crawl.
- Age is approximate (whole years) and depends on third-party first-seen data.
- TLS certificate verification is intentionally disabled for liveness and
  technology requests so that invalid certificates can still be analysed.
- The disk cache is safe for concurrent processes through atomic per-entry
  writes, but it does not coordinate duplicate in-flight fetches.
- ANSI colours are never emitted, which keeps redirected output clean.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
