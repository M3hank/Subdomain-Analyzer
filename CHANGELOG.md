# Changelog

All notable changes to this project are documented here.

## [2.0.0] - 2026-11-19

### Added

- `--offline` mode that performs zero network calls and scores from the
  hostname alone.
- JSON disk cache with `--cache-dir`, `--cache-ttl`, and `--no-cache`.
  Wayback, crt.sh, and `gau` results are cached with a TTL.
- `--explain` flag and per-signal `signals` data in JSON output.
- Versioned JSON schema (`tool`, `version`, `schema_version`, `generated_at`,
  `results`) with `score`, `severity`, `signals`, `status_code`, `tech`, and
  `age_years` per result.
- CSV output with a guaranteed header, including zero-result runs.
- TXT reports now include the full score breakdown.
- Input support for stdin (`-i -`), wildcards, schemes, ports, comments, and
  invalid-host warnings.
- Exit codes: `0` success, `1` fatal error, `2` no valid inputs.
- `--timeout`, `--retries`, `--rate`, `-q/--quiet`, and `--version`.
- Single shared rate limiter for all outbound HTTP calls and `gau`.
- Thread-local `requests.Session` objects, cache locking, and a Wappalyzer
  lock.
- `crt.sh` fallback for subdomain age.
- `pyproject.toml` with the `subdomain-analyzer` console script, CI workflow,
  and an offline pytest suite.

### Changed

- Scoring is deterministic and clamped to 0–100. Severity thresholds are now
  `CRITICAL ≥ 50`, `HIGH ≥ 30`, `MEDIUM ≥ 15`, `LOW ≥ 5`, `INFO < 5`
  (the v1 CRITICAL/HIGH/MEDIUM cut-offs are preserved; INFO is now explicit).
- `gau` is invoked without a shell, with `shutil.which` discovery, a `--`
  argument guard, and a timeout.
- `--top N` is reflected in JSON (`top_n`, `top`) and still writes a separate
  `<output>_topN.txt` file.
- Logging goes to stderr only. Machine output is written to the chosen file
  or stdout.
- The old `--skip-*` flags remain, with `--no-gau` and `--no-wappalyzer`
  aliases added.

### Removed

- The implicit `subdomain_analyzer.log` side effect.
- ANSI colour output (output is always plain text).

## [1.1.0]

- Initial public scoring tool with keyword, liveness, header, `gau`,
  Wappalyzer, and Wayback signals.
