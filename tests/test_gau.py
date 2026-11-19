"""gau integration tests: discovery, safety, timeout, cache, offline."""

import logging
import subprocess
from types import SimpleNamespace

import subdomain


def _analyzer(tmp_path, **overrides):
    config = subdomain.Config(
        offline=overrides.pop("offline", False),
        no_cache=overrides.pop("no_cache", True),
        skip_wappalyzer=True,
        skip_liveness=True,
        skip_age=True,
        **overrides,
    )
    client = subdomain.NetworkClient(
        rate=1000,
        limiter=subdomain.RateLimiter(calls_per_second=1000),
    )
    return subdomain.Analyzer(config, client=client)


def test_missing_gau_warns_once_and_returns_empty(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(subdomain.shutil, "which", lambda _name: None)
    analyzer = _analyzer(tmp_path)

    with caplog.at_level(logging.WARNING, logger="subdomain-analyzer"):
        assert analyzer.fetch_historical_urls("example.com") == []
        assert analyzer.fetch_historical_urls("example.com") == []

    warnings = [
        record for record in caplog.records if "gau not found" in record.getMessage()
    ]
    assert len(warnings) == 1


def test_gau_command_is_safe_and_has_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(subdomain.shutil, "which", lambda _name: "/usr/bin/gau")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout="https://example.com/b\nhttps://example.com/a\n"
            "https://example.com/a\n",
            stderr="",
        )

    monkeypatch.setattr(subdomain.subprocess, "run", fake_run)
    analyzer = _analyzer(tmp_path, gau_timeout=12)

    assert analyzer.fetch_historical_urls("example.com") == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert captured["command"] == ["/usr/bin/gau", "--", "example.com"]
    assert captured["kwargs"]["timeout"] == 12
    assert captured["kwargs"]["shell"] is False


def test_gau_timeout_is_handled(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(subdomain.shutil, "which", lambda _name: "/usr/bin/gau")

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="gau", timeout=1)

    monkeypatch.setattr(subdomain.subprocess, "run", timeout)
    analyzer = _analyzer(tmp_path, gau_timeout=1)

    with caplog.at_level(logging.WARNING, logger="subdomain-analyzer"):
        assert analyzer.fetch_historical_urls("example.com") == []
    assert any("timed out" in record.getMessage() for record in caplog.records)


def test_gau_results_are_cached(monkeypatch, tmp_path):
    monkeypatch.setattr(subdomain.shutil, "which", lambda _name: "/usr/bin/gau")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="https://example.com/x\n", stderr="")

    monkeypatch.setattr(subdomain.subprocess, "run", fake_run)
    cache = subdomain.DiskCache(str(tmp_path / "cache"), ttl=60)
    analyzer = subdomain.Analyzer(
        subdomain.Config(
            no_cache=False,
            skip_wappalyzer=True,
            skip_liveness=True,
            skip_age=True,
        ),
        client=subdomain.NetworkClient(
            rate=1000, limiter=subdomain.RateLimiter(calls_per_second=1000)
        ),
        cache=cache,
    )

    first = analyzer.fetch_historical_urls("example.com")
    second = analyzer.fetch_historical_urls("example.com")
    assert first == second == ["https://example.com/x"]
    assert len(calls) == 1


def test_offline_never_runs_gau(monkeypatch, tmp_path):
    def boom(*_args, **_kwargs):
        raise AssertionError("subprocess must not run in offline mode")

    monkeypatch.setattr(subdomain.subprocess, "run", boom)
    monkeypatch.setattr(subdomain.shutil, "which", boom)
    analyzer = _analyzer(tmp_path, offline=True)
    assert analyzer.fetch_historical_urls("example.com") == []
