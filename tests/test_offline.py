"""Offline-mode tests: no sockets, no subprocesses, hostname-only scoring."""

import subdomain


def _forbid(*_args, **_kwargs):
    raise AssertionError("offline mode must not perform network or subprocess calls")


def test_offline_analyzer_performs_no_network_calls(monkeypatch):
    monkeypatch.setattr(subdomain.NetworkClient, "get", _forbid)
    monkeypatch.setattr(subdomain.requests.Session, "request", _forbid)
    monkeypatch.setattr(subdomain.subprocess, "run", _forbid)
    monkeypatch.setattr(subdomain.shutil, "which", _forbid)

    analyzer = subdomain.Analyzer(subdomain.Config(offline=True, no_cache=True))
    result = analyzer.analyze("secure.admin.example.com")

    assert analyzer.wappalyzer is None
    assert result["score"] == 10  # secure + admin
    assert [signal["name"] for signal in result["signals"]] == ["keywords"]
    assert result["status_code"] is None
    assert result["is_live"] is None
    assert result["tech"] == []
    assert result["age_years"] is None
    assert result["matched_keywords"] == ["admin", "secure"]


def test_offline_analyze_many_is_deterministic(monkeypatch):
    monkeypatch.setattr(subdomain.NetworkClient, "get", _forbid)
    analyzer = subdomain.Analyzer(
        subdomain.Config(offline=True, no_cache=True, threads=4, quiet=True)
    )
    hosts = ["api.example.com", "admin.example.com", "www.example.com"]
    first = analyzer.analyze_many(hosts)
    second = analyzer.analyze_many(list(reversed(hosts)))

    assert [item["subdomain"] for item in first] == [
        item["subdomain"] for item in second
    ]
    assert [item["subdomain"] for item in first] == [
        "admin.example.com",
        "api.example.com",
        "www.example.com",
    ]
