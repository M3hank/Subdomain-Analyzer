"""Subdomain age tests with fake Wayback/crt.sh responses."""

from datetime import date

import subdomain


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, payload):
        self.payload = payload
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        return FakeResponse(self.payload)


def _analyzer(client):
    return subdomain.Analyzer(
        subdomain.Config(
            offline=False,
            no_cache=True,
            skip_wappalyzer=True,
            skip_liveness=True,
            skip_gau=True,
        ),
        client=client,
    )


def test_wayback_first_capture():
    client = FakeClient(
        [
            ["urlkey", "timestamp"],
            ["com,example)/", "20100101000000"],
        ]
    )
    analyzer = _analyzer(client)
    assert analyzer._wayback_age("example.com") == date(2010, 1, 1)
    assert client.urls == [subdomain.WAYBACK_CDX_URL]


def test_crtsh_earliest_certificate_date():
    client = FakeClient(
        [
            {"not_before": "2020-05-01T00:00:00"},
            {"not_before": "2017-02-03T12:00:00"},
            {"not_before": "not-a-date"},
        ]
    )
    analyzer = _analyzer(client)
    assert analyzer._crtsh_age("example.com") == date(2017, 2, 3)
    assert client.urls == [subdomain.CRTSH_URL]


def test_age_falls_back_to_crtsh(monkeypatch):
    analyzer = _analyzer(FakeClient([]))
    monkeypatch.setattr(analyzer, "_wayback_age", lambda _host: None)
    monkeypatch.setattr(analyzer, "_crtsh_age", lambda _host: date(2020, 1, 1))

    years, first_seen, method = analyzer.get_subdomain_age("example.com")
    assert years >= 5
    assert first_seen == "2020-01-01"
    assert method == "crt.sh"


def test_age_unknown_is_zero():
    analyzer = _analyzer(FakeClient([]))
    analyzer._wayback_age = lambda _host: None
    analyzer._crtsh_age = lambda _host: None
    assert analyzer.get_subdomain_age("example.com") == (None, None, None)
    assert subdomain.score_age(None) == 0
