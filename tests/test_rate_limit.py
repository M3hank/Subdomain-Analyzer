"""Rate limiter and thread-local session tests."""

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import subdomain


def test_rate_limiter_enforces_interval(fake_clock):
    limiter = subdomain.RateLimiter(
        calls_per_second=2, clock=fake_clock, sleep=fake_clock.sleep
    )
    limiter.wait()
    assert fake_clock.now == 1_000_000.0

    limiter.wait()
    assert abs(fake_clock.now - (1_000_000.0 + 0.5)) < 1e-9

    limiter.wait()
    assert abs(fake_clock.now - (1_000_000.0 + 1.0)) < 1e-9


def test_rate_limiter_rejects_zero():
    try:
        subdomain.RateLimiter(calls_per_second=0)
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_network_client_uses_single_shared_limiter(fake_clock):
    limiter = subdomain.RateLimiter(
        calls_per_second=10, clock=fake_clock, sleep=fake_clock.sleep
    )
    client = subdomain.NetworkClient(limiter=limiter)
    assert client.limiter is limiter
    assert client.timeout[1] == subdomain.REQUEST_TIMEOUT


def test_sessions_are_thread_local():
    client = subdomain.NetworkClient(rate=1000)
    main_session = client._session()
    assert client._session() is main_session

    with ThreadPoolExecutor(max_workers=1) as executor:
        other_session = executor.submit(client._session).result()
    assert other_session is not main_session
    assert client._session() is main_session


def test_retries_pass_through_the_limiter(monkeypatch, fake_clock):
    monkeypatch.setattr(subdomain.time, "sleep", lambda _seconds: None)
    limiter = subdomain.RateLimiter(
        calls_per_second=1000, clock=fake_clock, sleep=fake_clock.sleep
    )
    client = subdomain.NetworkClient(retries=2, limiter=limiter)
    responses = [
        SimpleNamespace(status_code=503),
        SimpleNamespace(status_code=200),
    ]
    calls = []

    class FakeSession:
        def get(self, url, **_kwargs):
            calls.append(url)
            return responses[len(calls) - 1]

    monkeypatch.setattr(client, "_session", lambda: FakeSession())
    response = client.get("https://example.com")
    assert response.status_code == 200
    assert len(calls) == 2
