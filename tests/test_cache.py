"""Disk cache tests: hit/miss, persistence, TTL expiry, corruption."""

import json
import time

import subdomain


def test_cache_miss_then_hit(tmp_path):
    cache = subdomain.DiskCache(str(tmp_path), ttl=60)
    hit, value = cache.get("v2:age:example.com")
    assert hit is False
    assert value is None

    cache.set("v2:age:example.com", [7, "2019-01-01", "Wayback Machine"])
    hit, value = cache.get("v2:age:example.com")
    assert hit is True
    assert value == [7, "2019-01-01", "Wayback Machine"]


def test_cache_persists_across_instances(tmp_path):
    first = subdomain.DiskCache(str(tmp_path), ttl=60)
    first.set("key", {"nested": [1, 2, 3]})

    second = subdomain.DiskCache(str(tmp_path), ttl=60)
    hit, value = second.get("key")
    assert hit is True
    assert value == {"nested": [1, 2, 3]}


def test_cache_ttl_expiry(tmp_path, fake_clock):
    cache = subdomain.DiskCache(str(tmp_path), ttl=10, clock=fake_clock)
    cache.set("key", "value")
    assert cache.get("key") == (True, "value")

    fake_clock.advance(11)
    assert cache.get("key") == (False, None)
    # The expired file is removed, not merely ignored.
    assert not cache._path("key").exists()


def test_cache_ttl_zero_never_expires(tmp_path, fake_clock):
    cache = subdomain.DiskCache(str(tmp_path), ttl=0, clock=fake_clock)
    cache.set("key", "value")
    fake_clock.advance(10 * 365 * 24 * 3600)
    assert cache.get("key") == (True, "value")


def test_cache_disabled_does_not_write(tmp_path):
    cache = subdomain.DiskCache(str(tmp_path), ttl=60, enabled=False)
    cache.set("key", "value")
    assert cache.get("key") == (False, None)
    assert list(tmp_path.iterdir()) == []


def test_corrupt_cache_entry_is_a_miss(tmp_path):
    cache = subdomain.DiskCache(str(tmp_path), ttl=60)
    cache.set("key", "value")
    path = cache._path("key")
    path.write_text("this is not json", encoding="utf-8")
    assert cache.get("key") == (False, None)
    assert not path.exists()


def test_cache_entry_is_json_with_metadata(tmp_path):
    cache = subdomain.DiskCache(str(tmp_path), ttl=60)
    cache.set("key", ["a", 1])
    payload = json.loads(cache._path("key").read_text(encoding="utf-8"))
    assert payload["key"] == "key"
    assert isinstance(payload["created_at"], float)
    assert payload["value"] == ["a", 1]
    assert payload["created_at"] <= time.time() + 1


def test_analyzer_uses_cache_for_repeated_fetches(tmp_path, fake_clock):
    cache = subdomain.DiskCache(str(tmp_path), ttl=5, clock=fake_clock)
    analyzer = subdomain.Analyzer(
        subdomain.Config(offline=True, no_cache=False),
        cache=cache,
    )
    calls = []

    def fetch():
        calls.append(1)
        return {"value": len(calls)}

    assert analyzer._cached("age", "example.com", fetch) == {"value": 1}
    assert analyzer._cached("age", "example.com", fetch) == {"value": 1}
    assert len(calls) == 1

    fake_clock.advance(6)
    assert analyzer._cached("age", "example.com", fetch) == {"value": 2}
    assert len(calls) == 2
