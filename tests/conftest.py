"""Shared pytest fixtures for the Subdomain Analyzer test suite."""

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import subdomain  # noqa: E402  (path setup must run first)


@pytest.fixture(autouse=True)
def reset_analyzer_logger():
    """Keep logger state from leaking between tests."""
    yield
    subdomain.LOGGER.handlers.clear()
    subdomain.LOGGER.propagate = True
    subdomain.LOGGER.setLevel(logging.NOTSET)


class FakeClock:
    """Deterministic clock for cache and rate-limiter tests."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()
