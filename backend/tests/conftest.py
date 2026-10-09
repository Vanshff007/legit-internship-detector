import httpx
import pytest

from app import cache, domain_intel, fetcher, ratelimit
from app.feedback import FEEDBACK_DB_ENV
from app.text_model import MODEL_PATH_ENV


@pytest.fixture(autouse=True)
def no_real_text_model(monkeypatch, tmp_path):
    """Keep tests deterministic: the real artifact is git-ignored and may change.

    Tests that need a model point MODEL_PATH_ENV at their own artifact.
    """
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "missing.joblib"))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No network in tests: every external lookup gets a 503, and the cache starts empty."""
    monkeypatch.setattr(
        domain_intel, "TRANSPORT", httpx.MockTransport(lambda request: httpx.Response(503))
    )
    monkeypatch.setattr(fetcher, "TRANSPORT", httpx.MockTransport(lambda r: httpx.Response(503)))
    monkeypatch.setattr(fetcher, "RESOLVE", _no_dns)
    monkeypatch.setattr(cache, "_cache", cache.MemoryCache())
    monkeypatch.delenv(domain_intel.SAFE_BROWSING_KEY_ENV, raising=False)


async def _no_dns(host: str, port: int) -> list[str]:
    raise OSError("DNS disabled in tests")


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    """Fresh rate limits and a throwaway feedback database for every test."""
    ratelimit.analyze_limit.reset()
    ratelimit.feedback_limit.reset()
    monkeypatch.setenv(FEEDBACK_DB_ENV, str(tmp_path / "feedback.sqlite3"))
