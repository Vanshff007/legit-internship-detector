import asyncio
import json
from datetime import date

import httpx
import pytest

from app import domain_intel
from app.domain_intel import analyze, lookalike_of, registrable, skeleton
from app.engine import _dedupe
from app.extractor import extract
from app.models import DetectorStatus, RedFlag, Severity
from app.parser import parse_text

TODAY = date(2026, 10, 9)
REGISTERED = {
    "fresh-jobs.in": "2026-09-20",  # 19 days old
    "young-hiring.com": "2026-03-01",  # ~7 months
    "oldcompany.com": "2010-01-01",
    "scam-site.com": "2026-10-01",
}


def handler(request: httpx.Request) -> httpx.Response:
    host, path = request.url.host, request.url.path
    if host == "data.iana.org":
        return httpx.Response(200, json={"services": [[["com", "in"], ["https://rdap.test/"]]]})
    if host == "rdap.test":
        domain = path.rsplit("/", 1)[1]
        if domain not in REGISTERED:
            return httpx.Response(404)
        events = [{"eventAction": "registration", "eventDate": REGISTERED[domain] + "T00:00:00Z"}]
        return httpx.Response(200, json={"events": events})
    if host == "bit.ly":
        return httpx.Response(301, headers={"location": "https://scam-site.com/pay"})
    if host == "safebrowsing.googleapis.com":
        entries = json.loads(request.content)["threatInfo"]["threatEntries"]
        matches = [
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": e["url"]}}
            for e in entries
            if "scam-site" in e["url"]
        ]
        return httpx.Response(200, json={"matches": matches} if matches else {})
    raise AssertionError(f"unexpected request to {request.url}")


def run(text: str, transport=None):
    offer = parse_text(text)

    async def go():
        async with httpx.AsyncClient(transport=transport or httpx.MockTransport(handler)) as c:
            return await analyze(offer, extract(offer), client=c, today=TODAY)

    return asyncio.run(go())


def ids(result) -> list[str]:
    return sorted(f.id for f in result.flags)


# --- lookalikes ------------------------------------------------------------------


def test_registrable():
    assert registrable("careers.infosys.co.in") == "infosys.co.in"
    assert registrable("192.168.1.1") is None


def test_skeleton_collapses_confusables():
    assert skeleton("inf0sys") == skeleton("lnfosys") == skeleton("infosys")
    assert skeleton("іnfosys") == skeleton("infosys")  # Cyrillic і
    assert skeleton("arnazon") == skeleton("amazon")


@pytest.mark.parametrize(
    ("domain", "company", "severity"),
    [
        ("inf0sys.com", "Infosys", Severity.HIGH),
        ("hr.lnfosys.com", "Infosys", Severity.HIGH),
        ("arnazon.in", "Amazon", Severity.HIGH),
        ("accentrue.com", "Accenture", Severity.HIGH),  # swapped letters
        ("accentur.com", "Accenture", Severity.HIGH),  # missing letter
        ("wipro.co", "Wipro", Severity.MEDIUM),  # same name, other extension
    ],
)
def test_lookalike_positive(domain, company, severity):
    match = lookalike_of(domain)
    assert match is not None and match[1] == company and match[2] == severity


@pytest.mark.parametrize(
    "domain",
    [
        "infosys.com",  # official
        "careers.infosys.com",  # official subdomain
        "gmail.com",
        "db.in",  # official label "db" is too short to compare
        "intex.com",  # one letter from "intel", but label shorter than 6
        "myworkdayjobs.com",
        "example.org",
    ],
)
def test_lookalike_negative(domain):
    assert lookalike_of(domain) is None


# --- detector --------------------------------------------------------------------


def test_new_domain_high_and_young_domain_medium(monkeypatch):
    monkeypatch.setenv(domain_intel.SAFE_BROWSING_KEY_ENV, "test-key")
    r = run("Apply at https://fresh-jobs.in/apply or mail hr@young-hiring.com")
    by_evidence = {f.evidence.split()[0]: f for f in r.flags}
    assert by_evidence["fresh-jobs.in"].severity == Severity.HIGH
    assert "19 days" in by_evidence["fresh-jobs.in"].message
    assert by_evidence["young-hiring.com"].severity == Severity.MEDIUM
    assert r.status == DetectorStatus.OK
    assert r.extra["checks"] == {"age": "ok", "safe_browsing": "ok"}


def test_old_and_unknown_domains_not_flagged(monkeypatch):
    monkeypatch.setenv(domain_intel.SAFE_BROWSING_KEY_ENV, "test-key")
    r = run("Contact jobs@oldcompany.com or visit https://unregistered-xyz.com")
    assert r.flags == [] and r.status == DetectorStatus.OK


def test_freemail_and_official_domains_skip_age_lookup():
    def no_rdap(request):
        assert request.url.host != "rdap.test", "should not look these up"
        return handler(request)

    r = run("Mail hr@gmail.com or campus@infosys.com", transport=httpx.MockTransport(no_rdap))
    assert r.flags == [] and r.extra["checks"] == {}


def test_shortener_expanded_and_safe_browsing(monkeypatch):
    monkeypatch.setenv(domain_intel.SAFE_BROWSING_KEY_ENV, "test-key")
    r = run("Pay here: https://bit.ly/abc123")
    assert ids(r) == ["D-NEWDOMAIN", "D-SAFEBROWSING"]
    sb = next(f for f in r.flags if f.id == "D-SAFEBROWSING")
    assert sb.evidence == "https://scam-site.com/pay" and sb.severity == Severity.CRITICAL
    assert r.extra["checks"] == {"shortener": "ok", "age": "ok", "safe_browsing": "ok"}
    assert r.status == DetectorStatus.OK


def test_missing_safe_browsing_key_is_partial():
    r = run("Details at https://oldcompany.com/jobs")
    assert r.extra["checks"]["safe_browsing"] == "not_configured"
    assert r.status == DetectorStatus.PARTIAL


def test_lookup_failure_is_partial_not_crash():
    r = run(
        "Visit https://inf0sys.com/apply",
        transport=httpx.MockTransport(lambda req: httpx.Response(503)),
    )
    assert ids(r) == ["D-LOOKALIKE"]  # local check still works
    assert r.extra["checks"]["age"] == "error" and r.status == DetectorStatus.PARTIAL


def test_results_are_cached():
    calls = []

    def counting(request):
        calls.append(request.url.host)
        return handler(request)

    run("Mail hr@fresh-jobs.in", transport=httpx.MockTransport(counting))
    run("Mail hr@fresh-jobs.in", transport=httpx.MockTransport(counting))
    assert calls.count("rdap.test") == 1 and calls.count("data.iana.org") == 1


def test_shortener_never_requests_other_hosts():
    seen = []

    def to_internal(request):
        seen.append(request.url.host)
        if request.url.host == "bit.ly":
            return httpx.Response(301, headers={"location": "http://127.0.0.1:8000/admin"})
        return handler(request)

    run("https://bit.ly/x", transport=httpx.MockTransport(to_internal))
    assert "127.0.0.1" not in seen


def test_dedupe_drops_lookalike_already_reported_as_impersonation():
    imp = RedFlag(
        id="C-IMPERSONATION", detector="company", severity="critical", message="m",
        evidence="https://inf0sys.com/apply",
    )  # fmt: skip
    look = RedFlag(
        id="D-LOOKALIKE", detector="domain", severity="high", message="m",
        evidence="inf0sys.com (looks like infosys.com)",
    )  # fmt: skip
    other = look.model_copy(update={"evidence": "wipro.co (looks like wipro.com)"})
    assert _dedupe([imp, look, other]) == [imp, other]
