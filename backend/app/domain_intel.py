"""Domain intel detector (docs/04-detection-engine.md §3).

Checks every email and link domain in the offer:
- lookalike of a known company's official domain (homoglyphs, one-letter typos,
  same name on another extension) — local, no network;
- domain age via RDAP (WHOIS fallback for TLDs without RDAP);
- Google Safe Browsing for every link (needs SAFE_BROWSING_API_KEY);
- link shorteners are expanded first so the real destination is checked.

All lookups are cached and time out. A failed lookup marks the detector `partial`
(lower confidence); it never fails the request.
"""

import asyncio
import logging
import os
import ssl
import unicodedata
from collections.abc import Awaitable
from datetime import UTC, date, datetime
from functools import cache
from typing import Any, TypeVar
from urllib.parse import urljoin

import certifi
import httpx
import tldextract
from rapidfuzz.distance import OSA

from app.cache import Cache, get_cache
from app.company import known_companies
from app.domains import FREEMAIL_DOMAINS, HIRING_PLATFORM_DOMAINS, is_under
from app.extractor import domain_of_url
from app.models import DetectorResult, DetectorStatus, Entity, Offer, RedFlag, Severity

log = logging.getLogger(__name__)

DETECTOR = "domain"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_KEY_ENV = "SAFE_BROWSING_API_KEY"

# Budget: shortener expansion, then age + Safe Browsing in parallel, must finish
# inside the engine's 2.5 s timeout for this detector.
SHORTENER_TIMEOUT_S = 0.8
LOOKUP_TIMEOUT_S = 1.5
MAX_REDIRECT_HOPS = 3
MAX_AGE_LOOKUPS = 5
MAX_SAFE_BROWSING_URLS = 20
NEW_DOMAIN_DAYS = 90
YOUNG_DOMAIN_DAYS = 365
NOT_FOUND_TTL_S = 3600

# Lookalike thresholds. Short labels ("hp", "db", "gs") give too many accidental matches.
# Typos use OSA distance: one edit, or one swap of adjacent letters.
MIN_LOOKALIKE_LABEL = 4
MIN_EDIT_DISTANCE_LABEL = 6

SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "ow.ly",
        "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id", "bit.do", "shorturl.gg",
    }
)  # fmt: skip

_CONFUSABLES = str.maketrans(
    {
        "0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s", "$": "s", "@": "a",
        # Cyrillic letters that look Latin
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "і": "l", "ӏ": "l", "ѕ": "s", "ԁ": "d", "ј": "j", "ԛ": "q", "ԝ": "w",
    }
)  # fmt: skip

# Tests replace this with an httpx.MockTransport so they never touch the network.
TRANSPORT: httpx.AsyncBaseTransport | None = None

_tld = tldextract.TLDExtract(suffix_list_urls=())  # bundled public suffix list, no network

T = TypeVar("T")


# --- lookalikes ------------------------------------------------------------------


def registrable(domain: str) -> str | None:
    """'careers.infosys.co.in' -> 'infosys.co.in'. None for IPs and bare hosts."""
    return _tld(domain).top_domain_under_public_suffix or None


def skeleton(label: str) -> str:
    """Collapse characters that look alike, so 'inf0sys', 'lnfosys' and 'іnfosys' match."""
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    s = unicodedata.normalize("NFKC", label.lower()).translate(_CONFUSABLES)
    return s.replace("rn", "m").replace("vv", "w").replace("-", "")


@cache
def _official_domains() -> dict[str, str]:
    """Official registrable domain -> company name."""
    return {d: c.name for c in known_companies() for d in c.official_domains}


def lookalike_of(domain: str) -> tuple[str, str, Severity] | None:
    """(official_domain, company, severity) if `domain` imitates a known official domain."""
    reg = registrable(domain)
    if not reg or reg in _official_domains() or reg in FREEMAIL_DOMAINS:
        return None
    if is_under(reg, HIRING_PLATFORM_DOMAINS):
        return None
    label = reg.split(".", 1)[0]
    for official, company in _official_domains().items():
        o_label = official.split(".", 1)[0]
        if len(o_label) < MIN_LOOKALIKE_LABEL:
            continue
        if label == o_label:
            # Same name, different extension: often a scam, sometimes a regional site.
            return official, company, Severity.MEDIUM
        if skeleton(label) == skeleton(o_label):
            return official, company, Severity.HIGH
        if len(o_label) >= MIN_EDIT_DISTANCE_LABEL and OSA.distance(label, o_label) == 1:
            return official, company, Severity.HIGH
    return None


# --- network lookups -------------------------------------------------------------


@cache
def _ssl_context() -> ssl.SSLContext:
    # Building this takes ~250 ms on Windows; a fresh httpx client per request would
    # pay that cost every time.
    return ssl.create_default_context(cafile=certifi.where())


async def _guarded(coro: Awaitable[T], timeout: float) -> tuple[bool, T | None]:
    try:
        return True, await asyncio.wait_for(coro, timeout)
    except Exception as exc:  # includes TimeoutError
        log.info("domain lookup failed: %s: %s", type(exc).__name__, exc)
        return False, None


async def expand_shortener(url: str, client: httpx.AsyncClient, cache: Cache) -> str:
    """Follow redirects only while the host is a known shortener. Never requests any
    other host, so a user-supplied link cannot make the server fetch internal URLs."""
    if (hit := await cache.get(f"short:{url}")) is not None:
        return hit
    current = url
    for _ in range(MAX_REDIRECT_HOPS):
        host = domain_of_url(current)
        if not host or host not in SHORTENERS:
            break
        r = await client.head(current, follow_redirects=False)
        location = r.headers.get("location")
        if not location:
            r = await client.get(current, follow_redirects=False)
            location = r.headers.get("location")
        if not location:
            break
        current = urljoin(current, location)
    await cache.set(f"short:{url}", current)
    return current


async def _rdap_base(tld: str, client: httpx.AsyncClient, cache: Cache) -> str | None:
    services = await cache.get("rdap:bootstrap")
    if services is None:
        r = await client.get(RDAP_BOOTSTRAP_URL)
        r.raise_for_status()
        services = r.json()["services"]
        await cache.set("rdap:bootstrap", services)
    for tlds, urls in services:
        if tld in tlds:
            return urls[0]
    return None


def _whois_created(domain: str) -> str | None:
    import whois  # python-whois; slow, only for TLDs without RDAP

    created = whois.whois(domain).creation_date
    if isinstance(created, list):
        created = min(created)
    return created.date().isoformat() if isinstance(created, datetime) else None


async def registration_date(domain: str, client: httpx.AsyncClient, cache: Cache) -> date | None:
    """Registration date of a registrable domain; None if unknown or not registered."""
    hit = await cache.get(f"age:{domain}")
    if hit is not None:
        return date.fromisoformat(hit["created"]) if hit["created"] else None

    base = await _rdap_base(domain.rsplit(".", 1)[-1], client, cache)
    created: str | None = None
    if base:
        r = await client.get(
            f"{base.rstrip('/')}/domain/{domain}", headers={"Accept": "application/rdap+json"}
        )
        if r.status_code == 404:
            await cache.set(f"age:{domain}", {"created": None}, NOT_FOUND_TTL_S)
            return None
        r.raise_for_status()
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration":
                created = event["eventDate"][:10]
                break
    else:
        created = await asyncio.to_thread(_whois_created, domain)

    await cache.set(f"age:{domain}", {"created": created})
    return date.fromisoformat(created) if created else None


async def safe_browsing(
    urls: list[str], key: str, client: httpx.AsyncClient, cache: Cache
) -> dict[str, str]:
    """URL -> threat type, for URLs Google Safe Browsing lists as dangerous."""
    threats: dict[str, str] = {}
    todo: list[str] = []
    for url in urls:
        hit = await cache.get(f"sb:{url}")
        if hit is None:
            todo.append(url)
        elif hit:
            threats[url] = hit
    if not todo:
        return threats

    body = {
        "client": {"clientId": "legit-internship-detector", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in todo],
        },
    }
    r = await client.post(SAFE_BROWSING_URL, params={"key": key}, json=body)
    r.raise_for_status()
    found = {m["threat"]["url"]: m["threatType"] for m in r.json().get("matches", [])}
    for url in todo:
        await cache.set(f"sb:{url}", found.get(url, ""))
    return threats | found


async def warm_up() -> None:
    """Build the SSL context and fetch the RDAP bootstrap before the first request."""
    _ssl_context()
    async with httpx.AsyncClient(
        transport=TRANSPORT, verify=_ssl_context(), timeout=LOOKUP_TIMEOUT_S
    ) as client:
        ok, _ = await _guarded(_rdap_base("com", client, get_cache()), 5.0)
    if not ok:
        log.warning("RDAP bootstrap not loaded at startup; will retry on first lookup")


# --- detector --------------------------------------------------------------------


def _age_flag(domain: str, created: date, today: date) -> RedFlag | None:
    days = (today - created).days
    if days >= YOUNG_DOMAIN_DAYS:
        return None
    new = days < NEW_DOMAIN_DAYS
    return RedFlag(
        id="D-NEWDOMAIN",
        detector=DETECTOR,
        severity=Severity.HIGH if new else Severity.MEDIUM,
        message=f"The domain {domain} was registered only {days} days ago. "
        "Scam sites and fake HR emails often use brand-new domains."
        if new
        else f"The domain {domain} is less than a year old ({days} days). "
        "Established employers usually have older domains.",
        evidence=f"{domain} registered {created.isoformat()}",
    )


def _needs_age_check(reg: str) -> bool:
    return not (
        reg in FREEMAIL_DOMAINS
        or reg in SHORTENERS
        or reg in _official_domains()
        or is_under(reg, HIRING_PLATFORM_DOMAINS)
    )


async def analyze(
    offer: Offer,
    entities: list[Entity],
    client: httpx.AsyncClient | None = None,
    today: date | None = None,
) -> DetectorResult:
    if client is None:
        async with httpx.AsyncClient(
            transport=TRANSPORT,
            verify=_ssl_context(),
            timeout=LOOKUP_TIMEOUT_S,
            headers={"User-Agent": "LegitInternshipDetector/0.1"},
        ) as own:
            return await analyze(offer, entities, own, today)

    cache = get_cache()
    today = today or datetime.now(UTC).date()
    checks: dict[str, str] = {}
    flags: list[RedFlag] = []

    urls = list(dict.fromkeys(e.value for e in entities if e.type == "url"))
    email_domains = [e.value.rsplit("@", 1)[1] for e in entities if e.type == "email"]

    # 1. Expand shorteners so the real destination gets checked.
    short = [u for u in urls if domain_of_url(u) in SHORTENERS]
    if short:
        results = await asyncio.gather(
            *(_guarded(expand_shortener(u, client, cache), SHORTENER_TIMEOUT_S) for u in short)
        )
        checks["shortener"] = "ok" if all(ok for ok, _ in results) else "error"
        urls += [v for ok, v in results if ok and v and v not in urls]

    domains = list(dict.fromkeys(email_domains + [d for u in urls if (d := domain_of_url(u))]))

    # 2. Lookalikes (local).
    for domain in domains:
        if match := lookalike_of(domain):
            official, company, severity = match
            flags.append(
                RedFlag(
                    id="D-LOOKALIKE",
                    detector=DETECTOR,
                    severity=severity,
                    message=f"{domain} looks like {official}, the official domain of "
                    f"{company}, but it is a different domain.",
                    evidence=f"{domain} (looks like {official})",
                )
            )

    # 3. Domain age and 4. Safe Browsing, in parallel.
    regs = [r for r in dict.fromkeys(registrable(d) for d in domains) if r and _needs_age_check(r)][
        :MAX_AGE_LOOKUPS
    ]
    age_tasks = [_guarded(registration_date(r, client, cache), LOOKUP_TIMEOUT_S) for r in regs]

    sb_key = os.environ.get(SAFE_BROWSING_KEY_ENV, "")
    sb_urls = urls[:MAX_SAFE_BROWSING_URLS]
    sb_task: Awaitable[tuple[bool, Any]] | None = None
    if sb_urls and sb_key:
        sb_task = _guarded(safe_browsing(sb_urls, sb_key, client, cache), LOOKUP_TIMEOUT_S)

    results = await asyncio.gather(*age_tasks, *([sb_task] if sb_task else []))
    age_results, sb_result = results[: len(regs)], (results[-1] if sb_task else None)

    if regs:
        checks["age"] = "ok" if all(ok for ok, _ in age_results) else "error"
    for reg, (ok, created) in zip(regs, age_results, strict=True):
        if ok and created and (flag := _age_flag(reg, created, today)):
            flags.append(flag)

    if sb_urls:
        if sb_result is None:
            checks["safe_browsing"] = "not_configured"
        else:
            ok, threats = sb_result
            checks["safe_browsing"] = "ok" if ok else "error"
            for url, threat in (threats or {}).items():
                flags.append(
                    RedFlag(
                        id="D-SAFEBROWSING",
                        detector=DETECTOR,
                        severity=Severity.CRITICAL,
                        message="Google Safe Browsing lists this link as dangerous "
                        f"({threat.replace('_', ' ').lower()}). Do not open it.",
                        evidence=url,
                    )
                )

    complete = all(v == "ok" for v in checks.values())
    return DetectorResult(
        DetectorStatus.OK if complete else DetectorStatus.PARTIAL,
        flags,
        extra={"checks": checks},
    )
