"""Company verifier (docs/04-detection-engine.md §5).

Finds which known companies the offer claims to be from, then checks the contact
email domains and link domains against those companies' official domains.
"""

import json
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from app.domains import FREEMAIL_DOMAINS, HIRING_PLATFORM_DOMAINS, is_under
from app.extractor import domain_of_url
from app.models import DetectorResult, DetectorStatus, Entity, Offer, RedFlag, Severity

DETECTOR = "company"
DATA_FILE = Path(__file__).parent / "data" / "known_companies.json"

# Aliases this short are matched case-sensitively ("TCS", "EY", "Ola") to avoid hits on
# ordinary words.
SHORT_ALIAS_LEN = 4
# Slugs this long are searched as substrings of a domain ("infosys-careers.in");
# shorter ones must be a whole domain token ("tcs-hr.co").
SUBSTRING_SLUG_LEN = 6
MIN_SLUG_LEN = 3


@dataclass(frozen=True)
class KnownCompany:
    name: str
    aliases: tuple[str, ...]
    official_domains: tuple[str, ...]
    case_sensitive_aliases: frozenset[str]

    @property
    def slugs(self) -> set[str]:
        return {
            s
            for a in (self.name, *self.aliases)
            if len(s := re.sub(r"[^a-z0-9]", "", a.lower())) >= MIN_SLUG_LEN
        }


@cache
def known_companies() -> tuple[KnownCompany, ...]:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    return tuple(
        KnownCompany(
            name=c["name"],
            aliases=tuple(c.get("aliases", [])),
            official_domains=tuple(d.lower() for d in c["official_domains"]),
            case_sensitive_aliases=frozenset(c.get("case_sensitive_aliases", [])),
        )
        for c in raw
    )


@cache
def _name_index() -> tuple[re.Pattern[str], dict[str, KnownCompany]]:
    """One regex over every name and alias; longest alternatives first so
    "Tech Mahindra" wins over "Mahindra"."""
    by_alias: dict[str, KnownCompany] = {}
    parts: list[tuple[str, str]] = []
    for company in known_companies():
        for alias in (company.name, *company.aliases):
            exact = len(alias) <= SHORT_ALIAS_LEN or alias in company.case_sensitive_aliases
            by_alias[alias if exact else alias.lower()] = company
            parts.append((alias, re.escape(alias) if exact else f"(?i:{re.escape(alias)})"))
    parts.sort(key=lambda p: len(p[0]), reverse=True)
    pattern = re.compile(r"(?<!\w)(?:" + "|".join(p for _, p in parts) + r")(?!\w)")
    return pattern, by_alias


def claimed_companies(offer: Offer) -> list[KnownCompany]:
    """Known companies mentioned in the sender name or body, in order of first mention."""
    pattern, by_alias = _name_index()
    text = "\n".join(t for t in (offer.sender, offer.reply_to, offer.body_text) if t)
    found: dict[str, KnownCompany] = {}
    for m in pattern.finditer(text):
        alias = m.group(0)
        company = by_alias.get(alias) or by_alias[alias.lower()]
        found.setdefault(company.name, company)
    return list(found.values())


def is_official(domain: str, company: KnownCompany) -> bool:
    return is_under(domain, company.official_domains)


def imitates(domain: str, company: KnownCompany) -> bool:
    """Domain carries the company's name but is not one of its official domains."""
    if is_official(domain, company):
        return False
    tokens = re.split(r"[.\-]", domain)
    joined = "".join(tokens)
    return any(
        (slug in joined) if len(slug) >= SUBSTRING_SLUG_LEN else (slug in tokens)
        for slug in company.slugs
    )


def verify(offer: Offer, entities: list[Entity]) -> DetectorResult:
    claimed = claimed_companies(offer)
    if not claimed:
        return DetectorResult(DetectorStatus.OK, extra={"verified": False})

    emails = sorted({e.value for e in entities if e.type == "email"})
    links = sorted({e.value for e in entities if e.type == "url"})
    email_domains = {a.rsplit("@", 1)[1] for a in emails}
    all_known = known_companies()

    flags: list[RedFlag] = []

    # 1. Lookalike domains: a domain that uses a claimed company's name but is not
    #    official for any known company (so "techmahindra.com" never imitates Mahindra).
    for company in claimed:
        evidence = [
            item
            for item in (*emails, *links)
            if (d := _domain_of(item))
            and not is_under(d, HIRING_PLATFORM_DOMAINS)
            and not any(is_official(d, c) for c in all_known)
            and imitates(d, company)
        ]
        if evidence:
            flags.append(
                RedFlag(
                    id="C-IMPERSONATION",
                    detector=DETECTOR,
                    severity=Severity.CRITICAL,
                    message=f"Uses a website or email domain that imitates {company.name}. "
                    f"The official domain is {company.official_domains[0]}.",
                    evidence=", ".join(evidence),
                )
            )

    # 2. Free-mail contact while claiming a known company.
    primary = claimed[0]
    free = [a for a in emails if a.rsplit("@", 1)[1] in FREEMAIL_DOMAINS]
    if free and not any(f.id == "C-IMPERSONATION" for f in flags):
        flags.append(
            RedFlag(
                id="C-IMPERSONATION",
                detector=DETECTOR,
                severity=Severity.CRITICAL,
                message=f"Claims to be {primary.name}, but the contact address is a free "
                f"email account, not an official {primary.name} domain "
                f"({primary.official_domains[0]}).",
                evidence=", ".join(free),
            )
        )

    # 3. Trust signal: every contact address is official (or a hiring platform),
    #    and at least one is official for a claimed company.
    official_hit = next((c for c in claimed if any(is_official(d, c) for d in email_domains)), None)
    all_explained = all(
        is_under(d, HIRING_PLATFORM_DOMAINS) or any(is_official(d, c) for c in claimed)
        for d in email_domains
    )
    verified = official_hit is not None and all_explained and not flags

    return DetectorResult(
        DetectorStatus.OK,
        flags,
        extra={
            "verified": verified,
            "verified_company": official_hit.name if verified and official_hit else None,
            "claimed": [c.name for c in claimed],
        },
    )


def _domain_of(item: str) -> str | None:
    if "@" in item and "://" not in item:
        return item.rsplit("@", 1)[1]
    return domain_of_url(item)
