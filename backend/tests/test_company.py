import json

import pytest

from app.company import DATA_FILE, claimed_companies, imitates, known_companies, verify
from app.domains import FREEMAIL_DOMAINS
from app.extractor import extract
from app.models import Offer
from app.parser import parse_text


def run(text: str, sender: str | None = None):
    offer = parse_text(text)
    if sender:
        offer = Offer("eml", offer.body_text, sender=sender, links=offer.links)
    return verify(offer, extract(offer))


def company(name: str):
    return next(c for c in known_companies() if c.name == name)


# --- seed list ---------------------------------------------------------------


def test_seed_list_has_100_unique_companies():
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    assert len(raw) == 100
    assert len({c["name"] for c in raw}) == 100


def test_no_official_domain_is_free_mail_or_shared():
    owners: dict[str, str] = {}
    for c in known_companies():
        for d in c.official_domains:
            assert d not in FREEMAIL_DOMAINS, (c.name, d)
            assert d not in owners, f"{d} listed for {owners.get(d)} and {c.name}"
            owners[d] = c.name


# --- name matching -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Selected for TCS Digital role", ["Tata Consultancy Services"]),
        ("Offer from Tech Mahindra, Pune", ["Tech Mahindra"]),  # not Mahindra & Mahindra
        ("Join amazon as data entry operator", ["Amazon"]),
        ("Kotak Mahindra Bank internship", ["Kotak Mahindra Bank"]),
        ("We place reliance on our interviews", []),  # "Reliance" is case-sensitive
        ("Our team works on Oracle databases", ["Oracle"]),
        ("tcs is hiring", []),  # short aliases need exact case
        ("Infosys and Wipro are both hiring", ["Infosys", "Wipro"]),
    ],
)
def test_claimed_companies(text, expected):
    assert [c.name for c in claimed_companies(parse_text(text))] == expected


def test_sender_display_name_counts_as_claim():
    offer = Offer("eml", "Please find your offer attached.", sender="Infosys HR <hr@gmail.com>")
    assert [c.name for c in claimed_companies(offer)] == ["Infosys"]


# --- lookalike domains ---------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "name"),
    [
        ("infosys-careers.in", "Infosys"),
        ("tcs-hr.co", "Tata Consultancy Services"),
        ("amazon-hr-jobs.in", "Amazon"),
        ("careers.wipro-india.com", "Wipro"),
    ],
)
def test_imitates_positive(domain, name):
    assert imitates(domain, company(name))


@pytest.mark.parametrize(
    ("domain", "name"),
    [
        ("infosys.com", "Infosys"),
        ("careers.infosys.com", "Infosys"),
        ("amazon.jobs", "Amazon"),
        ("statistics.example.com", "Tata Consultancy Services"),  # "tcs" only as substring
        ("example.com", "Amazon"),
    ],
)
def test_imitates_negative(domain, name):
    assert not imitates(domain, company(name))


# --- verify() ------------------------------------------------------------------


def test_free_mail_impersonation():
    r = run("You are selected at Amazon. Send documents to amazon.hr.jobs@gmail.com")
    [flag] = r.flags
    assert flag.id == "C-IMPERSONATION" and flag.severity == "critical"
    assert "Amazon" in flag.message and flag.evidence == "amazon.hr.jobs@gmail.com"
    assert r.extra["verified"] is False


def test_lookalike_link_impersonation():
    r = run("Infosys internship 2026. Apply at https://infosys-careers.in/apply")
    assert [f.id for f in r.flags] == ["C-IMPERSONATION"]
    assert "infosys-careers.in" in r.flags[0].evidence


def test_lookalike_email_impersonation():
    r = run("TCS offer letter", sender="TCS Recruitment <offers@tcs-hr.co>")
    assert [f.id for f in r.flags] == ["C-IMPERSONATION"]


def test_official_sender_is_verified():
    r = run(
        "Thank you for interviewing with Infosys. Your offer letter is attached.",
        sender="Infosys Campus Hiring <campus.hiring@infosys.com>",
    )
    assert r.flags == []
    assert r.extra["verified"] is True and r.extra["verified_company"] == "Infosys"


def test_subdomain_and_hiring_platform_still_verified():
    r = run(
        "Accenture interview schedule. Questions: recruit@in.accenture.com "
        "or noreply@accenture.myworkday.com"
    )
    assert r.flags == [] and r.extra["verified"] is True


def test_unrelated_corporate_domain_is_neutral():
    # A small firm mentioning a big client is not impersonation.
    r = run("We are an Accenture partner. Contact jobs@smallfirm.co.in to apply.")
    assert r.flags == [] and r.extra["verified"] is False


def test_other_companys_official_domain_is_not_a_lookalike():
    r = run("Mahindra group company. Contact hr@techmahindra.com")
    assert not r.flags


def test_no_company_claimed():
    r = run("Data entry work from home. Contact jobs@gmail.com")
    assert r.flags == [] and r.extra["verified"] is False
