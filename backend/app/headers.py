"""Email header analyzer (docs/04-detection-engine.md §4). Runs for .eml input only."""

import re
from email.utils import parseaddr

from app.company import claimed_companies
from app.domain_intel import registrable
from app.domains import FREEMAIL_DOMAINS, HIRING_PLATFORM_DOMAINS, is_under
from app.models import DetectorResult, DetectorStatus, Offer, RedFlag, Severity

DETECTOR = "headers"

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
# Words in a sender name that present it as an organisation or its HR team.
_ORG_NAME_RE = re.compile(
    r"\b(?:hr|human\s+resources?|recruit\w*|hiring|talent|careers?|placements?|"
    r"pvt|private\s+limited|ltd|limited|technologies|solutions|infotech|services|"
    r"consultancy|corporation|inc|llp|group)\b",
    re.IGNORECASE,
)


def auth_results(header: str) -> dict[str, str]:
    """{'spf': 'pass', 'dkim': 'fail', 'dmarc': 'fail'} from an Authentication-Results
    header. With several DKIM signatures, one pass counts as pass."""
    results: dict[str, str] = {}
    for method, verdict in _AUTH_RE.findall(header):
        method, verdict = method.lower(), verdict.lower()
        if method == "dkim" and results.get("dkim") == "pass":
            continue
        results[method] = verdict
    return results


def _auth_flag(results: dict[str, str]) -> RedFlag | None:
    spf, dkim, dmarc = (results.get(k, "none") for k in ("spf", "dkim", "dmarc"))
    if dmarc == "fail" or (spf == "fail" and dkim != "pass"):
        severity = Severity.HIGH
    elif spf in ("fail", "softfail") or dkim == "fail":
        severity = Severity.MEDIUM
    else:
        return None
    return RedFlag(
        id="H-AUTHFAIL",
        detector=DETECTOR,
        severity=severity,
        message="The email failed sender authentication checks. It may not really come "
        "from the address shown in 'From'.",
        evidence=f"spf={spf}, dkim={dkim}, dmarc={dmarc}",
    )


def _domain(address: str) -> str | None:
    return address.rsplit("@", 1)[1] if "@" in address else None


def _org(domain: str) -> str:
    return registrable(domain) or domain


def analyze(offer: Offer) -> DetectorResult:
    if offer.source_type != "eml":
        return DetectorResult(DetectorStatus.SKIPPED)

    flags: list[RedFlag] = []
    checks: dict[str, str] = {}

    # 1. SPF / DKIM / DMARC from the receiving server's Authentication-Results.
    auth_header = offer.headers.get("authentication-results")
    if auth_header:
        results = auth_results(auth_header)
        checks["auth"] = "ok"
        if flag := _auth_flag(results):
            flags.append(flag)
    else:
        # Some exports drop this header; without it we cannot verify the sender.
        checks["auth"] = "not_available"

    from_name, from_addr = parseaddr(offer.sender or "")
    from_addr = from_addr.lower()
    from_domain = _domain(from_addr)
    _, reply_addr = parseaddr(offer.reply_to or "")
    reply_addr = reply_addr.lower()
    reply_domain = _domain(reply_addr)

    # 2. Replies go to a different organisation than the sender.
    if (
        from_domain
        and reply_domain
        and _org(reply_domain) != _org(from_domain)
        and not is_under(reply_domain, HIRING_PLATFORM_DOMAINS)
    ):
        flags.append(
            RedFlag(
                id="H-REPLYTO",
                detector=DETECTOR,
                severity=Severity.HIGH,
                message="Replies to this email go to a different address than the sender. "
                "Scammers do this to capture your reply.",
                evidence=f"From: {from_addr} → Reply-To: {reply_addr}",
            )
        )

    # 3. Sender name looks like a company or HR team, address is personal free-mail.
    #    Known companies are left to the company verifier (C-IMPERSONATION).
    sender_only = Offer("eml", "", sender=from_name)
    if (
        from_domain in FREEMAIL_DOMAINS
        and _ORG_NAME_RE.search(from_name)
        and not claimed_companies(sender_only)
    ):
        flags.append(
            RedFlag(
                id="H-DISPLAYNAME",
                detector=DETECTOR,
                severity=Severity.HIGH,
                message=f"The sender calls itself '{from_name}', but writes from a personal "
                "free email account, not a company domain.",
                evidence=f"{from_name} <{from_addr}>",
            )
        )

    status = DetectorStatus.OK if checks["auth"] == "ok" else DetectorStatus.PARTIAL
    return DetectorResult(status, flags, extra={"checks": checks})
