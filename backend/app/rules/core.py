"""First five rules from docs/04-detection-engine.md §2.

Each rule takes the Offer and its entities and returns a list of RedFlags.
"""

import re

from app.domains import FREEMAIL_DOMAINS
from app.models import Entity, Offer, RedFlag, Severity
from app.rules._helpers import first_unnegated, sentence_around

DETECTOR = "rules"

_FEE_RE = re.compile(
    r"\b(?:registration|training|kit|security|joining|processing|refundable|onboarding"
    r"|verification|application|enrol(?:l)?ment|certificate|interview|laptop|id\s?card)"
    r"\s+(?:fee|fees|charges?|deposit|amount|cost)\b"
    r"|\b(?:pay|deposit|transfer|send)\b[^.\n]{0,40}?(?:₹|\brs\.?\s?\d|\binr\b|rupees|\bfees?\b)"
    r"|\brefundable\b[^.\n]{0,30}\b(?:amount|deposit|fee)\b",
    re.IGNORECASE,
)

_OFFPLATFORM_RE = re.compile(
    r"\b(?:whats\s?app|telegram)\b|\b(?:wa\.me|t\.me)/\S+",
    re.IGNORECASE,
)

_URGENCY_RE = re.compile(
    r"\blimited\s+(?:seats|slots|vacanc(?:y|ies)|positions|openings)\b"
    r"|\bonly\s+\d+\s+(?:seats|slots|positions|vacancies)\b"
    r"|\bwithin\s+(?:the\s+next\s+)?\d+\s*(?:hours?|hrs?|minutes?|mins?)\b"
    r"|\b(?:offer|link|seat)s?\s+(?:will\s+)?expires?\s+(?:today|tonight|soon|in\s+\d+)"
    r"|\blast\s+date\s+(?:is\s+)?today\b"
    r"|\b(?:urgent(?:ly)?\s+(?:hiring|requirement|joining)|immediate\s+joining\s+required)\b"
    r"|\b(?:act|apply|register)\s+now\b[^.\n]{0,20}\b(?:before|or)\b"
    r"|\bhurry\b",
    re.IGNORECASE,
)

_TASK_RE = re.compile(
    r"\b(?:lik(?:e|es|ed|ing)|subscrib\w*|rat(?:e|es|ed|ing)|review\w*|follow\w*|watch\w*"
    r"|shar(?:e|es|ed|ing))\b[^.\n]{0,40}?"
    r"\b(?:videos?|hotels?|products?|channels?|posts?|apps?|movies?|reels?|pages?|restaurants?)\b",
    re.IGNORECASE,
)
_EARN_RE = re.compile(
    r"\b(?:earn|earning|income|commission|paid|payout|per\s+task|daily\s+pay)\b|₹|\brs\.?\s?\d",
    re.IGNORECASE,
)


def fee_demand(offer: Offer, entities: list[Entity]) -> list[RedFlag]:
    m = first_unnegated(_FEE_RE, offer.body_text)
    if not m:
        return []
    return [
        RedFlag(
            id="R-FEE",
            detector=DETECTOR,
            severity=Severity.CRITICAL,
            message="The offer asks you to pay money (fee, deposit or charges). "
            "Genuine employers never charge candidates.",
            evidence=sentence_around(offer.body_text, *m.span()),
        )
    ]


def off_platform_contact(offer: Offer, entities: list[Entity]) -> list[RedFlag]:
    m = first_unnegated(_OFFPLATFORM_RE, offer.body_text)
    if not m:
        return []
    return [
        RedFlag(
            id="R-OFFPLATFORM",
            detector=DETECTOR,
            severity=Severity.HIGH,
            message="The recruiter wants to move the conversation to WhatsApp or Telegram. "
            "Real companies use official email and hiring portals.",
            evidence=sentence_around(offer.body_text, *m.span()),
        )
    ]


def free_mail_sender(offer: Offer, entities: list[Entity]) -> list[RedFlag]:
    addresses = sorted(
        {
            e.value
            for e in entities
            if e.type == "email" and e.value.rsplit("@", 1)[1] in FREEMAIL_DOMAINS
        }
    )
    if not addresses:
        return []
    return [
        RedFlag(
            id="R-FREEMAIL",
            detector=DETECTOR,
            severity=Severity.HIGH,
            message="The recruiter uses a free personal email address (Gmail, Yahoo, etc.) "
            "instead of an official company domain.",
            evidence=", ".join(addresses),
        )
    ]


def urgency(offer: Offer, entities: list[Entity]) -> list[RedFlag]:
    m = first_unnegated(_URGENCY_RE, offer.body_text)
    if not m:
        return []
    return [
        RedFlag(
            id="R-URGENCY",
            detector=DETECTOR,
            severity=Severity.MEDIUM,
            message="The message pressures you to act fast. Scammers create urgency "
            "so you do not stop to verify.",
            evidence=sentence_around(offer.body_text, *m.span()),
        )
    ]


def task_for_pay(offer: Offer, entities: list[Entity]) -> list[RedFlag]:
    text = offer.body_text
    for m in _TASK_RE.finditer(text):
        sentence = sentence_around(text, *m.span())
        if _EARN_RE.search(sentence):
            return [
                RedFlag(
                    id="R-TASKPAY",
                    detector=DETECTOR,
                    severity=Severity.CRITICAL,
                    message="Promises money for simple online tasks like liking videos or "
                    "rating hotels. This is a well-known task scam.",
                    evidence=sentence,
                )
            ]
    return []
