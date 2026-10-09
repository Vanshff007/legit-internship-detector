"""Pull entities (emails, domains, phones, money, contact channels) out of an Offer."""

import re
from urllib.parse import urlparse

from app.models import Entity, Offer
from app.parser import address_of

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Indian mobile numbers, optionally with +91 / 0 prefix.
PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
MONEY_RE = re.compile(
    r"(?:₹|\brs\.?|\binr)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:k|lakh|lpa))?"
    r"|\b\d[\d,]*(?:\.\d+)?\s?(?:rupees|/-)",
    re.IGNORECASE,
)
CHANNEL_RE = re.compile(r"\b(whats\s?app|telegram)\b|\b(wa\.me|t\.me)/", re.IGNORECASE)


def domain_of_url(url: str) -> str | None:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname
    return host.lower().removeprefix("www.") if host else None


def _channel_name(raw: str) -> str:
    raw = raw.lower()
    return "whatsapp" if raw.startswith(("wh", "wa")) else "telegram"


def extract(offer: Offer) -> list[Entity]:
    text = offer.body_text
    entities: list[Entity] = []

    for m in EMAIL_RE.finditer(text):
        entities.append(Entity("email", m.group(0).lower(), m.span()))
    for m in PHONE_RE.finditer(text):
        entities.append(Entity("phone", re.sub(r"[\s-]", "", m.group(0)), m.span()))
    for m in MONEY_RE.finditer(text):
        entities.append(Entity("money", m.group(0).strip(), m.span()))
    for m in CHANNEL_RE.finditer(text):
        entities.append(Entity("channel", _channel_name(m.group(0)), m.span()))

    for header in (offer.sender, offer.reply_to):
        addr = address_of(header)
        if addr:
            entities.append(Entity("email", addr))

    for link in offer.links:
        entities.append(Entity("url", link))

    domains = {e.value.split("@", 1)[1] for e in entities if e.type == "email"}
    domains |= {d for link in offer.links if (d := domain_of_url(link))}
    entities.extend(Entity("domain", d) for d in sorted(domains))
    return entities
