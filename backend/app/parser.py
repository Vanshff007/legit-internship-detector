"""Normalise raw input (text or .eml) into an Offer."""

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from app.models import Offer

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")


class ParseError(ValueError):
    pass


def extract_links(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for match in URL_RE.finditer(text):
        seen.setdefault(match.group(0).rstrip(".,;:!?"), None)
    return list(seen)


def parse_text(text: str) -> Offer:
    body = text.strip()
    if not body:
        raise ParseError("Text is empty.")
    return Offer(source_type="text", body_text=body, links=extract_links(body))


def _html_to_text(html: str) -> str:
    # Only strips tags for analysis; fetched/embedded HTML is never rendered (NFR-5).
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>|</p>", "\n", text)
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", text))


def parse_eml(raw: bytes) -> Offer:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # malformed MIME
        raise ParseError(f"Could not parse .eml file: {exc}") from exc

    part = msg.get_body(preferencelist=("plain", "html"))
    body = ""
    html_links: list[str] = []
    if part is not None:
        content = part.get_content()
        if part.get_content_type() == "text/html":
            html_links = re.findall(r"""href=["']([^"']+)["']""", content, re.IGNORECASE)
            content = _html_to_text(content)
        body = content.strip()

    subject = str(msg.get("Subject", "")).strip()
    if subject:
        body = f"{subject}\n\n{body}" if body else subject
    if not body:
        raise ParseError("Email has no readable text body.")

    # Lower-case names; for repeated headers keep the first (topmost) one, which was
    # added by the receiving server. Lower copies can be forged by the sender.
    headers: dict[str, str] = {}
    for name, value in msg.items():
        headers.setdefault(name.lower(), str(value))
    links = list(dict.fromkeys(extract_links(body) + [h for h in html_links if "://" in h]))
    return Offer(
        source_type="eml",
        body_text=body,
        sender=str(msg["From"]) if msg["From"] else None,
        reply_to=str(msg["Reply-To"]) if msg["Reply-To"] else None,
        headers=headers,
        links=links,
    )


def address_of(header_value: str | None) -> str | None:
    """'Infosys HR <hr@gmail.com>' -> 'hr@gmail.com'."""
    if not header_value:
        return None
    addr = parseaddr(header_value)[1].lower()
    return addr or None
