"""Normalise raw input (text, .eml or PDF) into an Offer."""

import io
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from pypdf import PdfReader

from app.models import Offer

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")

MAX_PDF_PAGES = 20
# Gmail's "Print" / "Save as PDF" layout:
#   <account owner> <owner@gmail.com>     (the person who printed it, not the sender)
#   <subject>
#   1 message
#   <Sender Name> <sender@domain> <date>
#   To: ...
#   <body>
# with a footer on every page: "<date>, <time> Gmail - <subject>" and the print URL.
_GMAIL_COUNT_RE = re.compile(r"^\d+ messages?$")
_ADDR_LINE_RE = re.compile(r"^(.*?<[^<>@\s]+@[^<>\s]+>)")
_RECIPIENT_RE = re.compile(r"^(To|Cc|Bcc):", re.IGNORECASE)
_PRINT_FOOTER_RE = re.compile(
    r"^\d{1,2}/\d{1,2}/\d{2,4},? \d{1,2}:\d{2}.*Gmail - |^https://mail\.google\.com/"
)
# A real email has at least one of these headers; a file with none is not an email.
_EMAIL_HEADERS = ("from", "subject", "date", "received", "message-id", "to")


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


def parse_file(raw: bytes) -> Offer:
    """An uploaded file: PDF (by its signature) or .eml."""
    if raw.lstrip()[:5] == b"%PDF-":
        return parse_pdf(raw)
    return parse_eml(raw)


def parse_eml(raw: bytes) -> Offer:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # malformed MIME
        raise ParseError(f"Could not parse .eml file: {exc}") from exc

    if not any(msg.get(h) for h in _EMAIL_HEADERS):
        raise ParseError(
            "This file is not an email. Upload an .eml file or a PDF of the email, "
            "or paste the text instead."
        )

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


def _pdf_text(raw: bytes) -> str:
    try:
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            raise ParseError("This PDF is password-protected. Paste the text instead.")
        pages = [page.extract_text() or "" for page in reader.pages[:MAX_PDF_PAGES]]
    except ParseError:
        raise
    except Exception as exc:  # pypdf raises many types for broken files
        raise ParseError("Could not read the PDF. Paste the text instead.") from exc
    # NFKC turns ligatures such as "ﬀ" back into plain letters.
    return unicodedata.normalize("NFKC", "\n".join(pages))


def parse_pdf(raw: bytes) -> Offer:
    """A PDF of an offer letter or an email. Gmail's "Save as PDF" layout is recognised,
    so the sender (not the account owner who printed it) is treated as the sender."""
    lines = [
        line
        for raw_line in _pdf_text(raw).splitlines()
        if (line := raw_line.strip()) and not _PRINT_FOOTER_RE.search(line)
    ]
    if not lines:
        raise ParseError("The PDF has no text (it may be a scanned image). Paste the text instead.")

    sender: str | None = None
    if len(lines) >= 4 and _ADDR_LINE_RE.match(lines[0]) and _GMAIL_COUNT_RE.match(lines[2]):
        subject, rest = lines[1], lines[3:]
        if m := _ADDR_LINE_RE.match(rest[0]):
            sender = m.group(1)
            rest = rest[1:]
        # Recipient lines list the user's own address; they say nothing about the sender.
        rest = [line for line in rest if not _RECIPIENT_RE.match(line)]
        body = "\n".join([subject, "", *rest])
    else:
        body = "\n".join(lines)

    return Offer(source_type="pdf", body_text=body, sender=sender, links=extract_links(body))


def address_of(header_value: str | None) -> str | None:
    """'Infosys HR <hr@gmail.com>' -> 'hr@gmail.com'."""
    if not header_value:
        return None
    addr = parseaddr(header_value)[1].lower()
    return addr or None
