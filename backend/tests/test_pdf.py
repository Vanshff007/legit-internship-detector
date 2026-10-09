import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parser import ParseError, parse_file, parse_pdf

client = TestClient(app)


def make_pdf(lines: list[str]) -> bytes:
    """Minimal one-page PDF with one text line per entry."""

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    ops = ["BT", "/F1 10 Tf", "14 TL", "40 800 Td"]
    ops += [f"({esc(line)}) Tj T*" for line in lines]
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


GMAIL_PRINT = [
    "Vansh Minhas <student@gmail.com>",
    "SDE I Intern Application - Update",
    "1 message",
    "Swarnakshi Sharma <Swarnakshi.APAC.ind.jobs@outlook.com> 20 August 2026 at 19:29",
    'To: "student@gmail.com" <student@gmail.com>',
    "Hi Vansh,",
    "Thank you for completing the SDE I Intern assessment.",
    "Amazon University Talent Acquisition Team",
    "10/9/26, 10:51 PM Gmail - SDE I Intern Application - Update",
    "https://mail.google.com/mail/u/0/?ik=abc&view=pt 1/1",
]


def test_gmail_print_pdf_uses_sender_not_account_owner():
    offer = parse_file(make_pdf(GMAIL_PRINT))
    assert offer.source_type == "pdf"
    assert offer.sender == "Swarnakshi Sharma <Swarnakshi.APAC.ind.jobs@outlook.com>"
    assert offer.body_text.startswith("SDE I Intern Application - Update\n\nHi Vansh,")
    assert "student@gmail.com" not in offer.body_text  # owner and To: line dropped
    assert "mail.google.com" not in offer.body_text  # print footer dropped
    assert offer.links == []


def test_plain_pdf_keeps_all_text():
    offer = parse_pdf(make_pdf(["Offer letter", "Pay Rs 1999 registration fee."]))
    assert offer.body_text == "Offer letter\nPay Rs 1999 registration fee."
    assert offer.sender is None


def test_pdf_without_text():
    with pytest.raises(ParseError, match="no text"):
        parse_pdf(make_pdf([]))


def test_broken_pdf():
    with pytest.raises(ParseError, match="Could not read"):
        parse_pdf(b"%PDF-1.4\nnot really a pdf")


def test_non_email_file_is_rejected():
    with pytest.raises(ParseError, match="not an email"):
        parse_file(b"just some notes\nwithout any headers")


def test_analyze_gmail_pdf_flags_impersonation_of_sender_only():
    r = client.post(
        "/api/v1/analyze",
        files={"file": ("offer.pdf", make_pdf(GMAIL_PRINT), "application/pdf")},
    )
    assert r.status_code == 200
    body = r.json()
    [flag] = [f for f in body["red_flags"] if f["id"] == "C-IMPERSONATION"]
    assert flag["evidence"] == "swarnakshi.apac.ind.jobs@outlook.com"
    assert body["verdict"] == "likely_scam"


def test_analyze_non_email_upload_is_400():
    r = client.post("/api/v1/analyze", files={"file": ("notes.txt", b"hello there", "text/plain")})
    assert r.status_code == 400
    assert "not an email" in r.json()["detail"]
