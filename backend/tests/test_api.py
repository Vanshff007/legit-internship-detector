from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SCAM_TEXT = (
    "Congratulations! You are selected for Work From Home data entry job at Amazon. "
    "Pay ₹1,999 registration fee within 24 hours. Contact amazon.hr.jobs@gmail.com "
    "or WhatsApp 98765 43210."
)

EML = b"""From: Amazon HR <amazon.hr.jobs@gmail.com>
To: student@example.com
Subject: Offer letter - Data Entry (WFH)
Content-Type: text/plain; charset=utf-8

You are selected without interview. Pay Rs. 1500 kit fee to receive your joining letter.
"""


def test_health():
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_analyze_text_scam():
    r = client.post("/api/v1/analyze", json={"text": SCAM_TEXT})
    assert r.status_code == 200
    body = r.json()
    ids = {f["id"] for f in body["red_flags"]}
    assert {"R-FEE", "R-OFFPLATFORM", "R-URGENCY", "C-IMPERSONATION"} <= ids
    assert "R-FREEMAIL" not in ids  # same address already reported as impersonation
    assert body["verdict"] == "likely_scam" and body["score"] >= 70
    assert body["report_links"] == ["https://cybercrime.gov.in", "tel:1930"]
    assert body["detectors"]["rules"]["status"] == "ok"
    assert body["detectors"]["headers"]["status"] == "skipped"
    assert body["detectors"]["company"]["status"] == "ok"
    assert body["confidence"] == "reduced"  # text model and domain intel not built yet


def test_analyze_text_genuine():
    r = client.post(
        "/api/v1/analyze",
        json={"text": "Your technical interview is scheduled for Monday at 11 AM."},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "looks_safe" and body["red_flags"] == []
    assert body["report_links"] == []


def test_analyze_eml():
    r = client.post("/api/v1/analyze", files={"file": ("offer.eml", EML, "message/rfc822")})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["red_flags"]}
    assert {"R-FEE", "C-IMPERSONATION"} <= ids


def test_eml_too_large():
    big = b"Subject: x\n\n" + b"a" * (2 * 1024 * 1024 + 10)
    r = client.post("/api/v1/analyze", files={"file": ("big.eml", big, "message/rfc822")})
    assert r.status_code == 413


def test_bad_inputs():
    assert client.post("/api/v1/analyze", json={}).status_code == 400
    assert client.post("/api/v1/analyze", json={"text": "  "}).status_code == 400
    both = {"text": "hi", "url": "https://example.com"}
    assert client.post("/api/v1/analyze", json=both).status_code == 400
    r = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert r.status_code == 501


VERIFIED_EML = b"""From: Infosys Campus Hiring <campus.hiring@infosys.com>
To: student@example.com
Subject: Infosys offer - Systems Engineer
Content-Type: text/plain; charset=utf-8

Thank you for attending the interview. Please reply within 24 hours to confirm.
"""


def test_verified_company_lowers_score():
    r = client.post(
        "/api/v1/analyze", files={"file": ("offer.eml", VERIFIED_EML, "message/rfc822")}
    )
    body = r.json()
    assert body["detectors"]["company"]["verified_company"] == "Infosys"
    assert [f["id"] for f in body["red_flags"]] == ["R-URGENCY"]
    assert body["score"] == 0  # 12 urgency points - 20 trust bonus, clamped
    assert body["verdict"] == "looks_safe"


SPOOFED_EML = b"""From: Nexa Technologies HR <nexa.hr2026@gmail.com>
Reply-To: offers@nexa-onboarding.in
To: student@example.com
Authentication-Results: mx.google.com; dkim=none; spf=softfail; dmarc=none
Subject: Internship offer
Content-Type: text/plain; charset=utf-8

You are selected for the internship. Reply to confirm.
"""


def test_eml_header_flags_and_dedupe():
    r = client.post("/api/v1/analyze", files={"file": ("offer.eml", SPOOFED_EML, "message/rfc822")})
    body = r.json()
    ids = {f["id"] for f in body["red_flags"]}
    assert {"H-AUTHFAIL", "H-REPLYTO", "H-DISPLAYNAME"} <= ids
    assert "R-FREEMAIL" not in ids  # same address already reported as H-DISPLAYNAME
    assert body["detectors"]["headers"] == {
        "status": "ok",
        "p_fraud": None,
        "verified_company": None,
        "checks": {"auth": "ok"},
    }
