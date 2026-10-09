from fastapi.testclient import TestClient

from app import feedback, ratelimit
from app.main import app

client = TestClient(app)


def analyze(text: str) -> dict:
    r = client.post("/api/v1/analyze", json={"text": text})
    assert r.status_code == 200
    return r.json()


def test_analyze_returns_analyzed_text_for_highlights():
    body = analyze("   Pay Rs 1999 registration fee today.  ")
    assert body["analyzed_text"] == "Pay Rs 1999 registration fee today."


def test_feedback_is_saved_with_verdict_and_masked_comment():
    result = analyze("Pay Rs 1999 registration fee. Contact hr.jobs@gmail.com")
    r = client.post(
        "/api/v1/feedback",
        json={
            "analysis_id": result["analysis_id"],
            "label": "genuine",
            "comment": "Real offer, HR was me@college.edu, call 98765 43210",
        },
    )
    assert r.status_code == 204
    [row] = feedback.all_rows()
    assert row["analysis_id"] == result["analysis_id"]
    assert row["label"] == "genuine"
    assert row["verdict"] == result["verdict"] and row["score"] == result["score"]
    assert row["comment"] == "Real offer, HR was [EMAIL], call [PHONE]"


def test_feedback_for_unknown_analysis_is_still_saved():
    r = client.post("/api/v1/feedback", json={"analysis_id": "an_abcdef", "label": "scam"})
    assert r.status_code == 204
    [row] = feedback.all_rows()
    assert row["verdict"] is None and row["comment"] is None


def test_feedback_validation():
    bad = [
        {"analysis_id": "nope", "label": "scam"},
        {"analysis_id": "an_abcdef", "label": "maybe"},
        {"analysis_id": "an_abcdef", "label": "scam", "comment": "x" * 1001},
    ]
    for body in bad:
        assert client.post("/api/v1/feedback", json=body).status_code == 422
    assert feedback.all_rows() == []


def test_analyze_rate_limit():
    for _ in range(ratelimit.analyze_limit.limit):
        assert client.post("/api/v1/analyze", json={"text": "hello"}).status_code == 200
    r = client.post("/api/v1/analyze", json={"text": "hello"})
    assert r.status_code == 429 and "retry-after" in r.headers


def test_rate_limiter_window():
    limiter = ratelimit.RateLimiter(2, window_s=0.0)
    for _ in range(5):
        limiter.check("1.2.3.4")  # zero window: old hits always expire
