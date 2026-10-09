import joblib
import pytest
from fastapi.testclient import TestClient
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from app.main import app
from app.text_model import DEFAULT_MODEL_PATH, MODEL_PATH_ENV, get_model, mask

SCAM = [
    "earn money from home data entry no experience pay registration fee",
    "work from home earn daily typing job registration fee required",
    "data entry job earn weekly send fee to confirm",
]
GENUINE = [
    "software engineer role interview with our engineering team in bangalore",
    "graduate trainee position technical interview and hr round at campus",
    "backend developer python experience interview process three rounds",
]


@pytest.fixture
def toy_model(tmp_path, monkeypatch):
    # Same structure as ml/train_baseline.py, trained on a few sentences.
    pipe = Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        ("word", TfidfVectorizer(ngram_range=(1, 2))),
                        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 4))),
                    ]
                ),
            ),
            ("clf", LogisticRegression(C=10)),
        ]
    ).fit(SCAM + GENUINE, [1, 1, 1, 0, 0, 0])
    path = tmp_path / "toy.joblib"
    joblib.dump({"pipeline": pipe, "threshold": 0.5, "model_version": "toy-v0"}, path)
    monkeypatch.setenv(MODEL_PATH_ENV, str(path))
    return get_model()


def test_mask_matches_training_placeholders():
    text = "Mail hr@gmail.com, visit https://x.in/a or call +91 98765 43210"
    assert mask(text) == "Mail [EMAIL], visit [URL] or call [PHONE]"


def test_missing_artifact_means_unavailable():
    assert get_model() is None
    body = TestClient(app).post("/api/v1/analyze", json={"text": "hello there"}).json()
    assert body["detectors"]["text_model"]["status"] == "unavailable"
    assert body["model_version"] is None and body["highlights"] == []


def test_prediction_and_highlights(toy_model):
    text = "Earn money from home! Pay the registration fee today."
    pred = toy_model.predict(text)
    assert pred.p_fraud > 0.5
    genuine = toy_model.predict("Technical interview with the engineering team")
    assert genuine.p_fraud < 0.5 and genuine.highlights == []  # below threshold

    assert pred.highlights and pred.highlights[0].weight <= 1
    assert max(h.weight for h in pred.highlights) == 1
    spans = [text[h.start : h.end].lower() for h in pred.highlights]
    assert any("earn" in s or "fee" in s or "registration" in s for s in spans)
    assert "the" not in spans  # stop words are never highlighted


def test_api_uses_model(toy_model):
    client = TestClient(app)
    body = client.post(
        "/api/v1/analyze", json={"text": "Earn money from home, data entry job."}
    ).json()
    tm = body["detectors"]["text_model"]
    assert tm["status"] == "ok" and tm["p_fraud"] > 0.5
    assert body["model_version"] == "toy-v0"
    assert body["highlights"]

    health = client.get("/api/v1/health").json()
    assert health["detectors"]["text_model"] == "ok" and health["model_version"] == "toy-v0"


@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="real artifact not built")
def test_real_baseline_smoke(monkeypatch):
    monkeypatch.setenv(MODEL_PATH_ENV, str(DEFAULT_MODEL_PATH))
    model = get_model()
    assert model is not None and model.version == "text-baseline-v1"
    scam = model.predict(
        "Work from home data entry. Earn $5000 weekly, no experience needed. "
        "Apply using the link below."
    )
    genuine = model.predict(
        "We are looking for a Senior Backend Engineer to join our platform team. "
        "You will design APIs in Python and Go. Requirements: 5+ years of experience. "
        "Benefits: health insurance, 401k, paid time off."
    )
    assert scam.p_fraud > genuine.p_fraud
