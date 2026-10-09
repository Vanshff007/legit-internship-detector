"""Text classifier detector (docs/04-detection-engine.md §1).

Loads the artifact exported by ml/train_baseline.py and returns P(fraud) plus
highlight spans for the words that pushed the score up.
"""

import logging
import os
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

from app.extractor import EMAIL_RE, PHONE_RE
from app.parser import URL_RE

log = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[2] / "ml" / "artifacts" / "text-baseline-v1.joblib"
)
MODEL_PATH_ENV = "LID_TEXT_MODEL"
MAX_HIGHLIGHTS = 8
MIN_HIGHLIGHT_WEIGHT = 0.2
# Features built from masking placeholders cannot be mapped back to the original text.
_PLACEHOLDER_TOKENS = {"url", "email", "phone"}


@dataclass(frozen=True)
class Highlight:
    start: int
    end: int
    weight: float


@dataclass(frozen=True)
class Prediction:
    p_fraud: float
    highlights: list[Highlight]


def mask(text: str) -> str:
    """Match the training data, where EMSCAD replaced these with placeholders."""
    text = EMAIL_RE.sub("[EMAIL]", text)
    text = URL_RE.sub("[URL]", text)
    return PHONE_RE.sub("[PHONE]", text)


class TextModel:
    def __init__(self, artifact: dict[str, Any]):
        self.pipeline = artifact["pipeline"]
        self.version: str = artifact["model_version"]
        self.threshold: float = artifact["threshold"]
        features = dict(self.pipeline.named_steps["features"].transformer_list)
        self._word = features["word"]
        self._word_names = self._word.get_feature_names_out()
        # FeatureUnion puts word features first, so their coefficients lead coef_.
        self._word_coef = self.pipeline.named_steps["clf"].coef_[0][: len(self._word_names)]
        self._token_re = re.compile(self._word.token_pattern)

    def predict(self, text: str) -> Prediction:
        masked = mask(text)
        p = float(self.pipeline.predict_proba([masked])[0, 1])
        # Highlights explain a fraud prediction; below threshold they would only add noise.
        highlights = self._highlights(text, masked) if p >= self.threshold else []
        return Prediction(round(p, 4), highlights)

    def _highlights(self, text: str, masked: str) -> list[Highlight]:
        row = self._word.transform([masked])
        contrib = {
            str(self._word_names[i]): float(v * self._word_coef[i])
            for i, v in zip(row.indices, row.data, strict=True)
        }
        top = sorted(
            ((term, c) for term, c in contrib.items() if c > 0 and _highlightable(term)),
            key=lambda tc: tc[1],
            reverse=True,
        )
        if not top:
            return []
        max_c = top[0][1]
        top = [(t, c) for t, c in top if c / max_c >= MIN_HIGHLIGHT_WEIGHT]

        tokens = [(m.group(0).lower(), m.start(), m.end()) for m in self._token_re.finditer(text)]
        out: list[Highlight] = []
        taken: set[int] = set()  # token indices already highlighted
        for term, c in top:
            words = term.split()
            n = len(words)
            for i in range(len(tokens) - n + 1):
                if [t[0] for t in tokens[i : i + n]] == words and not taken & set(range(i, i + n)):
                    out.append(Highlight(tokens[i][1], tokens[i + n - 1][2], round(c / max_c, 2)))
                    taken |= set(range(i, i + n))
            if len(out) >= MAX_HIGHLIGHTS:
                break
        return sorted(out[:MAX_HIGHLIGHTS], key=lambda h: h.start)


def _highlightable(term: str) -> bool:
    words = term.split()
    if set(words) & _PLACEHOLDER_TOKENS:
        return False
    return not all(w in ENGLISH_STOP_WORDS or w.isdigit() for w in words)


@cache
def _load(path: str) -> TextModel | None:
    if not Path(path).exists():
        log.warning("text model not found at %s; text_model detector unavailable", path)
        return None
    try:
        return TextModel(joblib.load(path))
    except Exception:
        log.exception("failed to load text model from %s", path)
        return None


def get_model() -> TextModel | None:
    return _load(os.environ.get(MODEL_PATH_ENV, str(DEFAULT_MODEL_PATH)))
