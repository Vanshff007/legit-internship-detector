"""TF-IDF + Logistic Regression baseline (docs/04-detection-engine.md §1).

Trains on data/splits/emscad/train.csv, picks the decision threshold that maximises
fraud-class F1 on val, and reports final metrics on test (docs/09-evaluation.md).

    .venv/Scripts/python train_baseline.py
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.pipeline import FeatureUnion, Pipeline

ML_DIR = Path(__file__).resolve().parent
SPLITS = ML_DIR / "data" / "splits" / "emscad"
ARTIFACTS = ML_DIR / "artifacts"
MODEL_VERSION = "text-baseline-v1"
SEED = 42


def load(name: str) -> tuple[pd.Series, np.ndarray]:
    df = pd.read_csv(SPLITS / f"{name}.csv", keep_default_na=False)
    return df["text"], (df["label"] == "scam").to_numpy(dtype=int)


def build_pipeline(c: float = 4.0) -> Pipeline:
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    ngram_range=(1, 2), min_df=2, max_features=100_000, sublinear_tf=True
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=3,
                    max_features=150_000,
                    sublinear_tf=True,
                ),
            ),
        ]
    )
    clf = LogisticRegression(
        C=c, class_weight="balanced", max_iter=2000, solver="liblinear", random_state=SEED
    )
    return Pipeline([("features", features), ("clf", clf)])


def best_threshold(y: np.ndarray, p: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(y, p)
    f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-12)
    return float(thresholds[int(np.argmax(f1[:-1]))])


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict[str, object]:
    pred = (p >= threshold).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", pos_label=1, zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
        "pr_auc": round(float(average_precision_score(y, p)), 4),
        "brier": round(float(brier_score_loss(y, p)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def top_terms(pipe: Pipeline, n: int = 25) -> dict[str, list[str]]:
    names = pipe.named_steps["features"].get_feature_names_out()
    coef = pipe.named_steps["clf"].coef_[0]
    order = np.argsort(coef)
    return {
        "scam": [str(names[i]) for i in order[::-1][:n]],
        "genuine": [str(names[i]) for i in order[:n]],
    }


def main() -> None:
    x_train, y_train = load("train")
    x_val, y_val = load("val")
    x_test, y_test = load("test")

    # Small C sweep, selected by val PR-AUC.
    best = None
    for c in (1.0, 4.0, 16.0):
        pipe = build_pipeline(c).fit(x_train, y_train)
        pr_auc = average_precision_score(y_val, pipe.predict_proba(x_val)[:, 1])
        print(f"C={c:<5} val PR-AUC {pr_auc:.4f}")
        if best is None or pr_auc > best[0]:
            best = (pr_auc, c, pipe)
    assert best is not None
    _, c, pipe = best

    p_val = pipe.predict_proba(x_val)[:, 1]
    threshold = best_threshold(y_val, p_val)
    p_test = pipe.predict_proba(x_test)[:, 1]

    report = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": "EMSCAD (near-duplicate-grouped 70/15/15 split, seed 42)",
        "params": {"C": c, "threshold": round(threshold, 4)},
        "val": metrics(y_val, p_val, threshold),
        "test": metrics(y_test, p_test, threshold),
        "top_terms": top_terms(pipe),
    }

    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump(
        {"pipeline": pipe, "threshold": threshold, "model_version": MODEL_VERSION},
        ARTIFACTS / f"{MODEL_VERSION}.joblib",
        compress=3,
    )
    (ARTIFACTS / f"{MODEL_VERSION}.metrics.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    print(f"\nChosen C={c}, threshold={threshold:.3f}")
    for split in ("val", "test"):
        m = report[split]
        print(
            f"{split:4s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
            f"ROC-AUC={m['roc_auc']:.3f} PR-AUC={m['pr_auc']:.3f} {m['confusion_matrix']}"
        )
    print("\nTop scam terms:", ", ".join(report["top_terms"]["scam"][:15]))


if __name__ == "__main__":
    main()
