"""Turn raw EMSCAD into processed/emscad.csv and stratified, leak-free splits.

Follows docs/05-dataset.md: columns id,text,label,scam_type,source; 70/15/15 split
stratified by label; near-duplicate postings (MinHash) are kept in the same split.

    .venv/Scripts/python scripts/prepare_emscad.py
"""

import re
from pathlib import Path

import pandas as pd
from datasketch import MinHash, MinHashLSH
from sklearn.model_selection import train_test_split

ML_DIR = Path(__file__).resolve().parents[1]
RAW = ML_DIR / "data" / "raw" / "emscad" / "fake_job_postings.csv"
PROCESSED = ML_DIR / "data" / "processed" / "emscad.csv"
SPLITS = ML_DIR / "data" / "splits" / "emscad"

TEXT_FIELDS = ["title", "company_profile", "description", "requirements", "benefits"]
SEED = 42
NEAR_DUP_THRESHOLD = 0.8
NUM_PERM = 128
SHINGLE = 5

_URL_RE = re.compile(r"#URL_[0-9a-f]+#")
_EMAIL_RE = re.compile(r"#EMAIL_[0-9a-f]+#")
_PHONE_RE = re.compile(r"#PHONE_[0-9a-f]+#")


def build_text(row: pd.Series) -> str:
    parts = [str(row[f]).strip() for f in TEXT_FIELDS if pd.notna(row[f]) and str(row[f]).strip()]
    text = "\n\n".join(parts)
    # EMSCAD already masks these with hashed tokens; normalise to plain placeholders.
    text = _URL_RE.sub("[URL]", text)
    text = _EMAIL_RE.sub("[EMAIL]", text)
    return _PHONE_RE.sub("[PHONE]", text)


def minhash(text: str) -> MinHash:
    words = re.findall(r"\w+", text.lower())
    m = MinHash(num_perm=NUM_PERM, seed=SEED)
    for i in range(max(1, len(words) - SHINGLE + 1)):
        m.update(" ".join(words[i : i + SHINGLE]).encode("utf-8"))
    return m


def near_duplicate_groups(texts: list[str]) -> list[int]:
    """Union-find over LSH neighbours; returns a group id per text."""
    parent = list(range(len(texts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    lsh = MinHashLSH(threshold=NEAR_DUP_THRESHOLD, num_perm=NUM_PERM)
    for i, text in enumerate(texts):
        m = minhash(text)
        for j in lsh.query(m):
            parent[find(i)] = find(int(j))
        lsh.insert(str(i), m)
    return [find(i) for i in range(len(texts))]


def main() -> None:
    raw = pd.read_csv(RAW)
    df = pd.DataFrame(
        {
            "id": "emscad_" + raw["job_id"].astype(str),
            "text": raw.apply(build_text, axis=1),
            "label": raw["fraudulent"].map({0: "genuine", 1: "scam"}),
            "scam_type": "",
            "source": "emscad",
        }
    )
    df = df[df["text"].str.len() > 0].reset_index(drop=True)

    df["group"] = near_duplicate_groups(df["text"].tolist())
    PROCESSED.parent.mkdir(parents=True, exist_ok=True)
    df.drop(columns="group").to_csv(PROCESSED, index=False)

    # Split whole groups; a group counts as scam if any member is scam.
    is_scam = df["label"] == "scam"
    groups = is_scam.groupby(df["group"]).any().map({True: "scam", False: "genuine"})
    g_train, g_rest = train_test_split(
        groups.index, test_size=0.30, stratify=groups.values, random_state=SEED
    )
    g_val, g_test = train_test_split(
        g_rest, test_size=0.50, stratify=groups.loc[g_rest].values, random_state=SEED
    )

    SPLITS.mkdir(parents=True, exist_ok=True)
    for name, ids in [("train", g_train), ("val", g_val), ("test", g_test)]:
        part = df[df["group"].isin(set(ids))].drop(columns="group")
        part.to_csv(SPLITS / f"{name}.csv", index=False)
        n_scam = (part["label"] == "scam").sum()
        print(f"{name:5s} {len(part):6d} rows, {n_scam:4d} scam ({n_scam / len(part):.1%})")

    n_groups, n_rows = df["group"].nunique(), len(df)
    print(f"{n_rows} rows in {n_groups} near-duplicate groups ({n_rows - n_groups} rows merged)")


if __name__ == "__main__":
    main()
