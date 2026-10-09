"""Download EMSCAD from Kaggle into ml/data/raw/emscad/.

Reads KAGGLE_USERNAME and KAGGLE_KEY from the repository's .env. Run from the ml/ folder:

    .venv/Scripts/python scripts/download_emscad.py
"""

import os
import subprocess
import sys
from pathlib import Path

ML_DIR = Path(__file__).resolve().parents[1]
ENV_FILE = ML_DIR.parent / ".env"
OUT_DIR = ML_DIR / "data" / "raw" / "emscad"
DATASET = "shivamb/real-or-fake-fake-jobposting-prediction"


def load_env(path: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def main() -> int:
    if not ENV_FILE.exists():
        print(f"Missing {ENV_FILE}. Copy .env.example to .env and fill in the Kaggle values.")
        return 1
    load_env(ENV_FILE)
    # New-style Kaggle tokens (KGAT_...) are read from KAGGLE_API_TOKEN.
    if os.environ.get("KAGGLE_KEY", "").startswith("KGAT_"):
        os.environ.setdefault("KAGGLE_API_TOKEN", os.environ["KAGGLE_KEY"])

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    kaggle = Path(sys.executable).with_name("kaggle.exe" if os.name == "nt" else "kaggle")
    cmd = [str(kaggle), "datasets", "download", "-d", DATASET, "-p", str(OUT_DIR), "--unzip"]
    result = subprocess.run(cmd, env={**os.environ, "PYTHONIOENCODING": "utf-8"}, check=False)
    csv = OUT_DIR / "fake_job_postings.csv"
    if not csv.exists():
        print("Download failed: fake_job_postings.csv not found.")
        return result.returncode or 1
    print(f"Saved {csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
