# Legit Internship Detector

> Fake job and internship offer detector for students and freshers in India. Paste a job offer, internship email, or link — get a risk score and a plain-language list of red flags before you pay, share documents, or reply.

## Problem

Students and freshers in India lose money and personal data to fake job and internship offers every placement season. Common patterns: "registration/training fee", offers without an interview, HR contacting only via WhatsApp/Telegram, Gmail-based "HR" addresses, newly registered lookalike domains, and unrealistic stipends for "simple online tasks". Existing tools (spam filters, generic URL scanners) do not understand the job-scam context.

## Solution

Legit Internship Detector analyses an offer from several angles and combines them into one explainable risk score:

| Signal | What it checks |
|---|---|
| Text model | NLP classifier trained on real vs. fraudulent postings |
| Rule engine | Fee demands, urgency, off-platform contact, salary vs. role mismatch |
| Domain intel | Domain age (WHOIS/RDAP), lookalike of known companies, Safe Browsing |
| Email headers | SPF / DKIM / DMARC results, reply-to mismatch, free-mail sender |
| Company check | Company exists in public registries / known-company list |

Output: **risk score (0–100)**, verdict (Safe / Suspicious / Likely Scam), and the exact red flags that triggered it.

## Interfaces

- **Web app** — paste text, upload `.eml`, or enter a URL.
- **Browser extension** — one-click check on job portals and webmail.
- **REST API** — used by both clients.

## Repository layout

```
legit-internship-detector/
├── backend/                  # FastAPI service + detection engine
├── ml/                       # data preparation, training scripts
├── web/                      # React web app (Vite + Tailwind)
└── extension/                # Chrome extension, Manifest V3
```

## Quick start

Requires Python 3.11.

```bash
# 1. Train the text model (needs Kaggle credentials in .env, see .env.example)
cd ml
py -3.11 -m venv .venv
.venv/Scripts/python -m pip install -e .
.venv/Scripts/python scripts/download_emscad.py
.venv/Scripts/python scripts/prepare_emscad.py
.venv/Scripts/python train_baseline.py

# 2. Run the API
cd ../backend
py -3.11 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs. The API also runs without step 1; the text model then reports `unavailable`.

```bash
# 3. Build the web app (needs Node 20+); the API then serves it at http://127.0.0.1:8000/
cd ../web
npm install
npm run build
```

For web development with live reload, run `npm run dev` in `web/` while the API runs; open http://localhost:5173.

```bash
# 4. Build the Chrome extension
cd ../extension
npm install
npm run build
```

In Chrome or Edge, open `chrome://extensions`, turn on Developer mode, click "Load unpacked" and pick the `extension/` folder. Select offer text on any page, right-click and choose "Check with Legit Internship Detector", or open the extension's popup to check the selected text or the whole page. The extension talks to `http://127.0.0.1:8000` by default; change it under Settings in the popup.

### Run with Docker

```bash
gh release download model-text-baseline-v1 --pattern "*.joblib" --dir ml/artifacts
docker build -t legit-internship-detector .
docker run -p 8000:8000 legit-internship-detector
```

Open http://127.0.0.1:8000/. Every push to `main` also publishes the image to `ghcr.io/vanshff007/legit-internship-detector` (see `.github/workflows/deploy.yml`).

Optional settings in `.env`: `SAFE_BROWSING_API_KEY` (link checks), `REDIS_URL` (shared cache).

Run tests with `.venv/Scripts/python -m pytest` in `backend/`.

## Status

Working end to end: text, `.eml` and URL input; entity extractor; first 5 rules; company verifier (100 known companies); TF-IDF text model with highlighted phrases; domain intel (lookalikes, domain age, Safe Browsing); email header analyzer; risk scorer; feedback on wrong results; per-IP rate limits; web app; Chrome extension. Next: India dataset, transformer model, admin trends page.

## Team

| Name | Role |
|---|---|
| _TBD_ | ML / NLP |
| _TBD_ | Backend + detection engine |
| _TBD_ | Web app + extension |
| _TBD_ | Data collection, testing, report |

