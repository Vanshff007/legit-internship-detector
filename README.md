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
├── README.md
├── CLAUDE.md                 # context for AI-assisted development
├── docs/
│   ├── 01-problem-statement.md
│   ├── 02-requirements.md
│   ├── 03-architecture.md
│   ├── 04-detection-engine.md
│   ├── 05-dataset.md
│   ├── 06-api-spec.md
│   ├── 07-tech-stack.md
│   ├── 08-roadmap.md
│   └── 09-evaluation.md
├── backend/                  # FastAPI service + detection engine
├── ml/                       # notebooks, training scripts, model artifacts
├── web/                      # React web app
└── extension/                # Chrome extension (Manifest V3)
```

## Status

Backend skeleton is running: text and `.eml` input, entity extractor, first 5 rules, company verifier (100 known companies), TF-IDF text model, domain intel (lookalikes, domain age, Safe Browsing), email header analyzer, risk scorer. See [backend/README.md](backend/README.md) and [docs/08-roadmap.md](docs/08-roadmap.md).

## Team

| Name | Role |
|---|---|
| _TBD_ | ML / NLP |
| _TBD_ | Backend + detection engine |
| _TBD_ | Web app + extension |
| _TBD_ | Data collection, testing, report |

