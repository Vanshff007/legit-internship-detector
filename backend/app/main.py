"""FastAPI app (docs/06-api-spec.md)."""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ValidationError

from app import domain_intel, engine
from app.config import load_env_file
from app.models import DetectorStatus, RedFlag, Verdict
from app.parser import ParseError, parse_eml, parse_text
from app.text_model import get_model

MAX_EML_BYTES = 2 * 1024 * 1024

load_env_file()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Loading takes seconds; do it before serving so the first request does not hit
    # the detector timeout.
    get_model()
    await domain_intel.warm_up()
    yield


app = FastAPI(title="Legit Internship Detector API", version="0.1.0", lifespan=lifespan)


class AnalyzeRequest(BaseModel):
    text: str | None = None
    url: str | None = None
    store_for_research: bool = False


class DetectorOut(BaseModel):
    status: DetectorStatus
    p_fraud: float | None = None
    verified_company: str | None = None
    checks: dict[str, str] | None = None


class HighlightOut(BaseModel):
    start: int
    end: int
    weight: float


class AnalyzeResponse(BaseModel):
    analysis_id: str
    score: int
    verdict: Verdict
    confidence: str
    red_flags: list[RedFlag]
    highlights: list[HighlightOut]
    detectors: dict[str, DetectorOut]
    report_links: list[str]
    model_version: str | None


async def _offer_from_multipart(request: Request):
    form = await request.form()
    upload = form.get("file")
    if upload is None or isinstance(upload, str):
        raise HTTPException(400, "Multipart request must include a 'file' field.")
    if form.get("text") or form.get("url"):
        raise HTTPException(400, "Send exactly one of text, url or file.")
    raw = await upload.read(MAX_EML_BYTES + 1)
    if len(raw) > MAX_EML_BYTES:
        raise HTTPException(413, "File too large (max 2 MB).")
    return parse_eml(raw)


async def _offer_from_json(request: Request):
    try:
        body = AnalyzeRequest.model_validate(await request.json())
    except (ValidationError, ValueError) as exc:
        raise HTTPException(400, "Invalid JSON body.") from exc
    given = [x for x in (body.text, body.url) if x is not None]
    if len(given) != 1:
        raise HTTPException(400, "Send exactly one of text, url or file.")
    if body.url is not None:
        raise HTTPException(501, "URL analysis is not implemented yet.")
    # store_for_research is accepted but nothing is persisted until the DB exists (NFR-4).
    return parse_text(body.text or "")


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(request: Request) -> AnalyzeResponse:
    content_type = request.headers.get("content-type", "")
    try:
        if content_type.startswith("multipart/form-data"):
            offer = await _offer_from_multipart(request)
        else:
            offer = await _offer_from_json(request)
    except ParseError as exc:
        raise HTTPException(400, str(exc)) from exc

    result = await engine.analyze(offer)
    return AnalyzeResponse(
        analysis_id=result.analysis_id,
        score=result.score,
        verdict=result.verdict,
        confidence=result.confidence,
        red_flags=result.red_flags,
        highlights=[HighlightOut(**asdict(h)) for h in result.highlights],
        detectors={
            name: DetectorOut(
                status=r.status,
                p_fraud=r.extra.get("p_fraud"),  # type: ignore[arg-type]
                verified_company=r.extra.get("verified_company"),  # type: ignore[arg-type]
                checks=r.extra.get("checks"),  # type: ignore[arg-type]
            )
            for name, r in result.detectors.items()
        },
        report_links=result.report_links,
        model_version=result.model_version,
    )


@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model_version": model.version if (model := get_model()) else None,
        "safe_browsing": "configured"
        if os.environ.get(domain_intel.SAFE_BROWSING_KEY_ENV)
        else "not_configured",
        "detectors": {
            "text_model": "ok" if model else "unavailable",
            "rules": "ok",
            "domain": "ok",
            "headers": "ok",
            "company": "ok",
        },
    }
