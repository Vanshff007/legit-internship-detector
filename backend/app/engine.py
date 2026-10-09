"""Runs all detectors in parallel and builds the analysis (docs/03-architecture.md)."""

import asyncio
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from app import domain_intel, headers
from app.company import verify
from app.extractor import extract
from app.models import DetectorResult, DetectorStatus, Entity, Offer, RedFlag, Verdict
from app.rules import run_rules
from app.scorer import score
from app.text_model import Highlight, get_model

log = logging.getLogger(__name__)

DETECTOR_TIMEOUT_S = 2.0
# Domain intel does network lookups with their own shorter timeouts; see domain_intel.py.
DETECTOR_TIMEOUTS_S = {"domain": 2.5}
REPORT_LINKS = ["https://cybercrime.gov.in", "tel:1930"]

Detector = Callable[[Offer, list[Entity]], Awaitable[DetectorResult]]


async def rules_detector(offer: Offer, entities: list[Entity]) -> DetectorResult:
    return DetectorResult(DetectorStatus.OK, run_rules(offer, entities))


async def text_model_detector(offer: Offer, entities: list[Entity]) -> DetectorResult:
    model = get_model()
    if model is None:
        return DetectorResult(DetectorStatus.UNAVAILABLE)
    pred = await asyncio.to_thread(model.predict, offer.body_text)
    return DetectorResult(
        DetectorStatus.OK,
        extra={
            "p_fraud": pred.p_fraud,
            "model_version": model.version,
            "highlights": pred.highlights,
        },
    )


async def domain_detector(offer: Offer, entities: list[Entity]) -> DetectorResult:
    return await domain_intel.analyze(offer, entities)


async def headers_detector(offer: Offer, entities: list[Entity]) -> DetectorResult:
    return headers.analyze(offer)


async def company_detector(offer: Offer, entities: list[Entity]) -> DetectorResult:
    return verify(offer, entities)


DETECTORS: dict[str, Detector] = {
    "text_model": text_model_detector,
    "rules": rules_detector,
    "domain": domain_detector,
    "headers": headers_detector,
    "company": company_detector,
}


async def _run_one(name: str, detector: Detector, offer: Offer, entities: list[Entity]):
    try:
        timeout = DETECTOR_TIMEOUTS_S.get(name, DETECTOR_TIMEOUT_S)
        return await asyncio.wait_for(detector(offer, entities), timeout)
    except TimeoutError:
        log.warning("detector %s timed out", name)
        return DetectorResult(DetectorStatus.TIMEOUT)
    except Exception:
        # A failed detector lowers confidence; it never fails the request.
        log.exception("detector %s failed", name)
        return DetectorResult(DetectorStatus.ERROR)


def _dedupe(flags: list[RedFlag]) -> list[RedFlag]:
    """Drop a general flag when a more specific one already reports the same thing,
    so the user does not see the same problem twice:
    - D-LOOKALIKE for a domain already reported as C-IMPERSONATION;
    - R-FREEMAIL when every address it lists is already in C-IMPERSONATION or
      H-DISPLAYNAME."""
    impersonation = " ".join(f.evidence for f in flags if f.id == "C-IMPERSONATION")
    specific_freemail = " ".join(
        f.evidence for f in flags if f.id in ("C-IMPERSONATION", "H-DISPLAYNAME")
    )

    def redundant(f: RedFlag) -> bool:
        if f.id == "D-LOOKALIKE":
            return f.evidence.split(" ", 1)[0] in impersonation
        if f.id == "R-FREEMAIL":
            return all(a in specific_freemail for a in f.evidence.split(", "))
        return False

    return [f for f in flags if not redundant(f)]


@dataclass
class Analysis:
    analysis_id: str
    score: int
    verdict: Verdict
    confidence: str
    red_flags: list[RedFlag]
    highlights: list[Highlight]
    detectors: dict[str, DetectorResult]
    report_links: list[str]
    model_version: str | None


async def analyze(offer: Offer) -> Analysis:
    entities = extract(offer)
    names = list(DETECTORS)
    results = await asyncio.gather(*(_run_one(n, DETECTORS[n], offer, entities) for n in names))
    detectors = dict(zip(names, results, strict=True))

    flags = _dedupe([f for r in results for f in r.flags])
    p_text = detectors["text_model"].extra.get("p_fraud")
    verified = bool(detectors["company"].extra.get("verified"))
    s = score(flags, detectors, p_text if isinstance(p_text, float) else None, verified)

    return Analysis(
        analysis_id=f"an_{secrets.token_hex(3)}",
        score=s.score,
        verdict=s.verdict,
        confidence=s.confidence,
        red_flags=flags,
        highlights=detectors["text_model"].extra.get("highlights", []),  # type: ignore[arg-type]
        detectors=detectors,
        report_links=REPORT_LINKS if s.verdict == Verdict.LIKELY_SCAM else [],
        model_version=detectors["text_model"].extra.get("model_version"),  # type: ignore[arg-type]
    )
