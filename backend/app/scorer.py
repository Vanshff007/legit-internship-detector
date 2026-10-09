"""Risk scorer (docs/04-detection-engine.md, "Risk scoring")."""

from dataclasses import dataclass

from app.models import DetectorResult, DetectorStatus, RedFlag, Severity, Verdict

SEVERITY_POINTS = {Severity.LOW: 5, Severity.MEDIUM: 12, Severity.HIGH: 25, Severity.CRITICAL: 40}
TEXT_WEIGHT = 0.45
RULE_WEIGHT = 0.55
TRUST_BONUS = 20
CRITICAL_FLOOR = 70

# Statuses that mean a detector should have run but did not.
_DEGRADED = {
    DetectorStatus.PARTIAL,
    DetectorStatus.UNAVAILABLE,
    DetectorStatus.TIMEOUT,
    DetectorStatus.ERROR,
}


@dataclass
class Score:
    score: int
    verdict: Verdict
    confidence: str  # "high" | "reduced"


def verdict_for(score: int) -> Verdict:
    if score >= 70:
        return Verdict.LIKELY_SCAM
    if score >= 35:
        return Verdict.SUSPICIOUS
    return Verdict.LOOKS_SAFE


def score(
    flags: list[RedFlag],
    detectors: dict[str, DetectorResult],
    p_text: float | None = None,
    verified_company: bool = False,
) -> Score:
    rule_score = min(100, sum(SEVERITY_POINTS[f.severity] for f in flags))
    trust_bonus = TRUST_BONUS if verified_company else 0

    if p_text is None:
        # No text model yet: rule score carries the full weight.
        raw = rule_score - trust_bonus
    else:
        raw = TEXT_WEIGHT * (100 * p_text) + RULE_WEIGHT * rule_score - trust_bonus

    value = max(0.0, min(100.0, raw))
    if any(f.severity == Severity.CRITICAL for f in flags):
        value = max(value, CRITICAL_FLOOR)

    final = round(value)
    degraded = any(r.status in _DEGRADED for r in detectors.values())
    return Score(final, verdict_for(final), "reduced" if degraded else "high")
