from app.models import DetectorResult, DetectorStatus, RedFlag, Severity, Verdict
from app.scorer import score


def flag(sev: Severity) -> RedFlag:
    return RedFlag(id="X", detector="rules", severity=sev, message="m", evidence="e")


OK = {"rules": DetectorResult(DetectorStatus.OK)}


def test_no_flags_is_safe():
    s = score([], OK)
    assert (s.score, s.verdict, s.confidence) == (0, Verdict.LOOKS_SAFE, "high")


def test_critical_floor():
    s = score([flag(Severity.CRITICAL)], OK, p_text=0.0)
    assert s.score == 70 and s.verdict == Verdict.LIKELY_SCAM


def test_weighted_formula_with_text_model():
    # 0.45*100*0.6 + 0.55*(25+12) = 27 + 20.35 = 47.35
    s = score([flag(Severity.HIGH), flag(Severity.MEDIUM)], OK, p_text=0.6)
    assert s.score == 47 and s.verdict == Verdict.SUSPICIOUS


def test_rule_score_capped_and_trust_bonus():
    flags = [flag(Severity.HIGH)] * 5  # 125 -> capped 100
    assert score(flags, OK).score == 100
    assert score(flags, OK, verified_company=True).score == 80


def test_reduced_confidence_when_detector_missing():
    detectors = {**OK, "domain": DetectorResult(DetectorStatus.TIMEOUT)}
    assert score([], detectors).confidence == "reduced"


def test_skipped_detector_keeps_high_confidence():
    detectors = {**OK, "headers": DetectorResult(DetectorStatus.SKIPPED)}
    assert score([], detectors).confidence == "high"
