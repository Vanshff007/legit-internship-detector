"""Core data model shared by the parser, detectors and scorer (see docs/03-architecture.md)."""

from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectorStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"  # ran, but some lookups failed, timed out or are not configured
    SKIPPED = "skipped"  # not applicable to this input (e.g. headers for plain text)
    UNAVAILABLE = "unavailable"  # detector not built or not loaded yet
    TIMEOUT = "timeout"
    ERROR = "error"


class Verdict(StrEnum):
    LOOKS_SAFE = "looks_safe"
    SUSPICIOUS = "suspicious"
    LIKELY_SCAM = "likely_scam"


class RedFlag(BaseModel):
    id: str
    detector: str
    severity: Severity
    message: str
    evidence: str


@dataclass
class Offer:
    source_type: str  # "text" | "eml" | "url"
    body_text: str
    sender: str | None = None
    reply_to: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Entity:
    type: str  # "email" | "domain" | "url" | "phone" | "money" | "channel"
    value: str
    span: tuple[int, int] | None = None  # offsets into Offer.body_text; None if not from body


@dataclass
class DetectorResult:
    status: DetectorStatus
    flags: list[RedFlag] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)
