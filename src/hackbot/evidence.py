"""Immutable evidence and fact records, separate from raw artifact bytes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import math
from types import MappingProxyType
from typing import Mapping


class EvidenceType(StrEnum):
    RECON_RECORD = "RECON_RECORD"
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    JS_ASSET = "JS_ASSET"
    JS_SNIPPET = "JS_SNIPPET"
    SOURCE_MAP = "SOURCE_MAP"
    BROWSER_EVENT = "BROWSER_EVENT"
    DOM_PROOF = "DOM_PROOF"
    SCREENSHOT = "SCREENSHOT"
    GRAPHQL_OPERATION = "GRAPHQL_OPERATION"
    AUTH_OBSERVATION = "AUTH_OBSERVATION"
    ROLE_OBSERVATION = "ROLE_OBSERVATION"
    OBJECT_OBSERVATION = "OBJECT_OBSERVATION"
    RESEARCH_REFERENCE = "RESEARCH_REFERENCE"
    MANUAL_NOTE = "MANUAL_NOTE"
    EXPERIMENT_RESULT = "EXPERIMENT_RESULT"


class Sensitivity(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"


class RedactionStatus(StrEnum):
    ORIGINAL = "ORIGINAL"
    REDACTED = "REDACTED"
    WITHHELD = "WITHHELD"


class ContentKind(StrEnum):
    INLINE = "INLINE"
    ARTIFACT = "ARTIFACT"


class FactStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    DISPUTED = "DISPUTED"
    RETRACTED = "RETRACTED"


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class EvidenceProvenance:
    system: str
    entity: str | None = None
    record_id: str | None = field(default=None, repr=False)
    observed_at: datetime | None = None
    qualification: str | None = field(default=None, repr=False)

    @classmethod
    def from_recon(cls, provenance: object) -> EvidenceProvenance:
        """Adapt Phase 2 provenance without fetching or copying recon payloads."""
        return cls(
            system="RECON",
            entity=str(getattr(provenance, "source_table")),
            record_id=str(getattr(provenance, "source_id")),
            observed_at=getattr(provenance, "observed_at"),
            qualification=str(getattr(provenance, "qualification")),
        )

    def to_reference(self) -> dict[str, object]:
        return {
            "system": self.system,
            "entity": self.entity,
            "record_id": self.record_id,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "qualification": self.qualification,
        }


@dataclass(frozen=True)
class Retention:
    retain: bool = True
    expires_at: datetime | None = None
    pinned: bool = False
    finding_related: bool = False
    changed_at: datetime | None = None


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    evidence_type: str
    target_ref: str | None = field(repr=False)
    observed_at: datetime
    created_at: datetime
    source: str = field(repr=False)
    content_hash: str
    content_kind: ContentKind
    content_size: int
    artifact_hash: str | None
    sensitivity: Sensitivity
    redaction_status: RedactionStatus
    provenance: EvidenceProvenance = field(repr=False)
    metadata: Mapping[str, object] = field(repr=False)
    retention: Retention = Retention()
    replaces_evidence_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze(dict(self.metadata)))

    def to_reference(self) -> dict[str, object]:
        """Small safe pointer for context packets; never includes content or metadata."""
        restricted = self.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET}
        return {
            "evidence_id": self.evidence_id,
            "type": self.evidence_type,
            "target_ref": "[REDACTED]" if restricted else self.target_ref,
            "observed_at": self.observed_at.isoformat(),
            "source": "[REDACTED]" if restricted else self.source,
            "content_hash": self.content_hash,
            "content_kind": self.content_kind.value,
            "content_size": self.content_size,
            "sensitivity": self.sensitivity.value,
            "redaction_status": self.redaction_status.value,
            "provenance": "[REDACTED]" if restricted else self.provenance.to_reference(),
            "replaces_evidence_id": self.replaces_evidence_id,
        }


@dataclass(frozen=True)
class Fact:
    fact_id: str
    subject: str = field(repr=False)
    predicate: str
    object: str = field(repr=False)
    confidence: float
    evidence_ids: tuple[str, ...]
    source: str = field(repr=False)
    observed_at: datetime
    created_at: datetime
    target_ref: str | None = field(repr=False)
    status: FactStatus
    sensitivity: Sensitivity
    status_changed_at: datetime

    def __post_init__(self) -> None:
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise ValueError("Fact confidence must be numeric")
        if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ValueError("Fact confidence must be between 0 and 1")
        if self.source != "MANUAL" and not self.evidence_ids:
            raise ValueError("Non-manual facts require evidence")

    def to_reference(self) -> dict[str, object]:
        restricted = self.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET}
        return {
            "fact_id": self.fact_id,
            "subject": "[REDACTED]" if restricted else self.subject,
            "predicate": self.predicate,
            "object": "[REDACTED]" if restricted else self.object,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "source": "[REDACTED]" if restricted else self.source,
            "observed_at": self.observed_at.isoformat(),
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
        }


@dataclass(frozen=True)
class FactStatusEvent:
    event_id: int
    fact_id: str
    status: FactStatus
    changed_at: datetime
    producer: str
    reason: str = field(repr=False)
    supporting_evidence_id: str | None = None
    related_fact_id: str | None = None
