"""Typed, secret-free exposure leads. A candidate is never a confirmed finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import re
from urllib.parse import urlsplit

from .evidence import Sensitivity


class ExposureCategory(StrEnum):
    UNAUTHENTICATED_RESOURCE = "UNAUTHENTICATED_RESOURCE"
    UNAUTHENTICATED_DOWNLOAD = "UNAUTHENTICATED_DOWNLOAD"
    PII_EXPOSURE = "PII_EXPOSURE"
    CREDENTIAL_DISCLOSURE = "CREDENTIAL_DISCLOSURE"
    CONFIG_DISCLOSURE = "CONFIG_DISCLOSURE"
    JS_SECRET = "JS_SECRET"
    SOURCE_MAP_SECRET = "SOURCE_MAP_SECRET"
    DEBUG_ENDPOINT = "DEBUG_ENDPOINT"
    ADMIN_SURFACE = "ADMIN_SURFACE"
    BACKUP_ARTIFACT = "BACKUP_ARTIFACT"
    INTERNAL_HOST_DISCLOSURE = "INTERNAL_HOST_DISCLOSURE"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    INTERNAL_VHOST_CANDIDATE = "INTERNAL_VHOST_CANDIDATE"
    OVEREXPOSED_API_RESPONSE = "OVEREXPOSED_API_RESPONSE"
    UNKNOWN_EXPOSURE = "UNKNOWN_EXPOSURE"


class ExposureStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    FORMAT_VALID = "FORMAT_VALID"
    TARGET_RELEVANT = "TARGET_RELEVANT"
    SAFE_VALIDATED = "SAFE_VALIDATED"
    REJECTED_PLACEHOLDER = "REJECTED_PLACEHOLDER"
    REJECTED_PUBLIC = "REJECTED_PUBLIC"
    NEEDS_RESEARCH = "NEEDS_RESEARCH"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    STALE = "STALE"


class ExposureSource(StrEnum):
    RECON = "RECON"
    TRAFFIC = "TRAFFIC"
    JS_ASSET = "JS_ASSET"
    SOURCE_MAP = "SOURCE_MAP"
    FACT = "FACT"
    TARGET_PROFILE = "TARGET_PROFILE"


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    credential_type: str
    fingerprint_sha256: str
    value_length: int
    service_class: str
    potential_privilege: str
    validation_status: ExposureStatus

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint_sha256):
            raise ValueError("Invalid credential fingerprint")
        if not 1 <= self.value_length <= 8192:
            raise ValueError("Invalid credential length")
        for value in (self.credential_type, self.service_class, self.potential_privilege):
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value):
                raise ValueError("Invalid credential classification")


@dataclass(frozen=True, slots=True)
class ExposureCandidate:
    candidate_id: str
    target_id: str
    category: ExposureCategory
    location: str = field(repr=False)
    endpoint_or_asset: str
    identity_context: str
    source: ExposureSource
    evidence_ids: tuple[str, ...]
    sensitivity: Sensitivity
    confidence: int
    priority: int
    verification_requirements: tuple[str, ...]
    status: ExposureStatus
    created_at: datetime
    updated_at: datetime
    reason_codes: tuple[str, ...] = ()
    artifact_sha256: str | None = None
    credential: CredentialMetadata | None = field(default=None, repr=False)
    pii_categories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"EXP-[0-9a-f]{32}", self.candidate_id):
            raise ValueError("Invalid exposure candidate ID")
        if not re.fullmatch(r"[A-Z][A-Za-z0-9_-]{0,127}", self.endpoint_or_asset):
            raise ValueError("Exposure source must be an opaque record ID")
        if not 0 <= self.confidence <= 100 or not 0 <= self.priority <= 100:
            raise ValueError("Invalid exposure rank")
        if len(self.evidence_ids) > 24 or len(self.verification_requirements) > 16:
            raise ValueError("Exposure candidate metadata is unbounded")
        if self.artifact_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256):
            raise ValueError("Invalid artifact fingerprint")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("Exposure timestamps must be timezone aware")
        try:
            parsed = urlsplit(self.location)
            safe_location = (parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                             and not parsed.username and not parsed.password
                             and not parsed.query and not parsed.fragment)
        except ValueError:
            safe_location = False
        if not safe_location or len(self.location) > 1024:
            raise ValueError("Exposure location must be an origin/path without credentials or query")
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,79}", self.identity_context):
            raise ValueError("Invalid exposure identity context")
        if any(not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value)
               for value in (*self.reason_codes, *self.verification_requirements,
                             *self.pii_categories)):
            raise ValueError("Exposure labels must be fixed codes")

    def public_dict(self) -> dict[str, object]:
        credential = self.credential
        return {
            "candidate_id": self.candidate_id, "target_id": self.target_id,
            "category": self.category.value, "location": self.location,
            "endpoint_or_asset": self.endpoint_or_asset,
            "identity_context": self.identity_context, "source": self.source.value,
            "evidence_ids": list(self.evidence_ids), "sensitivity": self.sensitivity.value,
            "confidence": self.confidence, "priority": self.priority,
            "verification_requirements": list(self.verification_requirements),
            "status": self.status.value, "reason_codes": list(self.reason_codes),
            "artifact_sha256": self.artifact_sha256,
            "credential": ({
                "type": credential.credential_type,
                "fingerprint_sha256": credential.fingerprint_sha256,
                "value_length": credential.value_length,
                "service_class": credential.service_class,
                "potential_privilege": credential.potential_privilege,
                "validation_status": credential.validation_status.value,
            } if credential else None),
            "pii_categories": list(self.pii_categories),
            "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat(),
            "finding_status": "UNVALIDATED",
        }
