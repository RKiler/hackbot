"""Metadata-first, planning-only security skills. Skills never execute traffic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
from pathlib import Path
import re
from typing import Any

import yaml


_ID = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_FIELDS = frozenset({"name", "description", "category", "vulnerability_classes", "triggers",
                     "prerequisites", "risk", "required_validators", "token_budget",
                     "request_budget", "version", "source", "execution_mode", "when_to_use",
                     "when_not_to_use", "alternatives", "technologies", "features", "boundaries"})
_SOURCES = frozenset({"CORE", "IMPORTED", "PERSONAL", "EPHEMERAL"})
_RISKS = frozenset({"LOW", "MEDIUM", "HIGH"})
_CATEGORIES = frozenset({"authorization", "client-side", "api", "exposure"})
_PREREQUISITES = frozenset({"authenticated_endpoint", "multiple_tenants", "multiple_roles",
                            "multiple_principals", "known_object_identifier", "known_ownership",
                            "verified_sessions", "message_listener", "dangerous_dom_sink",
                            "graphql_operation", "graphql_mutation", "current_js", "baseline_traffic",
                            "anonymous_access", "sensitive_artifact", "in_scope_target",
                            "attacker_controlled_source", "transformation_trace", "role_hidden_operation"})
_STEPS = frozenset({"OBSERVE", "ESTABLISH_CONTROL", "CREATE_TEST_OBJECT", "EXECUTE_REQUEST",
                    "COMPARE_RESPONSE", "VERIFY_BROWSER", "MANUAL_REVIEW"})
_PLAN_KEYS = frozenset({"workflow", "controls", "positive_signals", "negative_signals",
                        "evidence_requirements", "confirmation_requirements", "rejection_conditions",
                        "action_intents"})
_ACTION_INTENTS = frozenset({"SAFE_READ", "AUTHORIZATION_TEST", "BROWSER_NAVIGATION", "OBJECT_CREATE"})


class SkillError(ValueError):
    pass


def _strings(value: Any, label: str, maximum: int = 16) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum or any(
        not isinstance(item, str) or not 1 <= len(item) <= 160 or any(ord(c) < 32 for c in item)
        for item in value
    ):
        raise SkillError(f"invalid {label}")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class SkillMetadata:
    name: str
    description: str
    category: str
    vulnerability_classes: tuple[str, ...]
    triggers: tuple[str, ...]
    prerequisites: tuple[str, ...]
    risk: str
    required_validators: tuple[str, ...]
    token_budget: int
    request_budget: int
    version: str
    source: str
    when_to_use: str
    when_not_to_use: str
    alternatives: tuple[str, ...]
    technologies: tuple[str, ...]
    features: tuple[str, ...]
    boundaries: tuple[str, ...]
    path: Path

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "description": self.description, "category": self.category,
                "vulnerability_classes": list(self.vulnerability_classes), "triggers": list(self.triggers),
                "prerequisites": list(self.prerequisites), "risk": self.risk,
                "required_validators": list(self.required_validators), "token_budget": self.token_budget,
                "request_budget": self.request_budget, "version": self.version, "source": self.source,
                "when_to_use": self.when_to_use, "when_not_to_use": self.when_not_to_use,
                "alternatives": list(self.alternatives), "technologies": list(self.technologies),
                "features": list(self.features), "boundaries": list(self.boundaries)}


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    metadata: SkillMetadata
    content_hash: str
    workflow: tuple[tuple[str, str], ...]
    controls: tuple[str, ...]
    positive_signals: tuple[str, ...]
    negative_signals: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    confirmation_requirements: tuple[str, ...]
    rejection_conditions: tuple[str, ...]
    action_intents: tuple[str, ...]
    methodology: str

    def detail(self) -> dict[str, object]:
        return {**self.metadata.to_dict(), "content_hash": self.content_hash,
                "workflow": [{"type": kind, "description": description} for kind, description in self.workflow],
                "controls": list(self.controls), "confirmation_requirements": list(self.confirmation_requirements),
                "rejection_conditions": list(self.rejection_conditions),
                "evidence_requirements": list(self.evidence_requirements), "methodology": self.methodology,
                "execution": "PLAN_ONLY"}


class SkillRegistry:
    """Read only frontmatter at discovery; full bodies are loaded by select()."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._metadata: dict[str, SkillMetadata] = {}

    @staticmethod
    def _frontmatter(path: Path) -> tuple[dict[str, object], int]:
        try:
            with path.open("rb") as handle:
                if handle.readline() != b"---\n":
                    raise SkillError("missing skill frontmatter")
                buffer = bytearray()
                while True:
                    line = handle.readline()
                    if not line or len(buffer) + len(line) > 8192:
                        raise SkillError("skill frontmatter is unbounded")
                    if line == b"---\n":
                        break
                    buffer.extend(line)
                end = handle.tell()
            parsed = yaml.safe_load(buffer.decode("utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise SkillError("cannot parse skill frontmatter") from exc
        if not isinstance(parsed, dict) or set(parsed) - _FIELDS:
            raise SkillError("invalid skill metadata keys")
        return parsed, end

    @staticmethod
    def _metadata_from(path: Path, data: dict[str, object], source_dir: str) -> SkillMetadata:
        name = data.get("name")
        if not isinstance(name, str) or not _ID.fullmatch(name) or path.parent.name != name:
            raise SkillError("invalid skill ID")
        version = data.get("version")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise SkillError("invalid skill version")
        source = data.get("source")
        if source not in _SOURCES or source != source_dir.upper():
            raise SkillError("invalid skill source")
        if data.get("execution_mode") != "PLAN_ONLY":
            raise SkillError("skill execution must be planning-only")
        risk = data.get("risk")
        if risk not in _RISKS:
            raise SkillError("skill risk is required")
        category = data.get("category")
        if category not in _CATEGORIES:
            raise SkillError("invalid skill category")
        for label in ("description", "when_to_use", "when_not_to_use"):
            value = data.get(label)
            if not isinstance(value, str) or not 8 <= len(value) <= 400 or any(ord(c) < 32 for c in value):
                raise SkillError(f"invalid {label}")
        requests = data.get("request_budget")
        tokens = data.get("token_budget")
        if type(requests) is not int or not 0 <= requests <= 20 or type(tokens) is not int or not 0 <= tokens <= 8192:
            raise SkillError("skill budgets must be bounded")
        prereqs = _strings(data.get("prerequisites"), "prerequisites")
        if not set(prereqs) <= _PREREQUISITES:
            raise SkillError("unsupported prerequisite")
        triggers = _strings(data.get("triggers"), "triggers")
        if not triggers or any(not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", item) for item in triggers):
            raise SkillError("invalid triggers")
        return SkillMetadata(
            name, data["description"], category, _strings(data.get("vulnerability_classes"), "classes"),
            triggers, prereqs, risk, _strings(data.get("required_validators"), "validators"),
            tokens, requests, version, source, data["when_to_use"], data["when_not_to_use"],
            _strings(data.get("alternatives", []), "alternatives"),
            _strings(data.get("technologies", []), "technologies"),
            _strings(data.get("features", []), "features"),
            _strings(data.get("boundaries", []), "boundaries"), path)

    def discover(self) -> tuple[SkillMetadata, ...]:
        found: dict[str, SkillMetadata] = {}
        if not self.root.is_dir():
            raise SkillError("skill root is unavailable")
        for source in ("core", "imported", "personal"):
            base = self.root / source
            if not base.exists():
                continue
            for path in sorted(base.rglob("SKILL.md")):
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base.resolve()):
                    raise SkillError("unsafe skill path")
                data, _ = self._frontmatter(path)
                meta = self._metadata_from(path, data, source)
                if meta.name in found:
                    raise SkillError("duplicate skill ID")
                found[meta.name] = meta
        self._metadata = found
        return tuple(found.values())

    def metadata(self, name: str) -> SkillMetadata:
        if not self._metadata:
            self.discover()
        try:
            return self._metadata[name]
        except KeyError:
            raise LookupError("skill not found") from None

    def select(self, name: str) -> SkillDefinition:
        meta = self.metadata(name)
        data, body_start = self._frontmatter(meta.path)
        current = self._metadata_from(meta.path, data, meta.source.lower())
        if current != meta:
            raise SkillError("skill metadata changed; rediscover before selection")
        raw = meta.path.read_bytes()
        if len(raw) > 65_536:
            raise SkillError("skill body is too large")
        body = raw[body_start:].decode("utf-8")
        match = re.search(r"(?ms)^## Plan\s*\n```yaml\s*\n(.*?)\n```\s*$", body)
        if not match:
            raise SkillError("skill plan block is missing")
        try:
            plan = yaml.safe_load(match.group(1))
        except yaml.YAMLError as exc:
            raise SkillError("invalid skill plan") from exc
        if not isinstance(plan, dict) or set(plan) != _PLAN_KEYS:
            raise SkillError("invalid skill plan fields")
        workflow = plan["workflow"]
        if not isinstance(workflow, list) or not 1 <= len(workflow) <= 12:
            raise SkillError("invalid skill workflow")
        steps = []
        for step in workflow:
            if not isinstance(step, dict) or set(step) != {"type", "description"} or step["type"] not in _STEPS:
                raise SkillError("invalid skill step")
            description = step["description"]
            if not isinstance(description, str) or not 1 <= len(description) <= 240:
                raise SkillError("invalid skill step description")
            steps.append((step["type"], description))
        intents = _strings(plan["action_intents"], "action intents")
        if not set(intents) <= _ACTION_INTENTS or len(intents) > meta.request_budget:
            raise SkillError("unsupported or over-budget action intent")
        controls = _strings(plan["controls"], "controls")
        if intents and not controls:
            raise SkillError("active skill requires controls")
        return SkillDefinition(meta, hashlib.sha256(raw).hexdigest(), tuple(steps), controls,
                               _strings(plan["positive_signals"], "positive signals"),
                               _strings(plan["negative_signals"], "negative signals"),
                               _strings(plan["evidence_requirements"], "evidence requirements"),
                               _strings(plan["confirmation_requirements"], "confirmation requirements"),
                               _strings(plan["rejection_conditions"], "rejection conditions"), intents,
                               body[:match.start()].strip())
