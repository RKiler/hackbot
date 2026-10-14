"""Bounded, metadata-only response comparison for deterministic validators."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .evidence import RedactionStatus
from .api_graphql import GraphQLResult, classify_result
from .store import EvidenceFactStore
from .traffic import TrafficExchange


def _hash(value: bytes | str) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous duplicate JSON key")
        result[key] = value
    return result


def _walk(value: Any, path: str, volatile: frozenset[str], counters: list[int],
          object_ids: set[str], tenant_ids: set[str], *, depth: int = 0) -> Any:
    counters[0] += 1
    if counters[0] > 10000 or depth > 16:
        raise ValueError("JSON exceeds bounded comparison depth")
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if child in volatile:
                continue
            if key in {"id", "objectId", "object_id", "_id"} and isinstance(item, str) and item:
                object_ids.add(_hash(item))
            if key in {"tenantId", "tenant_id", "orgId", "organizationId"} and isinstance(item, str) and item:
                tenant_ids.add(_hash(item))
            output[key] = _walk(item, child, volatile, counters, object_ids, tenant_ids,
                                depth=depth + 1)
        return output
    if isinstance(value, list):
        return [_walk(item, path + "/" + str(index), volatile, counters,
                      object_ids, tenant_ids, depth=depth + 1)
                for index, item in enumerate(value)]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("unsupported JSON value")


@dataclass(frozen=True, slots=True)
class ResponseFeatures:
    status_code: int | None
    content_type: str | None
    body_hash: str | None
    body_size: int | None
    normalized_json_hash: str | None
    graphql_data_hash: str | None
    graphql_data_present: bool
    graphql_errors_present: bool
    object_id_hashes: tuple[str, ...]
    tenant_id_hashes: tuple[str, ...]
    request_path_fingerprint: str
    request_structural_fingerprint: str
    request_method: str
    graphql_result: str = GraphQLResult.AMBIGUOUS.value
    graphql_data_paths: tuple[str, ...] = ()
    graphql_error_paths: tuple[str, ...] = ()
    graphql_error_codes: tuple[str, ...] = ()
    graphql_value_hashes: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"status_code": self.status_code, "content_type": self.content_type,
                "body_hash": self.body_hash, "body_size": self.body_size,
                "normalized_json_hash": self.normalized_json_hash,
                "graphql_data_hash": self.graphql_data_hash,
                "graphql_data_present": self.graphql_data_present,
                "graphql_errors_present": self.graphql_errors_present,
                "object_id_hashes": list(self.object_id_hashes),
                "tenant_id_hashes": list(self.tenant_id_hashes),
                "request_path_fingerprint": self.request_path_fingerprint,
                "request_structural_fingerprint": self.request_structural_fingerprint,
                "request_method": self.request_method,
                "graphql_result": self.graphql_result,
                "graphql_data_paths": list(self.graphql_data_paths),
                "graphql_error_paths": list(self.graphql_error_paths),
                "graphql_error_codes": list(self.graphql_error_codes),
                "graphql_value_hashes": [list(item) for item in self.graphql_value_hashes]}

    def graphql_value(self, path: str) -> str | None:
        return next((value for key, value in self.graphql_value_hashes if key == path), None)


def _graphql_paths(payload: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...],
                                                    tuple[str, ...], tuple[tuple[str, str], ...]]:
    present: set[str] = set()
    values: dict[str, str] = {}

    def visit(value: Any, path: str, depth: int) -> None:
        if depth > 10 or len(present) >= 160 or value is None:
            return
        present.add(path)
        if isinstance(value, dict):
            for name, item in value.items():
                visit(item, path + "/" + name.replace("~", "~0").replace("/", "~1"), depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value[:16]):
                visit(item, path + "/" + str(index), depth + 1)
        else:
            values[path] = _hash(json.dumps(value, sort_keys=True, ensure_ascii=True))

    data = payload.get("data")
    if isinstance(data, dict):
        for key, value in data.items():
            visit(value, "/" + key.replace("~", "~0").replace("/", "~1"), 0)
    errors: set[str] = set()
    codes: set[str] = set()
    if isinstance(payload.get("errors"), list):
        for error in payload["errors"][:16]:
            if not isinstance(error, dict):
                continue
            path = error.get("path")
            if (isinstance(path, list) and len(path) <= 12 and
                    all(isinstance(part, (str, int)) and len(str(part)) <= 64 for part in path)):
                errors.add("/" + "/".join(str(part).replace("~", "~0").replace("/", "~1")
                                           for part in path))
            extensions = error.get("extensions")
            code = extensions.get("code") if isinstance(extensions, dict) else None
            if isinstance(code, str) and len(code) <= 64 and code.replace("_", "").isalnum():
                codes.add(code.upper())
    return tuple(sorted(present)), tuple(sorted(errors)), tuple(sorted(codes)), tuple(sorted(values.items()))


@dataclass(frozen=True, slots=True)
class ResponseComparison:
    status_equal: bool
    content_type_equal: bool
    body_hash_equal: bool
    size_equal: bool
    normalized_json_equal: bool | None
    graphql_data_equal: bool | None
    same_request_path: bool
    same_request_shape: bool


class ResponseComparator:
    def __init__(self, evidence: EvidenceFactStore, *, max_json_bytes: int = 262144,
                 volatile_json_paths: frozenset[str] = frozenset()) -> None:
        if type(max_json_bytes) is not int or not 1 <= max_json_bytes <= 1048576:
            raise ValueError("invalid JSON comparison bound")
        protected_keys = {"id", "objectId", "object_id", "_id", "tenantId", "tenant_id",
                          "orgId", "organizationId", "data", "errors"}
        if len(volatile_json_paths) > 16 or any(not path.startswith("/") or
                                                 len(path) > 128 or path.rsplit("/", 1)[-1] in protected_keys
                                                 for path in volatile_json_paths):
            raise ValueError("invalid exact volatile JSON paths")
        self.evidence = evidence
        self.max_json_bytes = max_json_bytes
        self.volatile_json_paths = volatile_json_paths

    def _json(self, exchange: TrafficExchange) -> tuple[str | None, str | None, bool, bool,
                                                        tuple[str, ...], tuple[str, ...],
                                                        str, tuple[str, ...], tuple[str, ...],
                                                        tuple[str, ...], tuple[tuple[str, str], ...]]:
        empty = (None, None, False, False, (), (), GraphQLResult.AMBIGUOUS.value, (), (), (), ())
        response = exchange.response
        if (response is None or response.body_evidence_id is None or
                response.record.content_type not in {"application/json", "application/graphql-response+json"}):
            return empty
        evidence = self.evidence.get_evidence(response.body_evidence_id)
        if (evidence is None or evidence.target_ref != exchange.target_id or
                evidence.redaction_status is not RedactionStatus.ORIGINAL or
                evidence.content_size > self.max_json_bytes):
            return empty
        try:
            raw = self.evidence.read_content(evidence.evidence_id, allow_sensitive=True,
                                             max_bytes=self.max_json_bytes)
            if response.body_hash != _hash(raw):
                return empty
            parsed = json.loads(raw, object_pairs_hook=_unique_pairs)
            objects: set[str] = set()
            tenants: set[str] = set()
            normalized = _walk(parsed, "", self.volatile_json_paths, [0], objects, tenants)
            digest = _hash(json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True))
            data = normalized.get("data") if isinstance(normalized, dict) else None
            graphql_present = isinstance(data, dict) and bool(data) and any(
                value is not None for value in data.values())
            graphql_errors = bool(normalized.get("errors")) if isinstance(normalized, dict) else False
            data_hash = (_hash(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=True)) if graphql_present else None)
            paths, error_paths, error_codes, value_hashes = (
                _graphql_paths(normalized) if isinstance(normalized, dict) and
                ("data" in normalized or "errors" in normalized) else ((), (), (), ()))
            return (digest, data_hash, graphql_present, graphql_errors,
                    tuple(sorted(objects)), tuple(sorted(tenants)),
                    classify_result(normalized).value if paths or error_paths or error_codes or
                    isinstance(normalized, dict) and ("data" in normalized or "errors" in normalized)
                    else GraphQLResult.AMBIGUOUS.value,
                    paths, error_paths, error_codes, value_hashes)
        except (UnicodeDecodeError, ValueError, TypeError, KeyError, PermissionError):
            return empty

    def features(self, exchange: TrafficExchange) -> ResponseFeatures:
        (normalized, graphql_hash, graphql_present, graphql_errors, objects, tenants,
         graphql_result, paths, error_paths, error_codes, value_hashes) = self._json(exchange)
        response = exchange.response
        return ResponseFeatures(
            response.record.status_code if response else None,
            response.record.content_type if response else None,
            response.body_hash if response else None,
            response.record.size_bytes if response else None,
            normalized, graphql_hash, graphql_present, graphql_errors,
            objects, tenants, exchange.request.path_fingerprint,
            exchange.request.structural_fingerprint, exchange.request.record.method,
            graphql_result, paths, error_paths, error_codes, value_hashes)

    @staticmethod
    def compare(control: ResponseFeatures, test: ResponseFeatures) -> ResponseComparison:
        return ResponseComparison(
            control.status_code == test.status_code,
            control.content_type == test.content_type,
            bool(control.body_hash and control.body_hash == test.body_hash),
            control.body_size == test.body_size,
            control.normalized_json_hash == test.normalized_json_hash
            if control.normalized_json_hash and test.normalized_json_hash else None,
            control.graphql_data_hash == test.graphql_data_hash
            if control.graphql_data_hash and test.graphql_data_hash else None,
            control.request_path_fingerprint == test.request_path_fingerprint,
            control.request_structural_fingerprint == test.request_structural_fingerprint)
