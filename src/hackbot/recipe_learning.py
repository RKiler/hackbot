"""Infer narrow disposable-object recipes from corroborated current observations."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
import re
from urllib.parse import urlsplit

from .api_graphql import JSAPIRoute, extract_js_api_artifacts
from .domain import TrafficSource
from .domxss_store import DOMXSSStore
from .evidence import EvidenceType, RedactionStatus
from .object_recipes import ObjectRecipe, RecipeCatalog, external_id, unique_json_pairs
from .policy import _strict_url_reason
from .store import EvidenceFactStore
from .target_package import AccountReference, TargetPackage
from .target_scope import ScopeResult
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore
from .test_objects import ObjectState, TestObject


_COLLECTION = re.compile(r"/api/([a-z][a-z0-9_-]{1,63})\Z")
_OBJECT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_EXCLUDED_RESOURCE = frozenset({
    "accounts", "users", "identities", "tenants", "organizations", "organisations",
    "workspaces", "invites", "invitations", "messages", "emails", "notifications",
    "webhooks", "payments", "payouts", "billing", "subscriptions", "orders",
})


def infer_name_only_rest_recipe(
    package: TargetPackage, account: AccountReference, *,
    form: dict[str, object], routes: tuple[JSAPIRoute, ...],
    owner_url: str, owner_response: object,
) -> tuple[ObjectRecipe, dict[str, object]] | None:
    """Return a data-only recipe; callers still verify source provenance and policy."""
    if (not account.tenant_hint or not isinstance(form, dict)
            or set(form) != {"action", "method", "fields"}
            or form["method"] != "POST"
            or form["fields"] != [{"name": "name", "type": "text"}]
            or not isinstance(form["action"], str)):
        return None
    action = form["action"]
    if (_strict_url_reason(action) is not None or
            package.scope.evaluate_url(action).result is not ScopeResult.IN_SCOPE):
        return None
    parsed = urlsplit(action)
    match = _COLLECTION.fullmatch(parsed.path)
    if (not match or parsed.query or parsed.fragment or
            match.group(1) in _EXCLUDED_RESOURCE or
            not match.group(1).endswith("s") or len(match.group(1)) <= 2):
        return None
    resource = match.group(1)
    route = parsed.path + "/{id}"
    if {("GET", route), ("DELETE", route)} - {
            (entry.method, entry.path) for entry in routes}:
        return None
    if (not isinstance(owner_response, dict) or
            any(not isinstance(owner_response.get(key), str)
                for key in ("id", "name", "owner", "tenant")) or
            owner_response["owner"] != account.alias or
            owner_response["tenant"] != account.tenant_hint or
            not _OBJECT_ID.fullmatch(owner_response["id"]) or
            not isinstance(owner_url, str) or
            owner_url != action + "/" + owner_response["id"] or
            _strict_url_reason(owner_url) is not None or
            package.scope.evaluate_url(owner_url).result is not ScopeResult.IN_SCOPE):
        return None
    object_type = resource[:-1]
    recipe_id = "learned_" + hashlib.sha256(
        f"{action}\0{account.alias}\0{account.tenant_hint}".encode()).hexdigest()[:20]
    detail = action + "/{object_id}"
    payload: dict[str, object] = {
        "id": recipe_id,
        "target_id": package.target.id,
        "package_id": package.id,
        "object_type": object_type,
        "protocol": "REST",
        "create": {"method": "POST", "url": action,
                   "operation": "create" + object_type.title(),
                   "content_type": "application/x-www-form-urlencoded",
                   "body": {"name": "$test_name"}},
        "verify": {"method": "GET", "url": detail,
                   "operation": "read" + object_type.title()},
        "cleanup": {"method": "DELETE", "url": detail,
                    "operation": "delete" + object_type.title()},
        "id_pointer": "/id",
        "verify_id_pointer": "/id",
        "verify_name_pointer": "/name",
        "verify_owner_pointer": "/owner",
        "verify_tenant_pointer": "/tenant",
        "expected_owner": account.alias,
        "expected_tenant": account.tenant_hint,
        "parent_type": None,
        "cleanup_strategy": "AUTO_CLEANUP",
        "source": "learned_form_js",
    }
    try:
        return ObjectRecipe.from_json(payload), payload
    except ValueError:
        return None


class ObservedRecipeLearner:
    """Correlate only current, identity-attributed capture with mapped UI forms."""

    def __init__(self, *, evidence: EvidenceFactStore, traffic: TrafficStore,
                 js: DOMXSSStore, catalog: RecipeCatalog) -> None:
        self.evidence = evidence
        self.traffic = traffic
        self.js = js
        self.catalog = catalog

    def _request_url(self, exchange: TrafficExchange) -> str | None:
        record = self.evidence.get_evidence(exchange.request.observation_evidence_id)
        if record is None or record.target_ref != exchange.target_id:
            return None
        try:
            data = json.loads(self.evidence.read_content(record.evidence_id,
                                                           allow_sensitive=True,
                                                           max_bytes=16384),
                              object_pairs_hook=unique_json_pairs)
            url = data.get("url") if isinstance(data, dict) else None
            if (not isinstance(url, str) or _strict_url_reason(url) is not None
                    or urlsplit(url).query or urlsplit(url).fragment):
                return None
            return url
        except (ValueError, KeyError, PermissionError, UnicodeError):
            return None

    def _forms(self, package: TargetPackage, session_id: str,
               since: datetime) -> tuple[dict[str, object], ...]:
        forms: list[dict[str, object]] = []
        cursor = None
        for _ in range(8):
            page = self.evidence.list_evidence_for_target(
                package.target.id, limit=50, cursor=cursor)
            for record in page.items:
                if record.created_at < since:
                    return tuple(forms[:16])
                if (record.evidence_type != EvidenceType.BROWSER_EVENT.value or
                        record.source != "application_mapper" or
                        record.provenance.record_id != session_id or
                        record.redaction_status is not RedactionStatus.ORIGINAL):
                    continue
                try:
                    data = json.loads(self.evidence.read_content(
                        record.evidence_id, max_bytes=8192),
                        object_pairs_hook=unique_json_pairs)
                    if isinstance(data, dict) and isinstance(data.get("form_schemas"), list):
                        forms.extend(item for item in data["form_schemas"][:16]
                                     if isinstance(item, dict))
                except (ValueError, PermissionError, UnicodeError):
                    continue
                if len(forms) >= 16:
                    return tuple(forms[:16])
            cursor = page.next_cursor
            if cursor is None:
                break
        return tuple(forms[:16])

    def _routes(self, package: TargetPackage, since: datetime
                ) -> dict[str, tuple[JSAPIRoute, ...]]:
        routes: dict[str, list[JSAPIRoute]] = {}
        for asset in self.js.list_current_assets(package.target.id, limit=12):
            if (asset.source != "CAPTURED_BURP" or asset.retrieved_at < since or
                    asset.retrieval_exchange_id is None):
                continue
            exchange = self.traffic.get_exchange(asset.retrieval_exchange_id)
            if (exchange is None or exchange.target_id != package.target.id or
                    exchange.package_id != package.id or exchange.source is not TrafficSource.BURP or
                    exchange.capture_provider != "MONTOYA_V1" or
                    exchange.scope_result is not ScopeResult.IN_SCOPE or
                    exchange.state is not ExchangeState.COMPLETE or
                    exchange.attribution.auth_state is not AuthState.VERIFIED or
                    exchange.request.record.method != "GET" or
                    exchange.response is None or
                    exchange.response.record.status_code != 200):
                continue
            url = self._request_url(exchange)
            if (url is None or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE
                    or hashlib.sha256(url.encode()).hexdigest() != asset.asset_url_sha256):
                continue
            try:
                body = self.evidence.read_content(asset.evidence_id,
                                                  allow_sensitive=True, max_bytes=1_048_576)
                if hashlib.sha256(body).hexdigest() != asset.artifact_sha256:
                    continue
                _, entries = extract_js_api_artifacts(body)
            except (ValueError, PermissionError, RuntimeError, UnicodeError):
                continue
            origin = exchange.request.origin
            routes.setdefault(origin, []).extend(entries)
        return {origin: tuple(items[:48]) for origin, items in routes.items()}

    def current_self_urls(self, package: TargetPackage, since: datetime) -> tuple[str, ...]:
        """Offer only exact safe self routes from current captured first-party JS."""
        allowed = {"/api/me", "/api/v1/me", "/me", "/api/current-user"}
        urls = []
        for origin, routes in self._routes(package, since).items():
            for route in routes:
                if route.method != "GET" or route.path not in allowed:
                    continue
                url = origin + route.path
                if (_strict_url_reason(url) is None and
                        package.scope.evaluate_url(url).result is ScopeResult.IN_SCOPE):
                    urls.append(url)
        return tuple(dict.fromkeys(urls))[:4]

    def current_object_read_urls(self, package: TargetPackage, recipe: ObjectRecipe,
                                 object_id: str, since: datetime) -> tuple[str, ...]:
        """Return only current JS-advertised sibling GET routes for this exact object."""
        external_id(object_id)
        if recipe.target_id != package.target.id or recipe.package_id != package.id:
            raise ValueError("Object recipe does not belong to this target")
        parsed = urlsplit(recipe.verify.url)
        if parsed.path.count("{object_id}") != 1:
            return ()
        origin = parsed.scheme + "://" + parsed.netloc
        base = parsed.path.replace("{object_id}", "{id}")
        allowed = {base + "/preview", base + "/view"}
        urls = []
        for route in self._routes(package, since).get(origin, ()):
            if route.method != "GET" or route.path not in allowed:
                continue
            url = origin + route.path.replace("{id}", object_id)
            if (_strict_url_reason(url) is None and
                    package.scope.evaluate_url(url).result is ScopeResult.IN_SCOPE):
                urls.append(url)
        return tuple(dict.fromkeys(urls))[:2]

    def has_captured_owner_read(self, package: TargetPackage, session_id: str,
                                identity_id: str, url: str, since: datetime) -> bool:
        exchange = self.captured_read(package, session_id, identity_id, url, since)
        return bool(exchange and exchange.response and
                    exchange.response.record.status_code == 200)

    def captured_read(self, package: TargetPackage, session_id: str,
                      identity_id: str, url: str,
                      since: datetime) -> TrafficExchange | None:
        cursor = None
        for _ in range(4):
            page = self.traffic.list_exchanges_for_session(
                package.target.id, session_id, limit=50, cursor=cursor)
            for exchange in page.items:
                if exchange.observed_at < since:
                    return None
                if (exchange.package_id == package.id and
                        exchange.source is TrafficSource.BURP and
                        exchange.capture_provider == "MONTOYA_V1" and
                        exchange.scope_result is ScopeResult.IN_SCOPE and
                        exchange.state is ExchangeState.COMPLETE and
                        exchange.attribution.auth_state is AuthState.VERIFIED and
                        exchange.attribution.verified_identity_id == identity_id and
                        exchange.request.record.method == "GET" and
                        exchange.response is not None and
                        self._request_url(exchange) == url):
                    return exchange
            cursor = page.next_cursor
            if cursor is None:
                break
        return None

    def record_tenant_private_control(
            self, package: TargetPackage, item: TestObject, recipe: ObjectRecipe,
            external: str, tenant_id: str, *,
            owner: tuple[str, str], same_tenant: tuple[str, str],
            foreign: tuple[str, str], since: datetime) -> bool:
        """Corroborate a fixture policy using a distinct, captured detail route."""
        if (item.target_id != package.target.id or item.package_id != package.id or
                item.state is not ObjectState.READY or not item.verified_at or
                item.tenant_id != tenant_id or recipe.package_id != package.id or
                recipe.target_id != package.target.id or recipe.verify.method != "GET" or
                len({owner[1], same_tenant[1], foreign[1]}) != 3):
            return False
        try:
            url = recipe.verify.template(test_name=item.test_name, object_id=external).url
        except ValueError:
            return False
        if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
            return False
        observed = [self.captured_read(package, session_id, identity_id, url, since)
                    for session_id, identity_id in (owner, same_tenant, foreign)]
        if any(exchange is None or exchange.response is None for exchange in observed):
            return False
        owner_read, peer_read, denied_read = observed
        assert owner_read and owner_read.response and peer_read and peer_read.response
        assert denied_read and denied_read.response
        if (owner_read.response.record.status_code != 200 or
                peer_read.response.record.status_code != 200 or
                denied_read.response.record.status_code not in {403, 404}):
            return False

        def body(exchange: TrafficExchange) -> dict[str, object] | None:
            response = exchange.response
            if (response is None or response.body_evidence_id is None or
                    response.record.size_bytes > 16384):
                return None
            try:
                value = json.loads(self.evidence.read_content(
                    response.body_evidence_id, allow_sensitive=True, max_bytes=16384),
                    object_pairs_hook=unique_json_pairs)
            except (ValueError, KeyError, PermissionError, UnicodeError):
                return None
            return value if isinstance(value, dict) else None

        expected = {"id": external, "name": item.test_name,
                    "owner": recipe.expected_owner, "tenant": recipe.expected_tenant}
        owner_body, peer_body = body(owner_read), body(peer_read)
        if (owner_body is None or peer_body is None or
                any(owner_body.get(key) != value or peer_body.get(key) != value
                    for key, value in expected.items())):
            return False
        if denied_read.response.body_evidence_id is not None:
            try:
                denied_body = self.evidence.read_content(
                    denied_read.response.body_evidence_id, allow_sensitive=True,
                    max_bytes=16384)
            except (ValueError, KeyError, PermissionError, UnicodeError):
                return False
            if external.encode() in denied_body:
                return False
        refs = tuple(dict.fromkeys((
            owner_read.response.observation_evidence_id,
            peer_read.response.observation_evidence_id,
            denied_read.response.observation_evidence_id)))
        subject = hashlib.sha256(external.encode()).hexdigest()
        for predicate, value in (("resource_tenant", tenant_id),
                                 ("resource_visibility", "PRIVATE"),
                                 ("access_policy", "TENANT_ONLY")):
            if any(fact.object == value and fact.target_ref == package.target.id
                   for fact in self.evidence.find_facts(subject, predicate, limit=8).items):
                continue
            self.evidence.create_fact(
                subject, predicate, value, confidence=0.95, evidence_ids=refs,
                source="OBSERVED_TENANT_DETAIL_CONTROL", target_ref=package.target.id)
        return True

    def _owner_samples(self, package: TargetPackage, session_id: str,
                       identity_id: str, since: datetime
                       ) -> tuple[tuple[str, object], ...]:
        samples: list[tuple[str, object]] = []
        cursor = None
        for _ in range(4):
            page = self.traffic.list_exchanges_for_session(
                package.target.id, session_id, limit=50, cursor=cursor)
            for exchange in page.items:
                if exchange.observed_at < since:
                    return tuple(samples[:16])
                response = exchange.response
                if (exchange.package_id != package.id or
                        exchange.source is not TrafficSource.BURP or
                        exchange.capture_provider != "MONTOYA_V1" or
                        exchange.scope_result is not ScopeResult.IN_SCOPE or
                        exchange.state is not ExchangeState.COMPLETE or
                        exchange.attribution.auth_state is not AuthState.VERIFIED or
                        exchange.attribution.verified_identity_id != identity_id or
                        exchange.request.record.method != "GET" or response is None or
                        response.record.status_code != 200 or
                        response.record.content_type != "application/json" or
                        response.body_evidence_id is None or
                        response.record.size_bytes > 8192):
                    continue
                url = self._request_url(exchange)
                if url is None or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
                    continue
                try:
                    body = self.evidence.read_content(response.body_evidence_id,
                                                      allow_sensitive=True, max_bytes=8192)
                    if hashlib.sha256(body).hexdigest() != response.body_hash:
                        continue
                    data = json.loads(body, object_pairs_hook=unique_json_pairs)
                except (ValueError, PermissionError, UnicodeError):
                    continue
                samples.append((url, data))
                if len(samples) >= 16:
                    return tuple(samples)
            cursor = page.next_cursor
            if cursor is None:
                break
        return tuple(samples)

    def learn(self, package: TargetPackage, account: AccountReference, *,
              session_id: str, identity_id: str, since: datetime
              ) -> tuple[ObjectRecipe, ...]:
        if not account.tenant_hint or since.tzinfo is None:
            return ()
        forms = self._forms(package, session_id, since)
        if not forms:
            return ()
        routes = self._routes(package, since)
        if not routes:
            return ()
        samples = self._owner_samples(package, session_id, identity_id, since)
        learned: list[ObjectRecipe] = []
        for form in forms:
            action = form.get("action")
            if not isinstance(action, str):
                continue
            matching = routes.get(urlsplit(action).scheme + "://" + urlsplit(action).netloc)
            if not matching:
                continue
            for url, response in samples:
                inferred = infer_name_only_rest_recipe(
                    package, account, form=form, routes=matching,
                    owner_url=url, owner_response=response)
                if inferred is None:
                    continue
                recipe, payload = inferred
                stored = self.catalog.add_learned(package, payload)
                learned.append(stored)
                break
            if len(learned) >= 2:
                break
        return tuple(learned)
