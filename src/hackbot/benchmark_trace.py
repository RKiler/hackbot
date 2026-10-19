"""Read-only projection of one isolated campaign into benchmark observations."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from .api_registry import APIOperationType
from .authorization import AuthorizationObject
from .benchmark_eval import CaseTrace, CaseUsage, ObservedCandidate, ObservedFinding
from .benchmark_models import (BenchmarkCategory, CandidateProvenance,
                               structured_root_fingerprint)
from .campaign_models import Campaign, CampaignWorkKind
from .domain import ObservationState
from .identity import MembershipStatus
from .validation_store import FindingStatus, ValidationStatus


_CATEGORY = {
    "CROSS_TENANT": BenchmarkCategory.CROSS_TENANT_BOLA,
    "BOLA": BenchmarkCategory.CROSS_TENANT_BOLA,
    "HORIZONTAL": BenchmarkCategory.HORIZONTAL_IDOR,
    "IDOR": BenchmarkCategory.HORIZONTAL_IDOR,
    "VERTICAL": BenchmarkCategory.VERTICAL_BFLA,
    "HIDDEN_FUNCTION": BenchmarkCategory.VERTICAL_BFLA,
    "BFLA": BenchmarkCategory.VERTICAL_BFLA,
    "ROLE_AUTHORIZATION": BenchmarkCategory.VERTICAL_BFLA,
    "GRAPHQL_AUTHORIZATION": BenchmarkCategory.GRAPHQL_OBJECT_AUTH,
    "API_AUTHORIZATION": BenchmarkCategory.NESTED_API_AUTH,
    "DOM_XSS": BenchmarkCategory.DOM_XSS,
    "POSTMESSAGE": BenchmarkCategory.POSTMESSAGE,
    "EXPOSURE": BenchmarkCategory.UNAUTHENTICATED_DOWNLOAD,
    "CREDENTIAL_EXPOSURE": BenchmarkCategory.CREDENTIAL_DISCLOSURE,
    "INTERNAL_SURFACE": BenchmarkCategory.INTERNAL_VHOST,
}


def _category(value: str) -> BenchmarkCategory:
    try:
        return BenchmarkCategory(value)
    except ValueError:
        return _CATEGORY.get(value, BenchmarkCategory.OTHER)


def _candidate_category(runtime: object, candidate: object) -> BenchmarkCategory:
    if candidate.source_kind != "API_GRAPHQL":
        return _category(candidate.category)
    source = runtime.api_operations.get_candidate(candidate.target_id,
                                                  candidate.source_id)
    if source is None or source.category != candidate.category:
        return BenchmarkCategory.OTHER
    operation = runtime.api_operations.get_operation(candidate.target_id,
                                                     source.operation_id)
    if (operation is not None and operation.state == "CURRENT" and
            operation.type is APIOperationType.GRAPHQL_QUERY):
        if source.category == "OBJECT_AUTH":
            return BenchmarkCategory.GRAPHQL_OBJECT_AUTH
        if source.category == "FIELD_AUTH":
            return BenchmarkCategory.GRAPHQL_FIELD_AUTH
    return _category(candidate.category)


def _authorization_category(value: str, boundary: str,
                            plan: dict[str, object] | None) -> BenchmarkCategory:
    if (value == "AUTHORIZATION_MUTATION" and plan is not None and
            plan.get("skill_id") == "typed-authorization-mutation"):
        return {"TENANT": BenchmarkCategory.CROSS_TENANT_BOLA,
                "OBJECT": BenchmarkCategory.HORIZONTAL_IDOR,
                "ROLE": BenchmarkCategory.VERTICAL_BFLA}.get(
                    boundary, BenchmarkCategory.AUTHORIZATION)
    return _category(value)


def _authorization_path(path: str, boundary: str) -> str:
    if boundary == "TENANT":
        for label in ("tenant-a", "tenant-b"):
            path = path.replace(f"/{label}/", "/{tenant}/")
    return path


def _operation(runtime: object, target_id: str, plan: dict[str, object] | None,
               surface_key: str, boundary: str) -> tuple[str, str]:
    if plan is None:
        return surface_key, "UNKNOWN"
    templates = plan.get("request_templates")
    if isinstance(templates, list) and templates and isinstance(templates[0], dict):
        if plan.get("skill_id") == "typed-authorization-mutation":
            boundary_steps = [row for row in templates if isinstance(row, dict) and
                              row.get("binding") == "AUTHORIZATION_RECIPE_MUTATION_V1" and
                              row.get("stage") == "BOUNDARY_MUTATE"]
            if len(boundary_steps) == 1:
                step = boundary_steps[0]
                object_id = step.get("test_object_id")
                item = runtime.objects.get(object_id, target_id) if isinstance(object_id, str) else None
                recipe = (runtime.object_factory.recipes.get(item.package_id, item.recipe_id)
                          if item is not None and item.verified_at else None)
                if (recipe is not None and recipe.sha256 == item.recipe_hash and
                        recipe.target_id == target_id and
                        step.get("recipe_hash") == recipe.sha256):
                    matching = [entry for entry in recipe.mutations if
                                entry.mutation_type.value == step.get("mutation_type") and
                                entry.write.method == step.get("method")]
                    if len(matching) == 1:
                        route = _authorization_path(
                            urlsplit(matching[0].write.url).path, boundary)
                        return f"{matching[0].write.method} {route}", "HTTP"
        template = templates[0]
        method = template.get("method")
        target = template.get("url") or template.get("source_ref")
        if isinstance(method, str) and isinstance(target, str):
            parsed = urlsplit(target)
            return f"{method} {_authorization_path(parsed.path or target, boundary)}", "HTTP"
        object_id = template.get("test_object_id")
        if (isinstance(method, str) and isinstance(object_id, str) and
                template.get("binding") in {
                    "AUTHORIZATION_OBJECT_PATH_V1", "EXPOSURE_OBJECT_PATH_V1"}):
            item = runtime.objects.get(object_id, target_id)
            if item is not None and item.verified_at is not None:
                recipe = runtime.object_factory.recipes.get(item.package_id,
                                                            item.recipe_id)
                if (recipe is not None and recipe.sha256 == item.recipe_hash and
                        recipe.target_id == target_id and
                        recipe.verify.method == method):
                    return (f"{method} {_authorization_path(urlsplit(recipe.verify.url).path, boundary)}",
                            "HTTP")
    if plan.get("dom_binding"):
        return surface_key, "DOM"
    if plan.get("message_binding"):
        return surface_key, "POSTMESSAGE"
    if plan.get("api_binding"):
        return surface_key, "API"
    return surface_key, "UNKNOWN"


def _graphql_owned_route(runtime: object, candidate: object) -> tuple[str, str, object, object] | None:
    """Resolve the exact GraphQL operation from verified owner evidence only."""
    if candidate.source_kind != "API_GRAPHQL":
        return None
    source = runtime.api_operations.get_candidate(candidate.target_id,
                                                  candidate.source_id)
    if source is None or source.category not in {"OBJECT_AUTH", "FIELD_AUTH"}:
        return None
    operation = runtime.api_operations.get_operation(candidate.target_id,
                                                     source.operation_id)
    if not source.test_object_id:
        return None
    item = runtime.objects.get(source.test_object_id, candidate.target_id)
    if (operation is None or operation.type is not APIOperationType.GRAPHQL_QUERY or
            operation.state != "CURRENT" or operation.method != "POST" or
            not operation.endpoint or not source.owner_exchange_id or
            source.owner_exchange_id not in operation.exchange_ids or
            not source.owner_identity_id or not source.boundary_identity_id or
            source.owner_identity_id == source.boundary_identity_id or
            item is None or not item.disposable or not item.verified_at or
            item.creator_identity_id != source.owner_identity_id or
            item.package_id != operation.package_id):
        return None
    recipe = runtime.object_factory.recipes.get(item.package_id, item.recipe_id)
    if (recipe is None or recipe.sha256 != item.recipe_hash or
            recipe.target_id != candidate.target_id):
        return None
    try:
        package = runtime.package(operation.package_id)
        if source.category == "FIELD_AUTH" and (
                not source.field_path or
                source.field_path not in {field.path for field in operation.fields} or
                not runtime.api._trusted_field_expectation(
                    package, item.id, source.field_path)):
            return None
        owner = AuthorizationObject(
            item.id, item.object_type, item.creator_identity_id,
            item.owner_principal_id, item.tenant_id, item.parent_id,
            item.external_id_hash, item.verification_evidence_ids[:8], ())
        observed = runtime.authorization.observed_operation(
            package, owner, source.owner_exchange_id)
    except (LookupError, ValueError, PermissionError, UnicodeError):
        return None
    if (observed is None or not observed.semantic_owner_success or
            observed.protocol != "GRAPHQL" or observed.graphql_kind != "QUERY" or
            observed.owner_identity_id != source.owner_identity_id or
            observed.object_id != item.id or observed.method != operation.method or
            observed.display_path != urlsplit(operation.endpoint).path):
        return None
    exchange = runtime.traffic.get_exchange(source.owner_exchange_id)
    try:
        exact_url = (runtime.authorization._request_url(exchange, runtime.store)
                     if exchange is not None else None)
    except (ValueError, PermissionError, UnicodeError):
        return None
    if (exact_url is None or urlsplit(exact_url).netloc !=
            urlsplit(observed.origin).netloc or not urlsplit(exact_url).path):
        return None
    try:
        owner_memberships = runtime.registry.list_memberships(
            source.owner_identity_id, limit=20)
        boundary_memberships = runtime.registry.list_memberships(
            source.boundary_identity_id, limit=20)
    except (ValueError, PermissionError):
        return None
    if (owner_memberships.next_cursor is not None or
            boundary_memberships.next_cursor is not None):
        return None
    def observed_tenants(page: object) -> set[str]:
        return {member.tenant_id for member in page.items
                if member.target_id == candidate.target_id and
                member.status is MembershipStatus.ACTIVE and
                member.observation_state is ObservationState.OBSERVED}
    owner_tenants = observed_tenants(owner_memberships)
    boundary_tenants = observed_tenants(boundary_memberships)
    if (item.tenant_id not in owner_tenants or
            item.tenant_id in boundary_tenants or not boundary_tenants):
        return None
    return f"{operation.method} {urlsplit(exact_url).path}", item.object_type, source, operation


def _browser_root(runtime: object, candidate: object, hypothesis: object | None,
                  plan: dict[str, object] | None,
                  category: BenchmarkCategory) -> tuple[str, str, str, str] | None:
    """Project only a bound current JS candidate, never a free-form title."""
    if hypothesis is None or plan is None:
        return None
    if candidate.source_kind == "DOM_XSS" and category is BenchmarkCategory.DOM_XSS:
        binding = plan.get("dom_binding")
        source = runtime.domxss_store.get_candidate(candidate.target_id,
                                                    candidate.source_id)
        asset = runtime.domxss_store.candidate_asset(candidate.target_id,
                                                     candidate.source_id)
        boundary, object_type, protocol, method = (
            "CLIENT_SERVER_TRUST", "BROWSER_DOCUMENT", "DOM", "GET")
    elif candidate.source_kind == "POSTMESSAGE" and category is BenchmarkCategory.POSTMESSAGE:
        binding = plan.get("message_binding")
        source = runtime.postmessage_store.get_candidate(candidate.target_id,
                                                         candidate.source_id)
        asset = runtime.postmessage_store.current_asset(candidate.target_id,
                                                        candidate.source_id)
        boundary, object_type, protocol, method = (
            "CROSS_ORIGIN", "BROWSER_MESSAGE_PORT", "POSTMESSAGE", "MESSAGE")
    else:
        return None
    if not isinstance(binding, dict) or source is None or asset is None:
        return None
    route = binding.get("route_url")
    asset_url = binding.get("asset_url")
    if (binding.get("candidate_id") != candidate.source_id or
            hypothesis.surface_key != "js:" + candidate.source_id or
            hypothesis.boundary != boundary or
            asset.state != "CURRENT" or asset.recon_sha256 != asset.artifact_sha256 or
            not isinstance(route, str) or source.route != route or
            not isinstance(asset_url, str) or
            hashlib.sha256(asset_url.encode()).hexdigest() != asset.asset_url_sha256):
        return None
    path = urlsplit(route).path
    if not path or path == "/" or urlsplit(route).query or urlsplit(route).fragment:
        return None
    return f"{method} {path}", boundary, object_type, protocol


def _graphql_finding_root(runtime: object, candidate: object,
                          plan: dict[str, object], finding: object,
                          boundary: str) -> tuple[BenchmarkCategory, str, str] | None:
    if (boundary != "TENANT" or finding.category != "API_AUTHORIZATION" or
            plan.get("skill_id") != "api-observed-read"):
        return None
    owned = _graphql_owned_route(runtime, candidate)
    if owned is None:
        return None
    route, object_type, source, operation = owned
    binding = plan.get("api_binding")
    templates = plan.get("request_templates")
    if (finding.object_type != object_type or not isinstance(binding, dict) or
            binding.get("candidate_id") != source.id or
            binding.get("category") != source.category or
            binding.get("operation_id") != operation.id or
            binding.get("version_hash") != operation.version_hash or
            binding.get("field_path") != (source.field_path or "") or
            not isinstance(templates, list) or not templates or
            not isinstance(templates[0], dict) or
            templates[0].get("binding") != "API_OBSERVED_READ_V1" or
            templates[0].get("source_exchange_id") != source.owner_exchange_id or
            templates[0].get("test_object_id") != source.test_object_id or
            templates[0].get("operation_id") != operation.id or
            templates[0].get("field_path") != (source.field_path or "")):
        return None
    category = (BenchmarkCategory.GRAPHQL_FIELD_AUTH if source.category == "FIELD_AUTH"
                else BenchmarkCategory.GRAPHQL_OBJECT_AUTH)
    return category, route, "HTTP"


def _candidate_root(runtime: object, candidate: object, hypothesis: object | None,
                    category: BenchmarkCategory,
                    plan: dict[str, object] | None = None) -> str:
    """Normalize only a pre-planning, exact owned-traffic/object relationship."""
    raw_key = candidate.root_cause_key
    browser = _browser_root(runtime, candidate, hypothesis, plan, category)
    if browser is not None:
        operation, boundary, object_type, protocol = browser
        return structured_root_fingerprint(category, operation, boundary,
                                           object_type, protocol)
    if (candidate.source_kind == "API_GRAPHQL" and
            category in {BenchmarkCategory.GRAPHQL_OBJECT_AUTH,
                         BenchmarkCategory.GRAPHQL_FIELD_AUTH}):
        owned = _graphql_owned_route(runtime, candidate)
        if owned is None:
            return raw_key
        route, object_type, _, _ = owned
        return structured_root_fingerprint(
            category, route, "TENANT", object_type, "HTTP")
    if candidate.source_kind == "AUTHORIZATION":
        source = runtime.authorization.ledger.get_candidate(candidate.source_id,
                                                             candidate.target_id)
        if source is None:
            return raw_key
        boundary = ("TENANT" if source.boundary.value in {
            "CROSS_TENANT", "GRAPHQL_OBJECT", "GRAPHQL_MUTATION"} else
            "ROLE" if source.boundary.value in {"VERTICAL", "HIDDEN_FUNCTION"} else
            "AUTHENTICATED" if source.boundary.value == "ANONYMOUS" else "OBJECT")
        if hypothesis is not None and hypothesis.boundary != boundary:
            return raw_key
        item = runtime.objects.get(source.test_object_id, candidate.target_id)
        exchange = runtime.traffic.get_exchange(source.owner_exchange_id)
        if (item is None or not item.verified_at or exchange is None or
                exchange.response is None or exchange.response.record.status_code != 200 or
                exchange.attribution.verified_identity_id != source.owner_identity_id or
                item.creator_identity_id != source.owner_identity_id or
                exchange.package_id != item.package_id):
            return raw_key
        recipe = runtime.object_factory.recipes.get(item.package_id, item.recipe_id)
        if (recipe is None or recipe.sha256 != item.recipe_hash or
                recipe.target_id != candidate.target_id):
            return raw_key
        try:
            external = runtime.object_factory._external_id(item)
            observed = runtime.authorization._request_url(exchange, runtime.store)
        except (ValueError, PermissionError, UnicodeError):
            return raw_key
        method = exchange.request.record.method
        if observed is None:
            return raw_key
        if (method == recipe.verify.method and
                observed == recipe.verify.url.replace("{object_id}", external)):
            route = recipe.verify.url
        else:
            matches = [entry for entry in recipe.mutations if
                       entry.write.method == method and
                       observed == entry.write.url.replace("{object_id}", external)]
            if len(matches) != 1 or not exchange.request.body_evidence_id:
                return raw_key
            route = matches[0].write.url
        return structured_root_fingerprint(
            category, f"{method} {_authorization_path(urlsplit(route).path, boundary)}",
            boundary, item.object_type, "HTTP")
    if candidate.source_kind != "EXPOSURE" or hypothesis is None:
        return raw_key
    source = runtime.exposure.store.get(candidate.target_id, candidate.source_id)
    if source is None or source.source.value != "TRAFFIC":
        return raw_key
    objects = runtime.objects.list_for_target(candidate.target_id, limit=50)
    if objects.next_cursor is not None:
        return raw_key
    matches: dict[str, object] = {}
    for link in runtime.exposure.store.source_links(candidate.target_id,
                                                    candidate.source_id):
        exchange = runtime.traffic.get_exchange(str(link["source_ref"]))
        if (exchange is None or exchange.response is None or
                exchange.response.record.status_code != 200 or
                exchange.request.record.method != "GET" or
                not exchange.attribution.verified_identity_id):
            continue
        for item in objects.items:
            if (item.package_id == exchange.package_id and item.verified_at and
                    item.creator_identity_id == exchange.attribution.verified_identity_id and
                    exchange.request.observation_evidence_id in
                    item.verification_evidence_ids):
                matches[item.id] = item
    if len(matches) != 1:
        return raw_key
    item = next(iter(matches.values()))
    recipe = runtime.object_factory.recipes.get(item.package_id, item.recipe_id)
    if recipe is None or recipe.sha256 != item.recipe_hash:
        return raw_key
    return structured_root_fingerprint(
        category, f"{recipe.verify.method} {urlsplit(recipe.verify.url).path}",
        hypothesis.boundary, item.object_type, "HTTP")


def collect_case_trace(runtime: object, case_id: str, campaign: Campaign,
                       started_at: str, finished_at: str) -> CaseTrace:
    """Follow stored links. No Finding is synthesized from candidate or status text."""
    target_id = campaign.target_id
    works = runtime.campaign.store.works(target_id, campaign.id)
    planner_ids = tuple(work.child_id for work in works
                        if work.kind is CampaignWorkKind.PLANNER and work.child_id)
    candidates: list[ObservedCandidate] = []
    findings: list[ObservedFinding] = []
    plan_ids: set[str] = set()
    executed_ids: set[str] = set()
    validation_ids: set[str] = set()
    hypothesis_times: list[str] = []
    plan_times: list[str] = []
    confirmation_times: list[str] = []
    global_rank = 0
    for planner_id in planner_ids:
        planner = runtime.planner_store.get(target_id, planner_id)
        if planner is None or planner.candidate_count > 200:
            raise ValueError("Benchmark planner record unavailable or truncated")
        for candidate in runtime.planner_store.candidates(
                target_id, planner_id, limit=200):
            global_rank += 1
            hypothesis = (runtime.hypotheses.get(candidate.hypothesis_id, target_id)
                          if candidate.hypothesis_id else None)
            if hypothesis is not None:
                hypothesis_times.append(hypothesis.created_at.isoformat())
            plan = (runtime.skill_plans.get(candidate.plan_id, target_id)
                    if candidate.plan_id else None)
            if candidate.plan_id and plan is not None:
                plan_ids.add(candidate.plan_id)
                created = plan.get("created_at")
                if isinstance(created, str):
                    plan_times.append(created)
            plan_run = (runtime.run_store.get(candidate.plan_run_id, target_id)
                        if candidate.plan_run_id else None)
            executed = bool(plan_run and plan_run.started_at)
            if executed:
                executed_ids.add(plan_run.id)
            validation = (runtime.validations.get(candidate.validation_id, target_id)
                          if candidate.validation_id else None)
            if validation is not None:
                validation_ids.add(validation.id)
            selected_skill = plan.get("skill_id") if plan else None
            skill_ids = tuple(dict.fromkeys((*candidate.skill_ids,
                                             *((selected_skill,) if
                                               isinstance(selected_skill, str) else ()))))
            category = _candidate_category(runtime, candidate)
            candidates.append(ObservedCandidate(
                candidate_id=candidate.id, category=category,
                specialist=candidate.specialist.value, skill_ids=skill_ids,
                rank=global_rank, root_fingerprint=_candidate_root(
                    runtime, candidate, hypothesis, category, plan),
                provenance=CandidateProvenance.DETERMINISTIC,
                hypothesis_id=candidate.hypothesis_id, plan_id=candidate.plan_id,
                executed=executed, validated=validation is not None,
                engine_root_fingerprint=candidate.root_cause_key))
            if not candidate.finding_id:
                continue
            finding = runtime.validations.get_finding(candidate.finding_id, target_id)
            if (finding is None or validation is None or plan_run is None or
                    hypothesis is None or plan is None or
                    validation.status is not ValidationStatus.CONFIRMED or
                    validation.source != "DETERMINISTIC" or
                    finding.status in {FindingStatus.DUPLICATE, FindingStatus.INFORMATIVE}):
                continue
            chain = (
                finding.target_id == target_id == validation.target_id == plan_run.target_id
                == hypothesis.target_id == planner.target_id and
                finding.validation_id == validation.id == candidate.validation_id and
                finding.hypothesis_id == validation.hypothesis_id == plan_run.hypothesis_id
                == hypothesis.id == candidate.hypothesis_id and
                validation.run_id == plan_run.id == candidate.plan_run_id and
                validation.plan_id == plan_run.plan_id == candidate.plan_id == plan.get("id") and
                plan.get("hypothesis_id") == hypothesis.id and
                candidate.run_id == planner_id and
                validation.supporting_evidence_ids and finding.evidence_ids)
            projected = _graphql_finding_root(
                runtime, candidate, plan, finding, hypothesis.boundary)
            browser = _browser_root(runtime, candidate, hypothesis, plan,
                                    _category(finding.category))
            if (browser is not None and finding.object_type == browser[2]):
                operation, boundary, object_type, protocol = browser
                category = _category(finding.category)
            elif projected is None:
                operation, protocol = _operation(runtime, target_id, plan,
                                                 hypothesis.surface_key, hypothesis.boundary)
                category = _authorization_category(finding.category,
                                                   hypothesis.boundary, plan)
            else:
                category, operation, protocol = projected
            object_type = finding.object_type or "UNKNOWN"
            boundary = hypothesis.boundary
            findings.append(ObservedFinding(
                finding_id=finding.id, validation_id=validation.id,
                plan_run_id=plan_run.id, planner_run_id=planner_id,
                campaign_id=campaign.id, hypothesis_id=hypothesis.id,
                category=category, operation=operation,
                boundary=boundary, object_type=object_type,
                protocol=protocol,
                root_fingerprint=structured_root_fingerprint(
                    category, operation, boundary, object_type, protocol),
                engine_root_fingerprint=finding.root_cause_fingerprint,
                audit_complete=bool(chain), evidence_count=len(finding.evidence_ids),
                control_count=len(validation.controls_evaluated),
                demonstrated_impact=bool(validation.demonstrated_impact and
                                         finding.demonstrated_impact),
                reproduction_count=validation.reproduction_count))
            confirmation_times.append(finding.created_at)
    usage = CaseUsage(requests=campaign.usage.requests,
                      browser_actions=campaign.usage.browser_actions,
                      research_requests=campaign.usage.research_requests)
    return CaseTrace(
        case_id=case_id, campaign_id=campaign.id,
        candidates=tuple(candidates), findings=tuple(findings), usage=usage,
        started_at=started_at, finished_at=finished_at,
        planner_runs=len(planner_ids), plans_generated=len(plan_ids),
        plans_executed=len(executed_ids), validations=len(validation_ids),
        first_hypothesis_at=min(hypothesis_times) if hypothesis_times else None,
        first_plan_at=min(plan_times) if plan_times else None,
        first_confirmation_at=min(confirmation_times) if confirmation_times else None,
        failure_reason=(None if campaign.status.value == "COMPLETED"
                        else campaign.status.value))
