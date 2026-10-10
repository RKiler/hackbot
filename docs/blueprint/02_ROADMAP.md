# Implementation Roadmap

Codex must implement these phases sequentially. Do not jump to autonomous hunting before foundations work.

## Phase 0 - VPS and recon discovery

Inspect `/root/enhanced_recon_framework`, Docker, DB schema/access code, target/scope storage, JS/endpoints/history, notifications and any saved HTTP traffic.

Deliver:
- `docs/EXISTING_INFRASTRUCTURE.md`
- `docs/RECON_INTEGRATION.md`
- `docs/PHASE0_RECOMMENDATIONS.md`

No production modifications.

## Phase 1 - Project foundation

Implement config, logging, CLI skeleton, testing, persistence conventions and health/status commands.

## Phase 2 - Read-only recon adapter

Expose stable interfaces for targets, hosts, endpoints, parameters, JS, JS analysis, source maps, GraphQL evidence and deltas.

## Phase 3 - Evidence and fact store

Immutable evidence IDs, content hashes, references and normalized facts with confidence/evidence links.

## Phase 4 - Core domain model

Target, Host, Endpoint, Parameter, Principal, Role, Tenant, ObjectReference, RequestRecord and ResponseRecord.

## Phase 5 - Identity registry

Account metadata, roles, tenant relationships and secret references.

## Phase 6 - SecretProvider + AuthContext

Secrets remain outside model prompts. AuthContext represents complete request identity.

## Phase 7 - Browser/session manager

Imported sessions, browser-assisted login, isolated contexts, session health and reauth-required state. Never bypass MFA/CAPTCHA.

## Phase 8 - Authenticated traffic attribution

Associate traffic with principal, role, tenant, endpoint and object where inferable.

## Phase 9 - Target profiler and normal-behaviour learner

Learn technologies, features, UI/API capabilities, legitimate workflows, roles, object ownership and trust boundaries.

## Phase 10 - Target ontology + object registry

Represent application objects and relationships: organization -> project -> dashboard, etc.

## Phase 11 - Hypothesis engine

Structured lifecycle: NEW, ENRICHING, READY, TESTING, VALIDATING, CONFIRMED, REJECTED, NEEDS_MANUAL_REVIEW, BLOCKED.

## Phase 12 - Task dependency graph

Persist prerequisites, branches, retries, backtracking and resumable research tasks.

## Phase 13 - Scope/risk/rate policy

ScopeGuard, RiskPolicy, RatePolicy, MethodPolicy, TargetPolicy. Return ALLOW, DENY or REQUIRE_APPROVAL.

## Phase 14 - Traffic executor

Controlled `search/get/replay/mutate/compare/batch_compare` APIs. Identity resolution happens below the LLM layer.

## Phase 15 - Skill engine

Implement SkillRegistry, metadata-only discovery, router, prerequisite checker, scorer, loader, context builder and metrics.

Skill sources:
- `skills/core/` custom high-quality bounty skills;
- `skills/imported/` curated public skills;
- `skills/personal/` generalized methods learned from successful research.

## Phase 16 - ResearchCoordinator

Trigger research only for knowledge gaps. Produce cached, source-backed ResearchBriefs and optional target-specific ephemeral skills.

## Phase 17 - Static-analysis layer

Deterministically index JS/source maps/traffic for APIs, GraphQL operations, message handlers, sources, sinks, decoders, configs and interesting strings.

## Phase 18 - ObjectFactory + side-effect classifier

Find or safely create disposable owned test objects. Track creator, tenant, purpose and cleanup. Classify operations by side effect.

## Phase 19 - Authorization specialist + validator

First real hunting specialist. Use known principals, roles, tenants, objects and controls for BAC/BOLA/IDOR/BFLA tests.

## Phase 20 - GraphQL authorization capability

Mine operations from JS/traffic, correlate hidden operations, construct requests, resolve prerequisites and test object/field/mutation/nested authorization.

## Phase 21 - DOM XSS specialist

Check-before-transform source -> validation -> transformation -> sink methodology, with browser execution proof.

## Phase 22 - postMessage / MessagePort specialist

Model full cross-origin protocols, origin/source checks, transferred ports, RPC methods and unauthorized capabilities.

## Phase 23 - Sensitive exposure specialist

Identify and safely verify secrets, internal surface, debug/admin endpoints and source-map/config disclosures.

## Phase 24 - Planner / orchestrator

Retrieve minimal context, rank hypotheses, route skills, budget tokens/requests, dispatch agents, backtrack and invoke validators.

## Phase 25 - Notifications and reporting

Notify on confirmed findings and high-value manual-review candidates. Generate reports only from evidence.

## Phase 26 - Delta hunter / campaign mode

Watch recon changes and analyze only new/changed hosts, endpoints, parameters, JS, GraphQL operations and permission behaviour.

## Phase 27 - Evaluation harness

Use local/recorded vulnerable cases. Measure precision, recall, false-positive rate, requests/finding, tokens/hypothesis, manual interventions and confirmed-findings yield.

## V1 completion gate

Do not call V1 successful until the system can:

1. ingest recon context;
2. authenticate multiple identities safely;
3. learn target roles/objects;
4. generate one bounded hypothesis;
5. select one skill;
6. resolve prerequisites;
7. run one permitted experiment;
8. validate it independently;
9. persist evidence and classification;
10. resume correctly after restart.
