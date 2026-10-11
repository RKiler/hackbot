# Phase 15: Policy-Gated Security Skill Engine

## Scope and Boundary

Skills are methodology, not permission, execution, or validation. Phase 15 routes evidence-linked hypotheses to a small catalog, builds bounded context, evaluates prerequisites, and persists immutable investigation plans. It sends no target traffic, creates no confirmed findings, and performs no public research. Recon remains read-only and Target Packages remain the only active-testing scope authority.

## Catalog Format

The package catalog lives under `src/hackbot/skill_catalog/` with `core/{authorization,client-side,api,exposure}/<id>/SKILL.md`, plus empty `imported/` and `personal/` namespaces. `[skills] root` in TOML may point to a separate absolute catalog for researcher-authored skills. Future `EPHEMERAL` source metadata is reserved; no skill generator exists yet.

Each `SKILL.md` uses YAML frontmatter with Agent-Skills-compatible `name` and `description`, plus `category`, classes, uppercase triggers, prerequisites, risk, validator names, bounded request/token budgets, semantic version, source, and `execution_mode: PLAN_ONLY`. `when_to_use`, `when_not_to_use`, and alternatives reduce collisions. A selected skill has methodology prose and a fenced `yaml` `## Plan` block with typed workflow steps, controls, positive/negative signals, evidence and confirmation requirements, rejection conditions, and bounded action intents. This block is parsed as data; no scripts or shell commands are run.

Registry discovery streams at most 8 KiB of frontmatter per file. Only `select()` reads and hashes the complete file (at most 64 KiB) and parses the plan. Invalid IDs, duplicate IDs, unsupported keys/primitives, unknown prerequisites, missing risk, and unbounded budgets fail closed. Imported and personal skills obey the same constraints. The catalog is deliberately eleven curated skills, not a bulk import.

## Routing and Context

`SkillRouter` is deterministic and returns at most five candidates (three by default). It scores category/trigger/tag matches, prerequisite coverage, technology, feature, boundary, risk, and budgets. Metrics are not fabricated; plan counts in the Skills page are derived from local plans. No model is required. A future model may refine or choose candidates, but must remain inside the same bounded structure and policy boundary.

`SkillContextBuilder` reads one target's Hypothesis, matching TargetProfile signals, up to four Evidence pointers, four Fact pointers, four matching TrafficStore exchanges from a recent twelve-exchange sample, and four IdentityRegistry identities with bounded memberships. For selected GraphQL skills it can read two target-scoped read-only recon API-surface metadata rows. It never reads Evidence bodies, raw JS/source maps, request/response bodies, cookies, Authorization headers, or secret values. Recon observations are not scope grants or proof that an asset is live. Missing data stays missing.

`PrerequisiteChecker` returns `READY`, `MISSING_CONTEXT`, `MISSING_IDENTITY`, `MISSING_OBJECT`, `MISSING_TRAFFIC`, `MISSING_RESEARCH`, or `UNSUPPORTED`, plus exact missing/satisfied names. Current verified session status is separate from identity metadata. `READY` only means planning prerequisites are present; it is not execution approval or a finding.

## Plans and Policy

`InvestigationPlan` contains a hypothesis, selected skill ID/version/SHA-256, target, prerequisites, typed steps, controls, proposed actions, safe request-template shapes, positive/negative signals, evidence/confirmation requirements, risk, budgets, status, and creation time. Schema 11 stores a secret-free immutable JSON snapshot in BugHunter SQLite. A unique hypothesis/skill/version/hash/generation key deduplicates ordinary requests; explicit regeneration increments generation and preserves prior plans. A separate bounded selection ledger records later manual selection without rewriting the plan.

Actions are only proposed when a complete, current-session-compatible GET/HEAD template can be formed from safe matching traffic metadata and prerequisites are ready. No query values, auth material, response bodies, or high-entropy path segments are copied. Authorization/GraphQL plans remain planning-only until an exact foreign actor/object binding can be established; the engine never picks an arbitrary session for an authorization test. Every proposed action is evaluated with Phase 13 `PolicyEngine.evaluate(record=False)`; `ALLOW`, `DENY`, and `REQUIRE_APPROVAL` are displayed as simulations. The planner has no reference to a `TrafficExecutor` instance and never issues a permit or request. Future orchestration must re-evaluate current policy and use Phase 14's executor; a saved plan is never an execution capability.

## Initial Skills

| Family | Skills |
| --- | --- |
| Authorization | cross-tenant object, horizontal object, vertical role, hidden function |
| Client-side | check-before-transform DOM XSS, postMessage trust |
| API | GraphQL object, GraphQL mutation |
| Exposure | unauthenticated sensitive download, sensitive data exposure, internal surface candidate |

Authorization skills require known ownership, owned identities, controls, and meaningful protected effect. DOM XSS requires a source-to-validation-to-transform-to-sink trace and later fresh browser execution. postMessage tracks origin/source, port transfer, and privileged capability independently of XSS. GraphQL plans use observed operations without introspection. Internal surface plans are passive; no Host-header or VHOST probing is implemented.

## Dashboard and API

The existing authenticated, CSRF-protected same-origin gateway exposes `/hackbot/skills` and `/hackbot/plans`. Hypothesis detail shows recommendations and a manual skill choice. APIs: `GET /api/hackbot/skills`, `GET /api/hackbot/skills/{id}`, `POST /api/hackbot/hypotheses/{id}/skills/route`, `POST /api/hackbot/hypotheses/{id}/plan`, and `GET /api/hackbot/plans/{id}`. The private service implements corresponding `/v1/*` routes. No upload endpoint exists. JSON responses contain methodology and metadata only; the UI uses text nodes, not HTML injection.

## Phase 16 Handoff

Build an explicit experiment-orchestration layer that consumes an immutable plan, rechecks prerequisites and current Target Package policy, obtains one-use permits, and calls Phase 14 TrafficExecutor. Keep browser proof and validators separate. Do not infer a confirmed bug from plan creation or policy simulation.
