# Phase 19: Authorization Specialist

## Boundary

The specialist is a target-package-scoped planner and coordinator. It has no
network client. BugHunter owns its hunt, candidate, and observation records in
SQLite migration 015. Production recon remains read-only and is never an
authorization source. No candidate, HTTP status, UI omission, or matrix entry
is a finding; only the Phase 17 deterministic validator can confirm one.

The private BugHunter service exposes target-scoped metadata through the
existing dashboard gateway. The gateway supplies browser authentication and
CSRF protection for mutations; the service stays on its private Unix socket.

## Model And Matrix

`AuthorizationSurface` joins at most 12 active identities, 30 verified
disposable objects, and 50 recent exchanges (40 matching operations). Actors
carry observed principal, membership, role, and verified-session state.
Objects require creation, tenant, and disposable Facts plus a verified
ObjectFactory read-back and secret Evidence-held external ID. Operations are
included only if a verified owner exchange references that exact ID and the
response semantically matches it. GraphQL operations use retained original
request bodies and one object-ID variable; a status-only 200 is insufficient.

The serialized profile includes role-operation and coarse role-feature maps
of *observed* traffic. Missing traffic is not a denial or proof of unavailable
functionality. Parent IDs are preserved; no parent-child mismatch request is
automatically dispatched without a verified operation template and both
ownership relationships.

`authorization_observations` persists sparse, target-scoped matrix rows with
actor, principal, tenant, role, object, operation, result, exchange, and
Evidence references. Results distinguish allowed, denied, auth-required,
not-found, ambiguous, and unknown. HTTP 200 with GraphQL authorization errors
and no data is a denial, not an allowed result.

## Candidate And Plan Flow

Candidate generation compares verified owner traffic with meaningful actor
pairs: cross-tenant, same-tenant/different-principal, verified role restriction,
an observed internal surface, or anonymous access to a protected artifact.
GraphQL query/mutation signals are distinguished. It ranks the bounded pool
before the per-hunt cap and deduplicates by target, boundary, object, operation,
and actor. Missing sessions, ownership, or legitimate controls become explicit
prerequisites; identifiers are never guessed or sequentially enumerated.

For read experiments, `prepare` routes through Phase 15 skills and binds
immutable references to observed owner requests and verified test objects.
The plan contains no raw application IDs or captured credentials. The dispatch
resolver rechecks package scope, ownership Facts, reservation, source exchange,
body/hash, and current session. The executor supplies current authentication.
Controls run before boundary requests: owner object, foreign-owned object when
required, invalid object, and two bounded boundary reproductions. Anonymous
uses no fake identity. GraphQL query POSTs require Phase 13 exact-action
approval because their side effect cannot be inferred from the HTTP method.

`BOUNDED_AUTONOMOUS` additionally requires target policy ALLOW for automated,
bounded, and cross-identity testing. It stops and pauses on an approval or
uncertain run, and stops after a confirmed proof. The default is `PLAN_ONLY`.
Interrupted dispatches reconcile through Phase 16 without replay and surface
manual review. Per-hunt metrics include candidate/plan/run/validation counts,
requests consumed, specialist-created objects, and orphaned cleanup objects.

The specialist cannot convert an observed 200 into a finding. Validation
requires a current audited run, owner/negative controls, trusted relationship
Facts, protected data, and two reproductions for read disclosure. The narrow
GraphQL rename mutation path requires an observed one-ID/one-name request,
one plain rename field and no aliases, fragments, or second operation,
verified disposable object, independent owner GET before and after one
approved foreign-actor mutation, a non-existent-ID negative control, and
a changed final name matching the submitted value. HTTP 200 with GraphQL
errors or a success-shaped no-op cannot confirm. The
`Finding -> Validation -> PlanRun -> Plan -> Skill -> Hypothesis -> observations
-> Traffic/Evidence -> Policy/Permit` references are retained for drill-down.
Object reservations are released by the orchestrator. ObjectFactory cleanup
remains a separately budgeted action. The specialist links only objects it
created for a hunt and attempts their known automatic cleanup after a terminal
or cancelled hunt. Reused/pre-existing fixtures are never deleted by that
path. Pending approvals and orphaned objects remain visible in metrics; they
are not silently marked cleaned.

## Safety And Current Limits

- REST exact object-path GET/HEAD, GraphQL single-ID query, protected
  anonymous GET/HEAD, and the narrowly typed GraphQL rename mutation have
  dispatch bindings. Query parameters, headers, nested object IDs, arbitrary
  mutation types, and batched inputs have no automatic binder yet.
- Other GraphQL mutations remain `NEEDS_MANUAL_REVIEW`. Neither a mutation
  response nor a Fact alone proves a durable unauthorized state change. The
  rename path still requires exact-action approval; no delete is dispatched.
- Same-actor/different-object comparisons are represented by horizontal or
  cross-tenant controls. Parent-child mismatches enter manual review only when
  an observed nested owner request and read-back establish the relationship;
  there is no automatic nested-ID binder. Their absence from the automatic
  queue is not a secure result.
- ObjectFactory can resolve a missing foreign comparison object only from a
  known target-bound recipe when creation policy is ALLOW. It does not infer
  recipes from recon or create accounts, tenants, or real-user objects.
- The dashboard never exposes raw secret Evidence. No public internet
  research, payload fuzzing, direct specialist networking, or model call is
  part of this phase.

## Interfaces

`GET /v1/authorization/<package>/profile|hunts|candidates|matrix|metrics`
return bounded metadata. `POST .../hunts`, `.../candidates/<id>/prepare|start|advance`,
and `.../hunts/<id>/pause|cancel` are gateway-protected control actions. A
dashboard Authorization view shows identities, tenants/roles, owned objects,
candidate reasons, plans/runs/validations, and matrix observations.

## Phase 20 Recommendation

Extend the typed before/mutation/read-back contract beyond the one-field
GraphQL rename to approved REST updates and other explicitly known mutations.
Require cleanup/read-back evidence in the resulting report workflow. Then add
parent-child and batch bindings with the same exact-reference and budget
rules; do not loosen the current proof gates for broad mutation replay.
