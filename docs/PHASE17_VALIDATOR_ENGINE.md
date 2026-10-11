# Phase 17: Deterministic Vulnerability Validator Engine

## Boundary and contract

`DeterministicValidatorEngine` judges a completed `PlanRun`; it has no
`TrafficExecutor`, browser driver, policy-permit writer, or model dependency.
Validation does not dispatch requests, collect new evidence, or alter target
state. The typed `Validator` protocol receives a frozen `ValidationContext`
containing the run, saved plan, ordered control/boundary observations, evidence
snapshot hash, and skill criteria. `ValidatorRegistry` binds the saved skill
identifier to a versioned implementation. The plan snapshot must contain its
required validator set; legacy plans without the frozen contract return
`INSUFFICIENT_EVIDENCE`.

`ValidationResult` is immutable and records target/run/plan/hypothesis,
skill ID/version/content hash, validator ID/version, source, status,
confidence band, plan/evidence snapshot hashes, supporting and contradicting
Evidence IDs, controls and criterion outcomes, impact, reproduction count,
limitations, reason codes, and a safe summary. A new decision for changed
evidence supersedes the previous result; equal deterministic snapshots are
idempotent. Manual reviews are separately marked `MANUAL` and cannot create a
confirmed finding.

Statuses are `CONFIRMED`, `REJECTED`, `NEEDS_MANUAL_REVIEW`,
`INSUFFICIENT_EVIDENCE`, `INVALID_TEST`, and `DUPLICATE_CANDIDATE`.
`CONFIRMED` requires all recorded checks to pass and supporting Evidence;
`INVALID_TEST` means a required control or execution context failed.
Uncertainty never becomes confirmation. A denied boundary is `REJECTED`
only after the owner and negative controls are valid. A single successful
boundary observation is manual review, not a reproducible finding.

## Evidence gates

Each traffic observation is traced from its runtime step to a completed
TrafficExchange, `REQUEST_SENT` executor event, consumed exact-action permit,
allow/in-scope policy decisions, current run target/package, and matching
anonymous or verified authenticated session attribution. Scope or audit gaps
fail closed. Ownership/tenant/role/visibility claims require active,
high-confidence, target-bound, Evidence-linked Facts plus observed identity
registry relationships. Manual Facts do not establish a deterministic
boundary. The original Evidence artifact remains access-controlled; API and
dashboard return references, hashes, classifications, and safe summaries,
not response bodies, cookies, or secret values.

The Fact source/evidence contract is a provenance gate, not independent
semantic proof of arbitrary asserted content. Upstream producers and any
researcher importing Facts must preserve truthful attribution. A confirmed
finding still requires an independently captured protected response and
negative controls. If ownership or public/shared status is unknown, the
validator returns insufficient evidence rather than guessing.

`ResponseComparator` compares status, content type, retained body hash and
size, request path/shape, normalized JSON hash, GraphQL `data` and `errors`,
and SHA-256 fingerprints of selected object/tenant IDs. JSON parsing is
bounded, rejects duplicate keys, and checks retained bytes against the
recorded response hash. Only explicit JSON-pointer-like volatile paths may
be ignored; identity, tenant, `data`, and `errors` fields cannot be suppressed.
It does not send sensitive bodies to a model or API.

## Implemented validators

| Family | Required positive and negative controls | Confirmation / limitation |
| --- | --- | --- |
| Cross-tenant BOLA | Owner 2xx, invalid-object denial, observed separate tenants, private object owned by owner's tenant | Same protected non-HTML GET/HEAD body and object identity to foreign tenant twice. |
| Horizontal IDOR | Same-tenant distinct observed principals, owner-only object, owner and invalid-object controls | Same protected body/object to foreign principal twice. |
| Vertical role and hidden function | Same tenant, verified higher/lower roles, evidence-backed required role, owner and invalid-object controls | Protected read from lower role twice. UI absence or status alone is insufficient. |
| Anonymous download / sensitive data | Verified authenticated owner, truly anonymous boundary, private classification, invalid-object control | Equivalent protected non-HTML artifact twice. Credential-like content additionally needs cleartext and first-party relevance Facts; sample data is rejected. |
| GraphQL object authorization | Known operation, tenant/object facts, owner semantic `data`, invalid-object semantic denial | Foreign semantic `data` with matching object twice; HTTP 200 containing only errors is not impact. |
| GraphQL mutation | Same controls, plus durable effect evidence | Returns manual review: Phase 16 has no independently attested state readback. |
| DOM XSS / postMessage | Browser execution/capability, source and trust path, benign/negative controls, fresh context | Returns insufficient evidence until a trustworthy browser-proof record exists. Static sinks/listeners never confirm. |
| Internal surface | Current external reachability and sensitive functionality | Returns manual review; validation sends no VHOST/Host-header requests. |

Read-only protected-content confirmation is intentionally narrow. State-changing
authorization, open redirect, and broader client-side validation remain
unconfirmed without independently attested durable effect or browser proof.
The validator never uses discovered credentials or performs external login.

## Findings and deduplication

Schema 13 stores append-only validations/checks, findings, Evidence links,
locations, duplicate-validation links, and finding status events. `Finding`
exists only after a deterministic confirmed result. It stores demonstrated
impact separately from potential impact, and severity is not auto-assigned.
The root-cause fingerprint covers target, category, operation/helper key,
and object type. An evidence-backed `root_cause_key` may group multiple
routes; without it, the method/origin/path template is the conservative
fallback. A matching root cause creates `DUPLICATE_CANDIDATE` linked to the
original finding and adds affected locations/Evidence without awarding a new
finding. Finding lifecycle states beyond `CONFIRMED` are reserved for later
researcher workflow; no submission automation exists.

Audit path: Finding -> ValidationResult -> PlanRun -> immutable plan and
skill version/hash -> Hypothesis -> checks/Evidence/TrafficExchange ->
executor event -> permit/approval (when required) -> policy decisions.
Rejected validations retain structured reason codes for future skill metrics.
Counters expose validator runs, confirmed, rejected, manual review,
insufficient, invalid, duplicates, findings, and recent reason frequencies.
They do not automatically change skill routing.

## Operator surface

The private service exposes target-scoped validation/finding list and detail
routes and explicit `POST /v1/runs/{id}/validate`. The authenticated recon
dashboard gateway provides `/api/hackbot/validations`,
`/api/hackbot/findings`, and the run validation action with its existing CSRF
gate. The UI has separate Hypotheses, Validations, and Confirmed Findings
sections; detail views show controls, checks, impact, Evidence IDs, run links,
and duplicate relationships. It never renders raw sensitive artifacts.
Completed runs require explicit validation; no queue, automatic request,
notification, or report submission was added.

## Verification and next phase

The tests use policy-gated loopback fixtures only, including BOLA positive and
denied, public-resource rejection, horizontal/vertical/hidden-function,
anonymous file, GraphQL semantic data, invalid controls, sample credentials,
duplicate root cause, append-only rows, private API target scoping, redacted
metadata, and zero validator network dispatch. Existing Phase 1-16 tests
remain the regression suite. Production BugHunter SQLite must be backed up
with SQLite's online backup operation before schema migration; recon
PostgreSQL is not part of this migration.

Phase 18 should implement the roadmap's ObjectFactory and side-effect
classifier: discover or safely create disposable owned objects, persist
creator/tenant/purpose/cleanup state, classify operation effects, and attach
target-scoped before/after readback Evidence for reversible fixture changes.
It must preserve the policy/permit boundary and cannot let a model override
the validator result. Fresh browser execution/capability proof for DOM XSS
and postMessage remains a later specialist-phase requirement.
