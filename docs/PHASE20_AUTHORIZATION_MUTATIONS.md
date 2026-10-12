# Phase 20: Typed Authorization Mutations

Phase 20 extends the Phase 19 Authorization Specialist with three bounded paths:
recipe-pinned rename mutations, nested parent/child reads, and mixed-ownership
batch reads. Production recon remains a read-only discovery source. All active
requests still pass through the Target Package, Phase 13 policy, Phase 14
TrafficExecutor, and Phase 16 PlanRun; tests use local loopback fixtures only.

## TypedMutation and MutationRecipe

`TypedMutation` is a data-only record of the target, operation, disposable
object, creator, actor, tenant, type, allowlisted field, deterministic value,
expected read-back, cleanup strategy, side-effect class, recipe hash, and
Evidence references. It has no raw-body or network method. Only `RENAME` of
`name` is executable in this phase. Other enum values reserve vocabulary for
reviewed future recipes; they cannot be dispatched. Account, role, tenant,
billing, payment, and arbitrary patch fields are not allowed.

An operator-reviewed `MutationRecipe` fixes one REST PATCH/PUT or one strictly
parsed GraphQL POST operation. GraphQL variables are exactly `id` and `name`;
the operation document/name are pinned. The recipe also fixes an independent
owner GET, JSON pointer to the field, restore operation, safe side-effect class,
and optional `X-CSRF-Token` requirement. Recipe bytes are hashed; changes make
existing plans stale. Values are deterministic `hackbot-test-<hash>` labels, not
model-generated payloads. Duplicate JSON keys are rejected.

Before dispatch the binder rechecks scope, current recipe hash, external ID
integrity, verified ownership Facts, disposable state, tenant, and the run's
exclusive reservation. A real, unknown, unverified, or unreserved object fails
closed. Phase 13 classifies each action anew; approvals are handled by Phase 16,
and the executor issues a fresh one-use permit. A trusted `TokenResolver` may
inject the recipe-declared CSRF header only inside the executor after policy and
authentication checks. No resolver or an invalid token blocks the mutation;
captured stale tokens are never reused. Browser-only mutations remain blocked.

## Read-Back, Restore, and Evidence

The seven-stage plan is: owner GET before state; owner mutation; owner GET;
boundary mutation; trusted owner GET; restore; trusted owner GET. Each request
consumes a plan and target rate budget slot. Mutation results persist action and
TrafficExchange IDs, read-back IDs, Evidence references, before/after value
fingerprints, ambiguity, and verification status, without storing raw values or
tokens in the mutation ledger. An owner-control failure stops the boundary
attempt. An HTTP 200 or GraphQL data wrapper never proves a changed state.

If a write may have been sent but its response is lost, the orchestrator never
retries it. It permits one fresh, policy-gated owner read-back if budget remains,
then pauses for human review. Failed or unclear read-back cannot confirm. The
restore is another active, policy-gated request and must have a final GET proof.
A failed restore persists a cleanup warning and pauses the run. Existing
ObjectFactory cleanup still owns disposition of the disposable fixture.
On restart, recovered runs reconcile pending mutation records to ambiguous or
insufficient-evidence states; they are never replayed automatically.

The deterministic validator requires a valid audit chain from plan/run/steps
through policy, permit, Traffic, Evidence, MutationResult, and verified object
ownership. It checks owner control, independently observed boundary effect,
permission/tenant/role expectations, state chain, and restore. A denied/no-op
boundary is rejected; insufficient or ambiguous proof remains review-only.
Equivalent mutations stop after the bounded proof rather than spraying variants.

## Nested and Batch Reads

Nested binding accepts only an observed owner request whose response proves the
parent-child relationship. Both IDs come from known, verified disposable
ObjectRegistry entries with ownership Facts. The binder changes only the
parent ID to a known foreign parent and rechecks the template hash and scope.
Validation needs protected child content in the unauthorized response; an
ignored but redundant parent field is not automatically a bug.

Batch binding accepts an observed exact two-ID GET path and constructs one
mixed batch with an acting-tenant object and a known foreign object. The model
has a configurable hard cap of 2-5, default 3; Phase 20's executable batch
path is stricter and uses exactly two IDs. Per-object protected data in the
response is required; aggregate HTTP status or array length is not proof.
State-changing batch operations, arbitrary arrays, and ID enumeration are not
implemented, so no batch cleanup path is needed in this phase.

## API and Dashboard Boundary

The private BugHunter API exposes test type and read-back status on
authorization candidates, bounded mutation/nested/batch metrics, object
mutation state and latest read-back references, and run mutation/restore
history. A run also exposes a typed approval summary: disposable object,
allowlisted field/action, acting identity, risk, state, and short before/after
hashes. There is no generic object-edit or raw mutation endpoint. The existing
authenticated, CSRF-protected recon dashboard gateway is unchanged; its
Authorization, Objects, Runs, and Approvals views consume the new metadata.
Only the gateway's HTML/JavaScript source is updated; no production service is
restarted by this phase.

## Deferred Work and Phase 21

This phase does not add arbitrary writes, browser execution, state-changing
batch operations, target accounts, active bounty tests, model calls, or a new
specialist. Dynamic per-target CSRF resolvers and mutation approval as an
independent authorization grant need separately reviewed implementations.

Recommended Phase 21 task: implement the roadmap's DOM XSS specialist with a
small, policy-gated browser execution/proof contract for current-page
source-to-sink validation. Add a trusted target-specific rotating-token
resolver only if that work needs one. Preserve the current policy, permit,
reservation, redaction, and proof gates; do not introduce a general request
editor or arbitrary mutation API.
