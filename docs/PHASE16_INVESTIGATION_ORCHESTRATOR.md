# Phase 16: Policy-Gated Investigation Plan Orchestrator

## Boundary

The service-owned `PlanOrchestrator` executes one selected Phase 15
`InvestigationPlan` step per explicit advance. Plan creation and run creation
send no target request. Only an `EXECUTE_REQUEST` step with a complete,
unchanged, typed binding can reach the Phase 14 `TrafficExecutor`. The
orchestrator is deterministic and does not confirm vulnerabilities, invoke a
model, crawl applications, create target objects, or run a background campaign.
`COMPLETED` means the plan steps finished; every run reports `UNVALIDATED`.

## Persistence and State

BugHunter SQLite schema 12 adds `plan_runs`, `plan_run_steps`, immutable
`plan_step_results`, append-only `plan_run_events`, and append-only manual
evidence links. The stored Phase 15 JSON is hashed at run creation; a changed
snapshot blocks continuation. New snapshots retain skill category, classes,
prerequisites, version, and full-content hash, so an installed skill revision
does not silently change an existing run. Legacy snapshots need an exact
installed skill hash for prerequisite reconstruction.

Run states are `CREATED`, `READY`, `RUNNING`, `WAITING_APPROVAL`,
`WAITING_HUMAN`, `PAUSED`, `COMPLETED`, `BLOCKED`, `REJECTED`, `FAILED`,
`BUDGET_EXHAUSTED`, and `CANCELLED`; `CHECKING_PREREQUISITES` is reserved.
Step states are `PENDING`, `READY`, `EXECUTING`, `WAITING_APPROVAL`,
`COMPLETED`, `FAILED`, and `BLOCKED`; `WAITING_POLICY`, `SKIPPED`, and
`CANCELLED` are reserved. One run per plan may remain open, and at most one
run globally may claim a step for execution. An explicit rerun creates a new
run only after the previous run reaches a terminal state.

The compiler inserts a current-prerequisite check, then maps the saved
workflow in order. This Phase 15 format has no independent-branch dependency
field, so ordering is the dependency model. Unsupported step types block
with `BLOCKED_UNSUPPORTED`; methodology text is never executed as code.
Controls and boundary steps retain roles and a `control_step_id`. Saved
comparison pairs permit a bounded, metadata-only status/hash comparison;
this is not an authorization or vulnerability validator. An unsuccessful
owner control blocks later steps.

## Current Gates

At start and before every advance, the orchestrator reloads the authoritative
Target Package, hypothesis, current context, prerequisites, and current
identity/session metadata. For an authenticated action, the exact saved
Identity and verified BrowserSession must still match a `VALID` AuthContext;
anonymous actions stay anonymous. Phase 15's saved policy result grants no
execution authority. The Phase 13 policy is evaluated again for the exact
action, then Phase 14 independently re-evaluates it at permit issuance and
dispatch. Scope changes, policy changes, expired sessions, invalid bindings,
and missing capture proxies fail closed. Auth material is resolved only by
the executor and is never stored in a run, step, dashboard response, or log.

Only saved, secret-free request shapes are accepted. The current Phase 15
planner emits bounded GET/HEAD templates without query values, headers, or
bodies. Phase 16 does not infer parameters or synthesize mutations. Locally
constructed fixture plans exercise state-changing approval and crash behavior;
real authorization/GraphQL plans still require a later safe actor/object/
request binding before they can execute. An old authenticated snapshot that
lacks an exact session ID blocks rather than acquiring a replacement session.

## Approval, Human Review, and Stops

`REQUIRE_APPROVAL` creates a Phase 13 exact-action approval request and pauses
the run. An operator may approve once or reject through the existing
authenticated approvals view. Resume checks current prerequisites, package
policy/version, identity, and the approval state; approval alone never sends
a request. The subsequent explicit advance rechecks policy and obtains a
new one-use permit. Rejected or expired approvals stop the run. A pending
approval remains pending across pause/resume.

Manual-review steps and ambiguous dispatch outcomes enter `WAITING_HUMAN`.
Completion requires a target-owned Evidence or TrafficStore reference. A
previous execution result remains immutable; an additional independent
manual link is required to resolve it. No fake browser proof is created.
Pause/cancel is durable. An in-flight request cannot be unsent, but the
executor checks the run stop flag before every dispatch, including redirect
hops, and will not send a later hop after a stop request.

## Budgets and Recovery

The plan request budget is 0-20. Each stored TrafficExchange reserves one
request slot atomically before wire dispatch and counts against the run
budget, including redirect hops and attempts cancelled after request
recording. This deliberately overcounts a pre-wire cancellation rather than
risk an unaccounted send. `max_dispatches` limits a single
executor call to the remaining budget. Phase 14 still reserves target rate
capacity for each hop. There are no automatic orchestrator retries; any
future retry must consume budget. Token budget is metadata only in Phase 16.

Before dispatch, the run persists its action, policy, permit, and execution
correlation ID. On process restart, stale `RUNNING` steps are reconciled by
that correlation against TrafficStore; known exchanges and Evidence refs are
linked, and missing exchange evidence is treated conservatively. The run
enters `WAITING_HUMAN` rather than replaying a request, especially a mutation
whose response may have been lost. The original result and later manual
resolution remain separately auditable.

## Audit and Operator Surface

The audit chain is:

`Hypothesis -> Skill snapshot -> InvestigationPlan -> PlanRun -> RuntimeStep
-> ProposedAction -> PolicyDecision -> Approval (when needed) -> PolicyPermit
-> ExecutionResult -> TrafficExchange -> Evidence`.

`plan_run_events` records creation, ready/started/finished steps, policy,
approval, permit, dispatch intent, completion, pause, cancel, and recovery.
The target-scoped API returns bounded run pages and at most 100 recent detail
events; the SQLite ledger retains the complete timeline. Safe metrics include
run counts, completed/blocked/approval waits, dispatches consumed, execution
failures, and recorded execution duration.

The existing `/hackbot/runs` dashboard displays status, steps, controls,
policy/approval/permit IDs, Traffic/Evidence references, budget, and timeline.
The Plans view has explicit Start/Rerun/Open actions; Approvals link to waiting
runs. The private BugHunter service exposes `/v1/plans/{id}/runs` and
`/v1/runs/{id}` plus explicit `advance`, `pause`, `resume`, `cancel`, and
manual-step completion routes. The public-facing recon dashboard gateway
requires its existing authentication and CSRF token for mutations. It does
not accept arbitrary request URLs. Evidence bodies remain protected; the
dashboard shows references and metadata only. No global Run All action exists.

## Verification and Next Phase

Phase 16 verification uses only loopback HTTP fixtures: two-tenant/three-role
controls, owner-versus-anonymous download, approval and denial, scope/policy
changes, request and redirect budgets, cancellation, crash recovery,
ambiguous POST, and missing capture proxy. No bounty target traffic is part
of these tests. Before deployment, back up the BugHunter SQLite file with
SQLite's online backup API; never copy a live database file blindly.

Phase 17 should introduce deterministic, independent result validators that
consume paired run observations, prove or reject a specific trust-boundary
violation, and preserve negative controls and duplicate checks. It must not
equate a completed plan or HTTP status difference with a confirmed finding.
