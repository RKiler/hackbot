# Phase 31: Bounded Campaign Coordination (complete)

Phase 31 adds an explicitly started, target-scoped Campaign above the existing
Phase 28 PlannerRun. It does not add a scheduler, a new executor, a new browser
controller, or a finding authority. The TargetPackage and current Phase 13
policy remain authoritative for every child action; Phase 17 validation remains
the only route to a confirmed Finding.

## Model and lifecycle

Schema 47 stores `campaigns`, `campaign_cycles`, `campaign_work`, task claims,
events, state-versioned root suppressions, and disposable-object cleanup links
in BugHunter's local SQLite state. No recon schema or data is changed. A
campaign captures the target/package version, policy hash, mode, operator,
created/started/finished times, limits, reserved capacity, current cycle,
readiness/wait reason, and stop reason. Child run IDs are linked in the same
SQLite transaction that creates the child. The event ledger is append-only.

Modes reuse `PlannerMode`: `ANALYZE_ONLY` ranks without target execution;
`PLAN_ONLY` creates bounded plans but does not run them; and
`BOUNDED_AUTONOMOUS` may invoke existing policy-gated work. A campaign starts
in `CREATED`, assesses readiness, then enters a bounded cycle. A cycle may use
existing cold-start bootstrap, normal-behaviour learning, local/cached research,
and one PlannerRun. The planner retains candidate scoring, specialist routing,
per-task waits, and validation. The coordinator only decides whether another
cycle is useful, subject to changed target knowledge and remaining budgets.

The coordinator checks TargetPackage status/version and policy hash before
new work. A mid-campaign change pauses the campaign for explicit reassessment;
resumption loads the current package. Confirmed root causes and deterministic
rejections are suppressed only for the same root and state hash, so meaningful
target-state changes can be reconsidered. A stable knowledge snapshot, no
selected work, the cycle cap, cancellation, or an exhausted budget ends a
campaign. `COMPLETED` means only that this bounded campaign ended, never that
the target is vulnerability-free.

## Budgets and readiness

`SMALL` is the default preset (two cycles, ten minutes, 20 request slots,
eight browser slots, one research slot, 2,000 token slots, one setup object,
four cleanup request slots). `STANDARD` and fully specified bounded `CUSTOM`
limits are available. Child work reserves capacity atomically before launch;
unspent allocations are conservatively treated as used, including after an
ambiguous crash. Planner runs receive only a bounded slice of the remaining
campaign capacity. Custom limits reserve at least three cleanup request slots
per allowed disposable object. These counters are reservations and upper
bounds, not a measurement of exact network traffic or billed model tokens.

Readiness reuses `PlannerContextBuilder`: current profile, recon state, recent
TrafficStore/Facts, verified identities and sessions, tenant/object coverage,
behaviour profile, research briefs, and candidate knowledge. Resource admission
uses the Phase 30 controls before new heavy work; critical disk/resource
conditions pause the campaign without hiding cleanup/control access. Capture
requirements remain enforced by existing planner/execution policy. Recon
outages do not turn recon records into authorization or force a direct-connect
fallback. Research remains advisory and target input cannot alter campaign
budgets, scope, or status.

## Pauses, cleanup, and recovery

Planner tasks retain their existing independent wait semantics: one login or
approval branch does not preempt other ready tasks. When no ready task remains,
the campaign surfaces `WAITING_LOGIN`, `WAITING_APPROVAL`, `WAITING_RESEARCH`,
or `WAITING_HUMAN`. The dashboard links login/session and approval views. It
does not open repeated VNC windows or automate human approval. A learning
prerequisite that stopped for login is settled only after a current verified
session exists; its already-started child is not replayed. Pause prevents
new campaign work; cancel prevents future work and retains cleanup obligations.

Campaign-created objects are tied to completed planner setup tasks and
recovered from the child ledger after a crash. Normal completion and
cancellation attempt cleanup through the existing ObjectFactory with a current
verified session. A missing session, uncertain child action, orphan, failed
absence check, or exhausted cleanup capacity yields `CLEANUP_REQUIRED` or a
human wait rather than a false clean completion. Before a service restart can
run any target work, startup reconciliation pauses interrupted campaigns and
marks child-start intents without a linked child as ambiguous. No campaign is
automatically resumed on boot; the operator must recheck current package,
resource, session, and child state. Existing child orchestrator reconciliation
continues to protect uncertain target actions from duplicate replay.

## Control plane and provenance

The private service exposes target-filtered `GET/POST /v1/campaigns`, detail,
and pause/resume/cancel routes. The existing dashboard gateway exposes only
allowlisted `/api/hackbot/campaigns` operations with its normal login and CSRF
checks. `/hackbot/campaigns` shows modes, presets/custom limits, readiness,
cycle/work ledgers, reservation metrics, finding/report links, object cleanup,
and an event timeline. There is no arbitrary task/request endpoint.

Finding linkage follows `campaign_work` -> PlannerRun -> candidate ->
PlanRun/Validation/Finding. Existing Phase 29 planner/finding notification
deduplication and report workflow remain authoritative. Campaign metrics
include cycles, candidates, plans, validations, manual reviews, findings,
objects pending cleanup, and reserved requests per finding. They are hooks
for Phase 33 evaluation, not bounty-value optimization.

## Verification and handoff

Acceptance used local fixtures and the source-bound segmented matrix: 61/61
modules passed in nine groups, including campaign modes, prerequisites,
budgets, waits, cleanup, restart reconciliation, scope changes, finding/report
links, browser specialists, and the service. The dashboard gateway's 15 tests
and the JavaScript syntax check also passed. No bounty-target request or
production recon write was part of acceptance.

The schema-46 state was backed up and restored in isolation before the
schema-47 rollout. A byte-identical quarantine copy was retained before the
live migration. The rehearsal and live database passed integrity and foreign
key checks, with 80 Evidence rows preserved. A schema-47 encrypted backup was
then created and restore-verified. The BugHunter service was reloaded with the
verified source and reports healthy storage, recon, Burp, and resources; its
readiness endpoint is `READY` and the private campaign list responds. The
dashboard's campaign page and API preserve its login and CSRF boundary. No
campaign was started against a live target during acceptance.

The dashboard exposes bounded summaries, not full evidence or secrets. Budget
counters are conservative reservations rather than exact network or billing
usage. `CLEANUP_REQUIRED` retains object obligations for human resolution; a
completed campaign is never a claim that the target is secure. Phase 32 may
later consume delta events to suggest or explicitly trigger campaigns only
after separate design and approval; Phase 31 has no recurring timer or
recon-delta trigger.
