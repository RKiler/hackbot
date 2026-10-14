# Phase 28: Cross-Specialist Research Planner

Phase 28 coordinates one explicit, target-scoped investigation. It does not
schedule campaigns, send notifications, generate reports, authorize traffic, or
create findings. The Target Package remains the scope authority. Phase 13
policy, Phase 14 execution, Phase 16 orchestration, Phase 17 validation, and
specialist-specific contracts remain the only paths to an active result.

## Run and modes

`PlannerRun` is stored in BugHunter SQLite with the Target Package ID/version,
policy hash, mode, lifecycle status, readiness, context fingerprint, limits,
reservations, outcome counts, and timestamps. One explicit run is active per
target. `ANALYZE_ONLY` ranks and stops; `PLAN_ONLY` creates plans but never
executes a plan or creates a disposable object; `BOUNDED_AUTONOMOUS` may resolve
approved prerequisites and start a policy-permitted child plan. Approval and
human-review gates remain in the child workflow. Start, pause, resume, cancel,
and one-step advance are explicit private service operations.

States include context loading, ranking, ready/running, waiting for research,
login, approval, or human review, paused, completed, blocked, failed, cancelled,
and budget exhausted. The planner claims one task atomically at a time. A
restarted process reconciles an interrupted task to an ambiguous waiting state;
it does not repeat a potentially active request. Safe pending branches resume
after restart, and idempotent task-graph construction repairs a crash between
portfolio persistence and task creation. An ambiguous branch is not rebuilt or
retried automatically; unrelated ready branches may continue. A crash before
portfolio persistence marks the run failed and releases its active-target slot.
A linked child is resumed only through Phase 16. An ambiguous child start cannot be silently
cancelled or declared budget-exhausted; it stays paused for review.
If a crash follows a committed stale-DOM successor link, resume completes the
old refresh task from that link without fetching the asset a second time.

## Context and portfolio

`PlannerContextBuilder` reads only small, target-bound metadata pages:
TargetProfile, BehaviourProfile, verified session and tenant summaries,
verified disposable-object IDs, recent TrafficExchange IDs, Fact IDs, current
ResearchBrief IDs, and existing Finding hypothesis links. Optional
ReconRepository access resolves the exact root and reads at most two completed
scan snapshots. Recon can improve readiness, never authorize a test. No raw
recon inventory, traffic body, JS body, credentials, or research webpage is
placed in planner context. A cold-start target can still produce prerequisite
recommendations. Low-readiness summaries list bounded next steps for missing
profile, owned session, normal behaviour, observed traffic, and disposable
fixture coverage; these recommendations do not start active work.
Fact selection inspects at most 48 recent target-bound records and retains up
to 16 active, supported high-confidence IDs, prioritizing ownership and tenant
relations over generic notes. Fact subjects and values remain outside context.
Portfolio creation atomically records bounded, target-checked profile,
behaviour-run, TrafficExchange, Fact, and ResearchBrief IDs in the immutable
planner event ledger. The run's context hash remains a change detector, while
these references let a reviewer trace the exact local context considered
without retaining private values or copying source records.
When a cached brief changes a candidate's ranking, its target-bound brief ID
is also retained in that candidate's bounded source references even if the
brief falls outside the context builder's sampled open-gap list.

The portfolio normalizes Phase 12 hypotheses and current Authorization,
GraphQL/API, DOM XSS, postMessage, and Exposure specialist candidates. Records
refer to their source IDs rather than copying specialist stores. Each candidate
captures specialist, category, surface hash, security boundary, confidence,
freshness, evidence references, gaps, estimated request/browser/token costs,
risk, skills, and handoff references. The default portfolio is bounded to 100;
limits may be reduced or raised within hard configuration caps.

Each ranked candidate also has an immutable, bounded `CandidateAssessment`:
typed identity, object, traffic, and research prerequisite codes; potential
impact; confidence; readiness; and prior related outcomes. These are advisory
ranking inputs, not vulnerability probability or proof. Existing planner
portfolios written before schema version 36 read with a neutral assessment;
new portfolios persist one assessment alongside each candidate. This keeps
the original planner migration immutable while allowing a safe upgrade.

## Ranking, deduplication, and routing

The deterministic score combines source score, trust-boundary value, current
evidence, verified identity/object readiness, risk, missing prerequisites, and
estimated cost. Priority answers *what to investigate next*, not the chance a
bug exists. Expected value is a bounded relative ordering, not a bounty-dollar
prediction. Skill validation history affects ranking only after several
observations. An optional `PlannerAdvisor` may reorder a narrow near-tie using
typed candidate IDs and bounded metadata; an invalid or unavailable advisor
has no effect. It cannot make a candidate eligible or bypass a budget.
The configurable exploration percentage can move at most two current,
evidence-backed hypotheses ahead of later same-specialist candidates; the
ordinary candidate, specialist, request, browser, and token caps still apply.

Root-cause keys use target, normalized surface, security boundary, owned object
when applicable, and helper/operation identity. GraphQL operations on a shared
endpoint are distinct. Anonymous protected-download signals from Authorization
and Exposure can collapse to one branch. For a traffic-derived Exposure lead,
the planner uses the linked in-scope TrafficExchange's structural display path
for clustering, not the Exposure lead's display-only redacted URL; unrelated
routes remain separate. `DUPLICATE_OF` and specialist handoff
relationships are persisted, with other typed relationships available for
explicit links. A confirmed or rejected root is remembered for the same target
and candidate-source state. Confirmation suppresses siblings; a strong
rejection prevents a same-state retry. Unrelated new traffic does not clear
that memory, while policy, relevant identities/objects, source evidence, or a
current asset change requires fresh assessment.

The existing Phase 15 SkillRouter supplies eligible skills. Specialists retain
their own preparation and run logic. A researcher may pin, deprioritize, or
exclude an unstarted candidate. A manual specialist switch is accepted only
for an unplanned hypothesis when Phase 15 routes a matching skill; it cannot
reroute a specialist-owned request to an arbitrary executor. Handoffs remain
linked metadata, not simultaneous writes against one object.
Pinning can displace the lowest-priority unstarted selection even when the
researcher-pinned candidate ranked lower; started work is never evicted and
the same specialist and budget caps still apply.

## Gaps, tasks, and research

The planner records structured identity, second-tenant, object/ownership,
request-template, browser-route, research/protocol, stale-source, policy, and
budget gaps. Resolution prefers existing Facts, TrafficStore, ObjectRegistry,
recon/profile metadata, then safe ObjectFactory setup, local ResearchCoordinator
work, and only then a login or operator action. `NOT_OBSERVED` behaviour is not
a denial. No object is fabricated to fill a missing owner baseline.

Tasks form a bounded relational dependency graph: resolve identity/object,
refresh traffic/asset, request research, create a disposable object, create a
plan, run a plan, validate, or request manual review. A candidate's branch is
serial; unrelated ready branches can proceed while another waits. Failed
prerequisites and ambiguous actions remain recorded, with at most one safe
retry of a waiting task. The planner does not synthesize a malformed request
to bypass a policy denial.

Stale-source refresh precedes disposable-object setup. A setup task rechecks
source freshness before invoking ObjectFactory, then reserves its bounded
request allowance. For a cross-tenant or horizontal Authorization candidate,
the missing object is the foreign actor's same-operation comparison control,
not the already-ready owner object. The planner delegates creation to the
Authorization specialist's reviewed ObjectFactory recipe under that hunt's
bounded-autonomous mode and the current creation policy; it checks foreign
ownership and observed tenant before treating the control as ready. Plan-only
mode never creates the fixture. A manual-review outcome or policy/prerequisite
block suppresses the same root in unchanged target state; a budget shortfall
remains eligible under a later, larger explicit run.

A stale postMessage candidate may refresh its exact recon-observed JS asset in
bounded-autonomous mode through the Phase 21 acquisition and policy gate. It
reserves at most three request slots first and does not automatically fetch a
source map. Plan-only mode sends no refresh traffic. If the refreshed protocol
still has the same candidate identity and is current, planning can continue;
otherwise the branch waits for review of the changed source rather than
silently investigating a different protocol. A stale DOM flow can use the same
bounded acquisition path; when the new analysis retains the same source and
sink kind on the exact recon asset, one newly ranked candidate replaces the
stale branch with a `SUPERSEDED_BY` link. The old plan dependencies are skipped
transactionally. A different flow or an unranked replacement remains a
manual-review gap. A stale GraphQL/API operation uses bounded existing-data
profiling, then regenerates only the exact current operation or a same-key
successor from the same recon JS asset and URL. The successor must retain the
candidate's category, actor/object binding, and field path before the planner
re-ranks it. No request is synthesized from a JS-only hint. If the operation
or its controls cannot be re-established, the branch waits rather than
borrowing a parallel traffic-observed document or another bundle's route.
After a no-match wait, resume retries only if that exact recon JS asset has
a new current body or the original operation has become current again; the
planner task's two-attempt cap prevents an unbounded refresh loop.
Other stale sources still need an explicit refresh before their blocked branch
can continue.
Before an Authorization or API plan is prepared or started, the planner checks
the required owned sessions and source object again. An object already reserved
by that exact child run remains valid; a missing or unrelated reservation
pauses the branch rather than starting on stale ownership state.
When a missing object becomes ready, resume re-claims a waiting plan or run
task instead of marking it complete. A child made ready by its own approval or
human-step workflow likewise resumes from its existing run ID.
ObjectFactory setup approvals remain bound to the original planned object and
pending action. Resume waits for a matching one-time approval, then continues
creation or ownership verification on that object; it does not call a new
`resolve` that would allocate a second fixture. An unresolved approval keeps
the planner waiting. A setup login gap retains the object reference while the
operator view resolves its owned creator alias.

ResearchCoordinator receives a structured, target-bound gap and first checks
the local cache. Planner-initiated research is local-only in Phase 28. Briefs
are advisory; a recommended skill is used only if Phase 15 independently
routes it. New ephemeral skill proposals require separate review and cannot
gain execution authority. The planner checks a proposal's name against the
Phase 15 catalog and full skill parser; an unregistered proposal remains a
visible manual-review reason, not an executable plan. Even a catalog match
must pass the current hypothesis's Phase 15 route before use. A missing brief
does not satisfy a research prerequisite. No external article text is
inserted into planner execution prompts.

## Budgets and stopping

Run limits cover candidates, each specialist, request slots, browser actions,
tokens, wall time, and a cleanup reserve. Candidate selection checks all three
cost dimensions. Request, browser, and token reservations are atomic and
idempotent per task; Phase 16 and ObjectFactory retain their own stricter
budgets. Time expiry requests child cancellation through Phase 16 before
closing the planner, leaving ambiguous starts paused. Validation, not planner
scoring, determines proof. Findings are linked only after Phase 17 returns a
confirmed validation.
DOM proof reserves six browser trials and postMessage proof reserves eight,
matching the current specialists' maximum variant counts. Manual specialist
switches use the same caps.

Metrics distinguish reservations from observations. Child request slots come
from `plan_runs.requests_consumed`, browser-proof steps from completed Phase 16
steps, and research token counts are estimates from linked research requests.
The planner also counts child DOM and postMessage trial dispatches as accounted
navigation attempts and runtime proof actions, with a separate fresh-context
reproduction count. These specialists do not issue page reloads, so their
reload count is zero. A dispatch can fail before browser navigation; neither
this count nor a completed proof step claims an exact number of successful
browser navigations. Pre-wire request slots may exceed actual wire sends. No
bounty yield is inferred from these numbers.

## API, dashboard, and audit

The private service owns `/v1/planner/<package_id>/runs` and target-bound run,
candidate, relationship, task, override, and control endpoints. The existing
authenticated dashboard gateway exposes these through `/hackbot/planner`,
allowlists paths, enforces CSRF for mutations, and strips incoming credentials
before proxying. The view shows readiness, mode/status, budgets, candidate
queue, dependencies, linked briefs/findings, events, and manual controls.
It renders safe text, not raw Evidence or secrets. When a known identity needs
login, the task retains its target-checked identity ID and the private detail
response shows the corresponding owned account alias.

Candidate links form the audit path from a planner run/task through hypothesis,
skill plan, child plan run, Phase 17 validation, and Finding. The child stores
retain policy, approval, permit, TrafficExchange, Evidence, and Fact references.
The planner's context-reference events link the same run to its bounded input
profile, behaviour, traffic, facts, and research records. Research and
behaviour links are supporting context, not proof or scope
authority. A Finding must pass the existing independent validator; the planner
has no Finding writer.

## Phase 29 handoff

Phase 29 may consume confirmed validation/Finding links and explicitly labeled
high-value manual-review leads for deduplicated notifications and report
generation. It must not treat planner priority, a ResearchBrief, or a candidate
status as a confirmed vulnerability. Phase 28 adds no alert channel or report
emitter.
