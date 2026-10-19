# Phase 33: Evaluation and Benchmarking

Status: core low-resource acceptance complete on 2026-10-19. Product readiness
is **NOT_READY**; do not enable a real-target pilot or continuous hunting from
this synthetic result. See `docs/PHASE33_ACCEPTANCE.md` for the current-source
matrix, baseline, remaining quality gaps, and separate extended-work record.

## Low-Resource Acceptance Contract

Core Phase 33 acceptance is a small, checkpointed, one-trial synthetic campaign
suited to this 2-vCPU VPS. It still requires a vulnerable and guarded scored
pair for each implemented specialist (Authorization, API/GraphQL, DOM XSS,
postMessage, Exposure), one noisy secure target, and one mixed multi-surface
target. Hidden answers stay evaluator-only. The core report must include
deterministic baseline, top-K, precision/recall, cost, interventions, safety,
readiness, primary/challenger architecture tests, and a source-bound Phase 30
matrix pass. Zero safety violations and zero false confirmed Findings on secure
cases are non-negotiable. Missing measurement is not a pass.

`hackbot benchmark coverage local-low-resource-candidate` checks only the
current fixture inventory and answer-key leakage. It does **not** run targets
or establish acceptance. The 19-case suite now has paired Authorization,
API/GraphQL, DOM XSS, postMessage, and Exposure cases plus noisy/mixed cases.
A paired case only counts when both variants use the
same fixture kind, visible-input hash, and case version. The final core report
must also prove those cases executed,
had complete audit chains where Findings exist, and passed their safety gates.

Three-trial GraphQL field stability runs are extended diagnostic evidence, not
a requirement to repeat every case/model/ablation combination. Additional
repetitions and live cross-provider comparisons belong to resumable,
operator-invoked `EXTENDED_BENCHMARK` work after core acceptance. No result is
claimed for an unexecuted run, and missing provider credentials never become
a Phase 33 completion blocker if independent fake-provider tests pass.
The CLI defaults to one trial. `hackbot benchmark run <suite> --mode local
--trials 3 --seed 33` starts an explicitly requested bounded repeatability
run; `hackbot benchmark resume <run-id>` retains the existing crash-safe
checkpoint semantics. This is available for later extended runs, not part of
the one-trial acceptance minimum.

The earlier version-33.15 15-case provisional run is stored at
`/root/codex_artifacts/bughunter-agent/artifacts/benchmark-reports/BENCH-f451718aefbd48a8bc9866a9ef682ce0/report.json`.
All 15 cases completed. It confirmed 3/8 planted roots (download,
cross-tenant mutation, and cross-tenant read), with precision 1.0 on those
three confirmations and recall 0.375 for this incomplete fixture mix. All
eight secure cases, including the noisy target, produced zero false confirmed
Findings. The run used 230 loopback requests, four synthetic approvals, and
seven manual-context waits; all 27 disposable objects were cleaned, with
zero orphan or safety events. Five planted roots were missed, including the
GraphQL and horizontal cases. This is a regression baseline, **not** core
acceptance or a production-readiness pass: DOM XSS and postMessage pairs are
absent, and the source-bound Phase 30 matrix remains unverified on this build.

The first 19-case local baseline, `BENCH-2bd4b620c1754284a67fd0575b56866f`,
completed before the browser fixture selectors were made data-derived. It
confirmed 5/10 planted roots, including DOM XSS and postMessage, with top-1
recall 0.7, precision 1.0, recall 0.5, 286 loopback requests, zero false
confirmed Findings, and zero safety violations. All 27 synthetic objects were
cleaned. GraphQL cases waited for approval; horizontal and mixed cases still
missed their planted roots. The report is at
`/root/codex_artifacts/bughunter-agent/artifacts/benchmark-reports/BENCH-2bd4b620c1754284a67fd0575b56866f/report.json`.
This is not yet final acceptance evidence: the updated browser selectors,
source-bound Phase 30 matrix, and readiness evidence still require verification.

A later version-33.16 one-trial run, `BENCH-1424738aa0914d0aa57d7aa52de8c331`,
completed all 19 cases after the browser-selector correction. It confirmed
4/10 planted roots, with precision 1.0, recall 0.4, top-1 recall 0.6, 284
loopback requests, zero false confirmations on secure cases, zero observed
safety violations, and 27/27 disposable objects cleaned. The change from
5/10 in the earlier run is an observed campaign-ranking/stability limitation;
neither the fixture nor its answer key was changed to hide it. This run is
historical after the version-33.18 ablation support and is not the final
source-bound acceptance report.

The version-33.18 acceptance attempt `BENCH-c3810337472f44d38857bc609d97989a`
is **failed evidence**, not a baseline pass: 18/19 cases completed, while
`local_tenant_b` raised a resource-admission error during the final case. The
completed cases had zero secure-case false confirmations and zero recorded
safety violations, but `local_mutation_b` left one of two synthetic objects
unverified as cleaned after its campaign paused. The report recorded 25
objects created and 24 cleaned, so the zero-safety-event count is not a clean
acceptance result. This exposed a teardown gap: cancellation before cleanup
was limited to GraphQL cases. The local fixture teardown now cancels any
waiting or paused campaign before cleaning owned objects and treats a remaining
orphan as a safety event. Resource-admission reason codes are now recorded
without exception text. Both changes require a new source-bound matrix and
acceptance run; the prior 78/78 matrix fingerprint
`acb0c66ff731ab495da9f4e99353c7dddf5ebb5dfb0e9fbd375cecbca0b40f8b`
predates them and is historical only.

The corrected version-33.18 baseline
`BENCH-df8b2379a1e84eefa27ab385c22ac830` completed all 19 cases on the
source fingerprint recorded in `docs/PHASE33_ACCEPTANCE.md`. It confirmed
5/10 planted roots with precision 1.0 and recall 0.5, zero secure-case false
confirmed Findings, zero observed safety events, and 27/27 disposable objects
cleaned. API/GraphQL, horizontal, and mixed-target misses remain explicit.
The report's readiness conclusion remains `NOT_READY`; benchmark acceptance
does not imply pilot authorization.

## Extended Benchmark Controls

The default low-resource acceptance remains one deterministic-only trial.
Repeated trials are explicit, checkpointed, and operator-invoked:

```text
hackbot benchmark run local-low-resource-candidate --mode local --trials 3 --seed 33
hackbot benchmark resume BENCH-<run-id>
```

Implemented ablations change a real input or advisor lane:

```text
hackbot benchmark run smoke --mode offline --ablation NO_TRAFFIC
hackbot benchmark run local-advice --mode local --fake-providers
hackbot benchmark run local-advice --mode local --fake-providers --ablation NO_MODEL
hackbot benchmark run local-advice --mode local --fake-providers --ablation NO_CHALLENGER
```

The fake primary and challenger are deterministic ordering fixtures. They
receive independent bounded planner packets, use no hidden answer, and cannot
authorize execution or confirm a Finding. Their results verify provider
plumbing and ablation accounting, **not** live-model usefulness. `NO_TRAFFIC`
is supported only by the offline runner; the model-lane ablations are supported
only with selected lanes in the local advice suite. Other declared ablation
names and live-provider comparisons fail closed until a suite and provider
adapter can actually exercise them. Do not report them as completed or
available comparisons.

The browser pairs use current exact JS retrieved from an observed loopback
page and normal Campaign/Planner/Phase 17 validation. DOM variants share the
same check-before-decode JavaScript; the guarded page's CSP blocks execution.
Messaging variants expose the same synthetic MessagePort RPC, but only the
vulnerable receiver accepts a foreign origin. The benchmark harness selects
only a page family and fixture mode; it derives the DOM query name and
messaging activation/RPC names from downloaded source. These are
route-observed specialist cases, not proof of cold-start route discovery.
Answers remain outside the runtime-visible target package.

## Architecture

The benchmark catalog has separate `benchmarks/visible` and `benchmarks/truth`
roots. Only hash-checked visible files are staged into a fresh local BugHunter
runtime. The evaluator reads the hidden answer after the case run. Inputs and
answer files are versioned, and symlinked or out-of-root visible paths are
rejected. `benchmark_runs` and `benchmark_case_runs` live in a separate
BugHunter-owned SQLite file, not the production Finding database. Interrupted
claimed cases become ambiguous rather than silently replaying target actions.

The current offline runner imports synthetic recorded HTTP traffic using
`TrafficSource.FIXTURE`, builds a normal target profile and passive hypotheses,
then runs Phase 31 Campaign and Phase 28 Planner in `ANALYZE_ONLY` mode. It
does not issue target requests, launch browsers, invoke models, create test
objects, or run active validation. It is a first pipeline baseline, not the
required full benchmark path. The runner refuses non-`.test` hosts and
undeclared package scope. Benchmark notification providers are disabled.

An evaluator counts detection only when a confirmed Finding matches hidden
category, operation, boundary, object type, protocol, and fingerprint and has
the required validation/campaign/audit chain, controls, impact, and
reproduction. Ranked candidates earn separate top-K/routing credit only.
Planner candidate keys may differ from validator Finding fingerprints; the
hidden answer can list both, and only the Finding fingerprint can satisfy
final detection.
An allowed alternate category matches only when the answer's primary
fingerprint agrees with its structured root metadata; the evaluator derives
the alternate structured key instead of accepting arbitrary fingerprints.
Known-secure cases must have zero false confirmed Findings. Missing data is
`NOT_MEASURED`, not a pass.

A read-only trace collector now follows persisted CampaignWork, PlannerRun,
PlannerCandidate, Hypothesis, Plan, PlanRun, Validation and Finding references.
It does not fabricate a Finding from a candidate or status string. Broken
links fail the audit gate. The offline baseline still has no executed
experiments or Findings, so its detection result remains zero.

A separate loopback-only validation diagnostic exercises ObjectFactory creation,
owner read-back, ExposureSpecialist candidate preparation, PlanOrchestrator,
Phase 17 deterministic validation, and ObjectFactory cleanup against a bounded
synthetic HTTP server. The vulnerable private download confirms with a full
validator-to-Finding link; the guarded equivalent produces no candidate. A
stale positive observation against the currently guarded server reaches the
validator and is rejected by fresh controls. Every variant uses a verified
synthetic owned identity, one disposable document, an exact `127.0.0.1` scope,
no redirects, and at most 40 fixture requests. This diagnostic deliberately
starts from a known route and is **validation-only**: it does not satisfy the
required blind Campaign/Planner discovery chain or raise recall in the offline
benchmark report.

A traffic-backed local Campaign probe now starts with an owned document and
owner/anonymous traffic, runs Exposure discovery, then uses the normal Phase 31
Campaign, Phase 28 Planner, specialist plan, Phase 16 execution, and Phase 17
validator. Before the Phase 33-discovered correction, its selected candidate
stopped at `PLAN_PREREQUISITE_MISSING` with no validation. PlannerRunner now
binds an existing ready disposable object only when the exposure candidate's
owner GET is the exact request Evidence recorded by ObjectFactory verification;
it does not infer ownership from a redacted URL or try a guessed identifier.
After that correction, the vulnerable local run completes with one selected
candidate, one validation, one confirmed Finding, an audited chain, ten bounded
HTTP requests, and successful object cleanup. The guarded equivalent completes
with zero candidates/findings, six requests, and successful cleanup. This is a
traffic-backed end-to-end case, not cold-start no-route discovery or broad
category coverage.

The versioned `local-smoke` suite now scores that pair through a loopback-only
`BenchmarkLocalRunner`. Its visible case IDs are neutral (`local_download_a`
and `local_download_b`); their target manifests are identical. A third,
runner-only `benchmarks/harness` root selects the synthetic server behavior,
while `benchmarks/truth` is loaded only for evaluation after the campaign.
The local runner requires explicit `--mode local`, checks visible and harness
hashes, serializes cases, and marks an interrupted claim ambiguous instead of
replaying a possibly state-changing test. The case starts with one disposable
owner object and observed owner/anonymous traffic, so it tests traffic-backed
discovery and validation, not a cold start without route data.

Loopback ports change between trials, and the production Finding root hash
includes its target origin. Benchmark traces therefore retain that engine
fingerprint for audit but calculate a separate structured evaluator fingerprint
from confirmed category, canonical operation, trust boundary, object type, and
protocol. The semantic key is stable across repeated local runs and cannot
create a Finding; it only compares an existing audited Finding to hidden truth.
For candidate metrics, a traffic-backed Exposure candidate is normalized only
when its pre-planning owner GET Evidence exactly matches a verified disposable
object's request Evidence and pinned recipe. Otherwise the engine key remains.
The original key is retained in the trace. This corrects ephemeral-port
distortion of top-K and false-candidate metrics without changing planner
ranking or validator confirmation.

## Current Suites

The `smoke`, `specialist`, `planner`, `campaign`, `secure-negative`, and `full`
names exist in the catalog, but currently contain only the first download
vulnerable/secure recorded-traffic pair. These suite names do **not** prove the
required category coverage, active execution, or held-out evaluation. The
separate local suites now include paired Authorization, API/GraphQL, DOM XSS,
postMessage, and Exposure cases, as checked by the low-resource fixture
inventory. Deeper subtype combinations such as GraphQL nested, mutation, and
batch authorization or credential and VHOST exposure remain extended-coverage
work, not completed measurements. The exposed
case contains a fictional
private-file response; the guarded case contains an anonymous denial.
The separate `local-smoke` suite contains the active download pair.
`local-secure-negative` contains the guarded download and the noisy secure
workspace; `local-noisy-secure` isolates the latter. Run local cases with
`hackbot benchmark run local-smoke --mode local`; offline mode refuses them.
`local-mixed` contains a separate loopback vulnerable/guarded pair with two
different read boundaries and harmless admin, GraphQL, public-file, JavaScript,
and source-map signals. The fixture is implemented but its current campaign
misses both planted roots and requests human review; it is not acceptance
evidence for successful mixed-target detection.

The noisy workspace serves an admin-looking login page, a GraphQL error,
public configuration and sample download, and inert JavaScript/source-map
signals. Owned and anonymous read traffic produced six Exposure candidates;
the campaign requested human context and executed no validation. The answer
key has no vulnerabilities. Zero confirmed Findings is therefore not credited
as an automatic rejection: the report records the candidate false-positive
load and `WAITING_HUMAN` separately. The JavaScript and source map are served
and captured as traffic, but are not yet ingested into the DOM/postMessage
specialists; this case does not measure their false-positive resistance.

The `local-advice` development suite adds a noisy vulnerable/guarded pair with
identical visible target files and a declared 400-token budget. Its separate
harness selects the private-download behavior, and its answer remains
evaluator-only. A programmatically injected bounded `ModelBenchmarkProvider`
can now advise the actual planner near-tie: the primary lane may reorder the
tie, while challenger and critic receive independent copies of the original
packet and cannot directly affect planner order or confirmation. Unsupported
or unregistered provider selections fail before case execution. Actual valid
model-call tokens and latency are recorded in the case trace; a configured
lane with no invocation is labelled `MODEL_ADVISOR_NOT_INVOKED`. Fake-provider
tests prove lane independence, accounting, and clean guarded behavior. This is not
yet a CLI-configured external provider, a broad specialist comparison, or
evidence that model assistance improves recall.
The noisy vulnerable case can be missed under the one-cycle budget because
several safe candidates have the same deterministic score as the real lead.
Repeated fake-provider trials observed both confirmation and a ranked miss;
the evaluator retains the miss instead of changing the fixture or answer key.
Planner stability and tie ranking remain open quality work.

Version `33.5` adds a scored `local-authorization` vulnerable/guarded pair.
Each run creates two verified disposable documents under separate synthetic
tenants and sessions, records owner controls, and lets AuthorizationSpecialist
generate one cross-tenant hypothesis from owned traffic. The normal Campaign,
Planner, skill plan, executor, and deterministic validator produce one audited
Finding only when the foreign read returns protected content. The guarded
equivalent reaches validation and produces no Finding. Both cases complete
with 15 loopback requests each and clean both objects. The candidate evaluator
key is normalized from the verified owner request and pinned recipe; the
engine key remains in the trace. No real target traffic or production notifier
is involved. This measures cross-tenant reads only, not authorization writes,
horizontal or vertical access, GraphQL, or browser-based bugs.

Version `33.6` adds the `local-authorization-mutation` vulnerable/guarded
development pair and the four-case `local-access-control` suite. In both
mutation variants, foreign GET is denied. Only the vulnerable variant permits
a foreign PATCH; the typed authorization plan must demonstrate the changed
object name through owner read-back and restore it. The guarded variant rejects
the PATCH. Mutation Findings retain their validator category in storage; the
benchmark projection classifies an audited typed mutation by its recorded
tenant boundary and derives the operation from the pinned recipe's boundary
stage. A recipe-hash mismatch yields no normalized operation. Tenant-A and
tenant-B fixture paths normalize to the same `{tenant}` root-cause route so
direction does not change evaluator identity. This projection cannot create
or confirm a Finding.

Version `33.8` adds a scored mixed multi-surface pair and fixes the evaluator's
alternate-category matching. The vulnerable fixture permits anonymous read of
one protected document and cross-tenant read of a different document; the
guarded fixture denies both. Both serve unrelated, non-vulnerable surface
signals. In the first scored run, the vulnerable case had two expected roots,
zero confirmed detections, and two misses; the guarded case had zero false
confirmed Findings. Each case used 23 loopback requests and cleaned both
objects without safety violations. Both campaigns stopped at `WAITING_HUMAN`.
This measures a real orchestration limitation, not a fixture or answer-key
reason to soften the confirmation gate. JavaScript and source-map specialist
analysis remains unmeasured here.

Version `33.9` adds the `local-horizontal` vulnerable/guarded pair. Two
independently verified synthetic identities belong to the same tenant and
create separate disposable documents. The vulnerable fixture permits a
cross-owner GET while the guarded fixture denies it; both deny anonymous reads
and cross-owner writes. The initial scored run missed the vulnerable read and
waited for human context in both variants. Its trace classified both
Authorization-routed candidates as `OTHER`, exposing an evaluator projection
defect rather than a change in the target or validator. Version `33.10` maps
the Phase 19 `HORIZONTAL` category to `HORIZONTAL_IDOR` and computes candidate
keys from an exact verified owner request and pinned object recipe even before
the candidate receives a plan. Mismatched ownership, package, recipe hash, or
boundary keeps the original engine key. This can correct top-K credit but does
not turn a candidate into a confirmed finding.

Version `33.11` adds the `local-graphql-object` vulnerable/guarded development
pair. Both cases receive identical visible target packages and observed owner
GraphQL query/response traffic. The vulnerable fixture permits a foreign-tenant
`node(id:)` read through GraphQL while its REST route remains protected; the
guarded fixture returns HTTP 200 with `data.node: null` and a GraphQL denial.
The first scored run, `BENCH-dacb7a49cc934caa98b73a1819f72abd`, generated
four candidates in each case but paused at policy `WAITING_APPROVAL` before
GraphQL verification. It confirmed zero of one planted vulnerabilities and no
secure-case false Finding. The run used 24 loopback requests and cleaned all
four disposable objects. Approval waits are recorded as interventions, and
the campaign reservation is cancelled before fixture cleanup. That run also
projected API `OBJECT_AUTH` candidates as `OTHER`, understating top-K and
specialist-routing credit. Version `33.12` corrects only this evaluator
projection: the current operation must be a GraphQL query, the pre-planning
owner capture must semantically prove the verified disposable object, the
object recipe must be pinned, and observed memberships must prove separate
tenants. Its canonical route comes from that exact owner Evidence rather than
the API registry's redacted path token. The hidden specialist label was
corrected from `API` to the actual `API_GRAPHQL` enum. The post-correction
scored run, `BENCH-a09b1e59c2254bc0826590c806a904cb`, credits the planted
root in top 3 with correct specialist and skill; confirmation remains 0/1,
the secure case has zero false confirmations, and four objects are cleaned.
An operator-assisted continuation and other GraphQL variants remain open at
this version; the blind pair alone does not establish validator precision or
broad GraphQL coverage.

Version `33.13` adds `local-graphql-approved`, an operator-assisted synthetic
evaluation of the *same* visible GraphQL pair and hidden truth. The harness
approves only policy-generated `api-observed-read` steps for the exact loopback
GraphQL owner route, at most eight times, and records every approval. It does
not turn off the policy gate or change the validator. The run
`BENCH-815ad5b35b3d4ba59e59f04c7747b38b` confirmed the planted object
authorization bug with a complete Finding/Validation/PlanRun/Planner/Campaign
audit chain. The guarded equivalent reached validation and produced no
Finding. Across both cases: one of one expected vulnerabilities confirmed,
zero false confirmations, 10 synthetic approvals, 34 loopback requests,
four objects created and cleaned, zero safety events. Both campaigns later
stopped at `WAITING_HUMAN` on additional work, so this is proof of the tested
branch, not complete autonomous campaign coverage. The benchmark's readiness
conclusion remains `NOT_READY`.

The approved run exposed a real planner continuation defect: a PlanRun with
several individually approved GraphQL requests exhausted the generic two-attempt
task retry counter even though it was resuming one already-linked child. The
planner now permits repeated `RUN_PLAN` wakeups only for a matching approved,
ready child; those continuations reuse the existing attempt slot and have an
independent 32-event cap. New child starts and other task retries retain the
two-attempt limit. This is a correctness fix driven by a pre-fix failure, not
a fixture, policy, or validator relaxation.

Version `33.14` adds `local-graphql-field` and
`local-graphql-field-approved`. The pair's visible packages are identical;
the runner-only harness chooses whether a foreign tenant receives a private
`email` field. Both variants expose the same public GraphQL object fields;
the guarded variant returns HTTP 200 with public data, `email: null`, and a
field-level permission error. REST remains protected, and only owned synthetic
documents are created. The current specialist ranks the true field candidate
inside the top five, but the one-cycle campaign spends its executed plan on
an object-auth candidate and later waits for human input. The scored approved
baseline `BENCH-c60a72ffa7734614be81a505c71b5377` therefore records 0/1
confirmed field vulnerabilities, 0 secure-case false confirmations, 34 loopback
requests, 10 synthetic approvals, and 4/4 objects cleaned with no safety
events. It remains `NOT_READY`. This is an observed planner/coverage miss, not
a reason to rewrite the fixture, loosen the validator, or count the candidate
as a detected vulnerability.

Version `33.15` records repeated-trial stability without treating a ranked
lead as a confirmed finding. The three-trial approved field suite is stored at
`/root/codex_artifacts/bughunter-agent/artifacts/benchmark-reports/BENCH-67f9190e5749483ba932c339070f47f0/report.json`.
The planted field lead ranked 1-4 (top three in two of three trials; top five
in all three), but confirmed recall was 0/3. The top-three category ordering
changed between trials. The guarded case had zero false confirmations. The
run used 102 loopback requests and 30 synthetic approvals, cleaned all 12
created objects, and recorded zero safety violations. Both campaigns ended
in the same manual-context wait. Readiness remains `NOT_READY`; ranking
stability and confirmation stability are reported separately so repeated
misses cannot appear as a success.

## Metrics and Cost

The evaluator records confirmed precision/recall, top-1/3/5/10 recall,
specialist and skill routing, candidate/executed/confirmed false-positive
rates, request setup/verification/cleanup counts, browser and research counts,
token counts, durations, intervention counts, safety events, and disposable
object cleanup. Model comparison uses independent bounded advice packets and
rejects malformed output; models cannot confirm a Finding or authorize
execution. Primary/challenger/critic model lanes are independently
configurable. Provider and VPS prices are operator inputs. A missing price
stays unknown, never zero by assumption. Research, ablation, model stability,
specialist/skill yield, and campaign/delta efficiency require fuller cases
before they can be claimed measured.

Duplicate true confirmations do not increase unique recall, but are included
as true confirmations when calculating precision. New false confirmations,
secure-case confirmations and safety violations are explicit regression gates.

Reports include a fixed five-specialist yield table. Positive cases are
attributed only to the hidden expected specialist; absent specialists show
`NOT_MEASURED`. Secure/noisy cases remain in global false-confirmation metrics
and are not arbitrarily credited to one specialist. Model-call rows record
actual lane, role, provider, model, tokens, and latency, but leave model
quality `NOT_MEASURED` until comparable model-backed runs exist. Missed
positive cases are grouped by failure stage.

## First Baseline

On 2026-10-18 the offline `smoke` suite completed two synthetic cases in a
benchmark-only state root on the block volume. Its report is:

`/root/codex_artifacts/phase33_eval/runtime/artifacts/benchmark-reports/BENCH-12058fe69f3b4cb1b4590644a378f0d6/report.json`

The baseline has one expected vulnerability, zero confirmed detections,
zero confirmed false positives, top-K recall 0, zero target requests, and a
`NOT_READY` conclusion. The exposed download was `NOT_DISCOVERED`: this path
does not currently derive a security hypothesis from the synthetic traffic
response body. It is an observed coverage limitation, not a reason to alter
the answer key or weaken confirmation. Active safety, validator precision,
report accuracy, complete fixture coverage, and production test-matrix
evidence remain unmeasured in this report. No model call was made, and no
monetary cost was inferred without configured prices.

A first scored local `local-smoke` run completed on 2026-10-18:

`/root/codex_artifacts/bughunter-agent/artifacts/benchmark-reports/BENCH-182023bb583d4367ab1fb0dcd46e9da6/report.json`

It recorded one expected and one detected vulnerability, zero false confirmed
findings, top-1 candidate recall 1/1, correct Exposure routing, 16 loopback
requests including setup and cleanup, two objects created and cleaned, and no
orphaned objects. `NOT_READY` is still the conclusion because the suite has
one simple vulnerability class and does not measure model, browser, research,
noisy/mixed, GraphQL, DOM, messaging, delta, or full Phase 30 release gates.

The first noisy secure run is:

`/root/codex_artifacts/bughunter-agent/artifacts/benchmark-reports/BENCH-a2cd677829c64b53afeb166d20f3b853/report.json`

It recorded six false-positive candidates, no confirmed Findings, 18 loopback
requests, one manual-context wait, and one object created and cleaned. Its
campaign outcome was `WAITING_HUMAN`, so the case measures review burden, not
successful automatic triage. Readiness remains `NOT_READY`.
Benchmark contract version `33.3` adds explicit manual-context and campaign
outcome fields; the cited early run is a pre-version-bump baseline, not a
final-build acceptance result.
Version `33.4` adds the isolated model-advice fixture pair and model-call
accounting in scored local campaigns. Each advice packet also retains bounded
primary/challenger/critic statuses, original and suggested orders,
disagreement, and candidate provenance in the synthetic case evaluation.
The report and dashboard show these facts without claiming model quality from
one run. The earlier cited reports are historical baselines, not final-build
model comparisons.

A version-33.4 single-trial `local-advice` comparison is preserved on the block
volume at:

- Deterministic: `/root/codex_artifacts/phase33_eval/advice_pair/reports/BENCH-91126d3b0b0d4230bafb328d9011e9c7/report.json`
- Fake primary/challenger/critic: `/root/codex_artifacts/phase33_eval/advice_pair/reports/BENCH-0f51557dd9d549afb4a1559b1e2b5869/report.json`

The deterministic run missed the noisy positive; the fake-provider run found
it. Both had zero false confirmations, safety violations, and orphaned
objects, with `NOT_READY` readiness and unknown dollar cost. This single
comparison does not establish model benefit: equal-score noisy leads caused
different outcomes across repeated runs, and the fake providers supplied
ordering only, not novel hypotheses. Stability and attribution remain open.

The version-33.5 `local-authorization` baseline is stored at:

`/root/codex_artifacts/phase33_eval/tenant_pair/reports/BENCH-b182fcb1abca4631812f0543811a0ef7/report.json`

It has one expected and one confirmed cross-tenant read, top-1 recall 1/1,
correct specialist and skill routing, zero false confirmations, 30 total
loopback requests, four created and cleaned fixtures, and no safety or orphan
events. Precision/recall of 1.0 describe only this two-case pair; readiness
remains `NOT_READY` and most required categories remain unmeasured.

The version-33.6 four-case access-control baseline is stored at:

`/root/codex_artifacts/phase33_eval/access_control/reports/BENCH-a79e3532a5c144cda7f6b8592a37cde2/report.json`

It detected two of two vulnerable roots with no guarded false confirmations,
70 loopback requests, eight created and cleaned fixtures, and zero safety or
orphan events. These are two closely related synthetic authorization classes,
not general authorization recall. The mutation pair ended in `WAITING_HUMAN`
after the first selected plan, and eight of ten candidates across the four
cases did not match hidden vulnerable roots. That review load and blocked-work
state remain open planner/campaign quality issues. The wait follows the
existing object safety rule: a completed plan releases its fixture to
`CLEANUP_PENDING`, so a second candidate cannot silently reuse it as a fresh
control. Version `33.7` additionally attempts cleanup of every created
synthetic object even if one cleanup raises, and records the failed attempt as
an orphan and safety event. The version-33.6 report above predates that
fault-handling change. Browser, research, model,
GraphQL, DOM, messaging, and real-world quality are still unmeasured.

The version-33.8 `local-mixed` baseline is stored at:

`/root/codex_artifacts/phase33_eval/mixed/reports/BENCH-696ee16b1e934918861e789dda0a84e1/report.json`

It recorded 0/2 detections, 19 unmatched candidates across both cases, zero
false confirmed Findings, 46 loopback requests, four created and cleaned
fixtures, and two manual-context waits. The vulnerable case had no expected
root in its top ten. Readiness remains `NOT_READY`; this is a retained failure
baseline for discovery and ranking, not a pass for the mixed-target gate.

The same-tenant horizontal pair has a retained pre-fix report and a version-33.10
post-fix report on the block volume:

- Pre-fix: `/root/codex_artifacts/phase33_eval/horizontal/reports/BENCH-66c920c24e6a47b8a80c20abe5329013/report.json`
- Post-fix: `/root/codex_artifacts/phase33_eval/horizontal/reports/BENCH-3df2116f881c4ce5b5e3b17c9431e452/report.json`

The pre-fix projection gave top-1 recall 0 because it labeled both
Authorization-routed candidates `OTHER`. The corrected projection gives top-1
recall 1/1 with the expected specialist and skill. Confirmed recall is still
0/1: both campaigns end in `WAITING_HUMAN` without validation. The guarded
case has zero false confirmed Findings but two review candidates. Each case
used 15 loopback requests and cleaned both objects. Readiness remains
`NOT_READY`; the evaluator fix is not a hunting-engine improvement. The formal
regression comparator returns `NOT_MEASURED/INCOMPARABLE_FIXTURE_SET` across
these two reports because the benchmark protocol version changed. The numbers
above are a same-fixture diagnostic contrast, not a comparable release gate.

## Evaluation Control Plane

The private BugHunter service exposes read-only `/v1/evaluation` routes for
visible suites, bounded run listings, run summaries, paged case outcomes,
comparison, and readiness. A missing benchmark ledger is reported as empty
without creating one. The dashboard gateway exposes only these GET routes to
authenticated users and rejects evaluation POSTs and unknown query keys. The
separate `/hackbot/evaluation` view labels results `SYNTHETIC / EVALUATION`
and displays measured metrics, specialist yield, model usage, failure analysis,
advice comparison, readiness gates, case outcomes, and regression
comparison. Local browser smoke tests cover desktop/mobile rendering; gateway
tests cover auth and route filtering. These controls do not launch benchmarks.
An asynchronous, resource-admitted run/status API with CSRF-protected start
and cancellation controls is still required by the Phase 33 objective.

## Post-Acceptance Work

The current-source 78/78 matrix and 19/19 low-resource baseline have passed.
The exact results and unmeasured readiness gates are in
`docs/PHASE33_ACCEPTANCE.md`. Phase 33 delivers the evaluation framework; it
does not certify the hunting system as ready for unattended real-target work.

- Improve the missed GraphQL, horizontal, and mixed-target paths without
  weakening validators or hiding failed cases. Measure false-candidate load
  and manual-context waits after each change.
- Keep exhaustive repetitions and live-provider comparisons optional,
  operator-invoked work in `docs/EXTENDED_BENCHMARK.md`; report only runs
  actually executed.
- The authenticated dashboard and evaluation API remain read-only.
  Asynchronous web run controls are deferred pending resource admission and
  CSRF protection. The CLI provides the checkpointed operator path.
