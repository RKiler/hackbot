# Phase 25: Target and Normal-Behaviour Learning

## Purpose and boundary

`NormalBehaviourLearner` turns bounded existing observations into a target-level `BehaviourProfile`. It is deterministic context for authorization, exposure, and the later GraphQL/API specialist, not a vulnerability scanner or a statement of intended access. An observed success, denial, route, or missing UI control is not a confirmed bug. The tracked Target Package remains authoritative for scope; recon is read-only context and never grants active-testing permission.

Phase 25 does not issue HTTP requests, click controls, submit forms, create objects, change roles, send invitations, or trigger payments. It reads current saved TrafficStore exchanges, Phase 12/24 profile signals, verified session state, identity metadata, and ObjectFactory records. The operator may use the existing VNC/Burp path to capture missing normal workflows; a subsequent refresh consumes them. The learner does not synthesize browser exchanges or bypass Burp capture.

## Persistent model

BugHunter SQLite schema 24 adds `behaviour_runs`, `behaviour_observations`, `behaviour_workflows`, `behaviour_expectations`, and `behaviour_profiles`. Raw traffic is never copied. Observations reference TrafficExchange and Evidence IDs. A workflow groups a bounded set of operations by actor, feature, tenant context, and captured correlation hash (or operation fingerprint). Recurring identical requests do not multiply workflows. Each workflow retains its operation keys, bounded object references, exchange IDs, Evidence IDs, result, and last observation time. Object references from response or path hints are hashed leads, not ownership claims.

`BehaviourProfile` contains features and their source classes, workflows, normalized operations, attributed identities, declared roles/tenants at capture, anonymous observations, verified disposable objects, path-derived object leads, ownership controls, role-feature and role-operation matrices, expectations, coverage, gaps, and provenance. REST, GraphQL, RPC, and browser responses share a generic operation key and action (`VIEW`, `CREATE`, `UPDATE`, `DELETE`, `EXPORT`, `SHARE`, `INVITE`, `APPROVE`, `TEST`, or `UNKNOWN`). The original method, safe path shape, origin, operation ID, parameter names, GraphQL operation name/type/variable names when parsable, and protected body Evidence reference remain available. Raw parameter values and bodies do not enter the profile. Phase 26 can consume this metadata and retrieve Evidence under existing access controls.

Path- and JSON-response-derived IDs are represented only by stable hashes. Response owner, tenant, and parent fields become hashed claims linked to Evidence, not authoritative relationships. These leads do not establish ownership. Verified ownership requires a READY disposable ObjectFactory record with read-back Evidence and matching active `OBJECT_FACTORY` Facts for creator and tenant. The learner may add deduplicated evidence-backed `owned_by` and `belongs_to` Facts for these records; it does not infer ownership from who viewed an object. Known-good controls point to verified objects, owning identities, tenants, and Evidence. The existing Fact Store remains the object graph; no graph database is added.

## Access and response semantics

The role-feature and role-operation matrices use `OBSERVED`, `NOT_OBSERVED`, and `UNKNOWN`. `NOT_OBSERVED` means a sampled verified role had other traffic but no matching operation; it is never a denial. An explicit 401/403 or a GraphQL authorization error code becomes `OBSERVED_DENIED`. A GraphQL HTTP 200 with errors or null data is not marked allowed. A 2xx response with no body or no positive result signal remains `UNKNOWN`; an explicit success or substantive structured response is only an observed success, not durable side-effect proof.

Manual access expectations can be saved as `CONFIGURED_EXPECTATION` with `RESEARCHER`, `PROGRAM_POLICY`, or `PRODUCT_DOCUMENTATION` provenance. Unconfigured observed rows are `OBSERVED_PATTERN`; missing rows are `UNKNOWN`. Neither an observed UI difference nor repeated successes silently becomes a policy rule. Phase 19 uses a learned role-operation gap only as a small ranking signal after its existing verified owner/object/tenant gates pass. Phase 23 uses an authenticated export observation only to enrich an already-matched owner/anonymous exposure lead; Phase 17 still controls confirmation.

## Runs, freshness, and gaps

Runs use `CREATED`, `READY`, `RUNNING`, `WAITING_LOGIN`, `PARTIAL`, `COMPLETED`, `BLOCKED`, `CANCELLED`, or `FAILED`. Only one active run per target is allowed. Interrupted created/ready/running runs become partial on service restart and are never replayed automatically. A configured account with no currently valid verified session yields `WAITING_LOGIN`; historical verified traffic may still inform the saved profile but is not a current login. Unverified or wrong-identity captures are excluded from trusted learning. Anonymous observations are kept separate.

Defaults: 4 representative identities, 3 observed HTML pages per identity, 60 workflows, 90 seconds, 160 traffic records, 50 verified objects, and 14-day freshness. Hard caps are enforced by `LearningLimits`. Representatives favor role and tenant diversity among currently verified sessions; all reads are target-scoped, paginated, and limited. Existing traffic is processed before any manual gap action. A repeat with no new observations reports `STABLE_EXISTING_DATA`. Budget exhaustion is `PARTIAL`, not complete coverage.

Coverage is `NONE`, `PARTIAL`, `GOOD`, or `STALE`, with counts and sampling markers; it never claims exhaustive application coverage. Old observations or observations predating recent JS/endpoint signals are marked stale. Gaps identify the next small operator action, such as verifying a second role, capturing a second-tenant control, confirming an owned object, or refreshing a changed workflow. There is no continuous scheduler in Phase 25.

## Private API and dashboard

The private service exposes `GET /v1/targets/{package}/behaviour` plus `coverage`, `features`, `workflows`, `matrix`, `gaps`, and `runs/{run_id}` reads; `POST /behaviour` and `/behaviour/refresh` start a bounded passive run; `POST /runs/{run_id}/cancel` requests cancellation. `POST /behaviour/expectations` records a manual expectation. No route accepts an arbitrary target URL, browser action, raw HTTP body, or test payload. The same-origin `/api/hackbot/` gateway requires dashboard authentication and CSRF on all POSTs, strips client credentials, and allowlists these routes.

The Behaviour panel shows run state, coverage, gaps, attributed identities, features, workflows, normalized operations, role matrices, objects with evidence references, and run history. `Start learning`, `Refresh missing coverage`, and `Cancel` are the only controls. An expired account is directed to the existing VNC login/verification path. The Objects page remains the source of full disposable-object lifecycle and cleanup state.

## Verification and Phase 26 handoff

Local fixtures cover multi-role and multi-tenant traffic, anonymous capture, GraphQL 200 denial, explicit 403, absent UI observation, Burp-attributed traffic, out-of-scope exclusion, stale data, wrong identity, reauth wait, verified object/parent Facts, duplicate-free reruns, budgets, cancellation, dashboard auth/CSRF, and secret-free summaries. No live bounty target is required.

Phase 26 may use saved operation fingerprints, GraphQL names/types/variable names, evidence pointers, role/tenant matrices, and known-good controls to propose field/nested/mutation tests. It must still obtain fresh owned baselines, enforce Target Package policy, and use the independent validator before confirming impact. Broader browser navigation, role changes, account creation, continuous refresh, research retrieval, and cross-specialist planning remain outside Phase 25.
