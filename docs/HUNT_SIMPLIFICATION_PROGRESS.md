# Post-Phase-33 Hunt Simplification Progress

Source: `/root/.codex/attachments/e1595ae7-e431-404d-bd0d-8cf60d37a558/pasted-text-1.txt`.

This task is **in progress**. Do not expose a `Start Hunt` action until the
synthetic operator journey proves it works without hidden manual API steps.
Do not send real-target traffic or modify production recon while implementing.

## Current Worktree Boundary

- `/root/bughunter-agent` has pre-existing uncommitted schema-49 reusable
  package-ID changes. Preserve them. The running service is already schema 49.
- `/root/enhanced_recon_framework/.git` is an empty directory, so Git cannot
  report a diff there. Inspect touched dashboard files directly and preserve
  the rest of the deployment.
- The dashboard is bind-mounted into its container. The BugHunter Python
  process does not load new source until its service is deliberately restarted.
- The new source expects local BugHunter SQLite schema 51 while the running
  service still owns schema 49. Do not restart it with this worktree until a
  backed-up, reviewed schema-51 migration is performed; ordinary startup must
  remain fail-closed on a schema mismatch.

## Implemented In This Pass

- Saving valid `accounts.yaml` metadata now imports identities through the
  existing registry service; failed import restores the previous account file.
- Invalid aliases identify `accounts.alias`; normal UI shows the observed
  registration result and keeps manual retry in Advanced account actions.
- BugHunter local schema 50 now contains a target-scoped hunt state/event ledger
  with the specified top-level states, an active-target lock, and unique campaign
  linkage constrained by package version and policy hash. The downstream
  campaign handoff is wired, but Start Hunt is not exposed.
- A backend HuntSupervisor now registers configured accounts, resolves recon
  without using it for authorization, reuses captured sessions, retires stale
  sessions through supported teardown, and provisions Burp-routed login
  sessions when local resources permit. Accountless active hunts also provision
  or reuse anonymous Burp capture. PLAN_ONLY preparation avoids browser
  startup. The primary operator UI remains pending.
- Local-only restart reconciliation marks interrupted mapping/preparation for
  safe re-preparation, preserves approval gates, settles completed linked
  campaigns, and stops ambiguous campaign starts for review. It does not
  dispatch target traffic during startup.
- Verified login/identity confirmation now schedules target-scoped preparation
  automatically, with a pending-wakeup flag to avoid losing a second login
  event. The worker now hands READY to a linked campaign, but this path still
  needs the synthetic operator E2E and failure-injection gates.
- `GET /v1/targets/<package-id>/hunt` exposes durable state, event history,
  and actionable login/identity-review items without mutating state. The
  authenticated dashboard gateway can forward it, but no Start Hunt action is
  exposed yet.
- Manual login can be explicitly bound to its configured alias with
  `OPERATOR_CONFIRMED` provenance. A later stable identity signal upgrades it
  to automatic verification or fails closed on mismatch.
- The existing Sessions dashboard now offers that confirmation only for a
  session awaiting manual identity review. The operator must type the exact
  configured alias; the gateway continues to require authentication and CSRF.
  The action is hidden until the service returns its new verification field,
  so the live schema-49 process does not present a nonfunctional control.
- Local hunt-ledger, store-migration, campaign-store, and service suites pass;
  the latest combined hunt/service run passed 75 tests.
- The dashboard gateway suite passes (22 tests), and dashboard JavaScript
  syntax passes. These checks do not replace the required operator E2E test.
  No real-target request was sent and no service was restarted for this change.
- A local Chromium check confirmed that the synchronous Playwright driver fails
  when preparation starts it on one thread and login verification observes it
  on another. Production runtime construction now uses a single owning-thread
  actor; a cross-thread local browser test passes.
- Playwright route fulfillment of a 302 was observed to bypass interception on
  its next hop. The DOM experiment now aborts all browser redirects. A bounded
  read-only navigation primitive follows approved top-level redirects using
  a fresh tab and a fresh per-request gate; non-read methods are blocked.
- The first-class ApplicationMapper now selects bounded safe links from an
  authenticated browser, records redacted structural Evidence, and uses a
  BrowserActionExecutor that requires verified identity, active Burp routing,
  recorded policy decisions, one-use permits, rate reservations, and new
  TrafficStore capture. The gate paces transient 1 req/s pressure within a
  short bound and rejects unsafe redirect queries. The supervisor now
  dispatches it for verified account sessions.
- Local Chromium navigation, redirect, and write-block tests pass. Chromium
  background requests were observed despite background-networking flags, so
  capture-required Playwright sessions now use a loopback origin guard before
  Burp. It accepts only TargetPackage-scoped hosts/schemes/ports, denies
  malformed or unrelated requests, and closes with the browser. HTTPS path
  restrictions cannot be enforced at CONNECT time and therefore fail closed.
  The separate automated navigation gate still owns permits, rates, policy,
  and TrafficStore capture checks.
- The latest affected browser/Burp/mapper/hunt/service run passed 142 tests,
  including local Chromium, guard, mapping-resume, and historical migration
  checks. The full source-bound Phase
  30-33 matrix and operator E2E remain unrun, so this is not completion
  evidence.
- The preparation worker now invokes bounded authenticated ApplicationMapper
  work after all configured account sessions verify. Schema 50 checkpoints
  per-session mapping counts, so restarted mapping can skip completed sessions.
  Capture/identity loss fails into review, and a disappeared session gets one
  local re-preparation attempt. READY now links a single existing-architecture
  campaign and launches its worker; a post-create/link ambiguity requires
  review rather than replay. Supervised campaign work asks for approval before
  higher-risk policy-permitted actions. This is not yet an operator E2E proof.
- A focused 94-test policy/hunt/service run passed, followed by a 20-test hunt
  run including local anonymous capture reuse and stale teardown. The full
  source-bound Phase 30-33 matrix remains unrun for this change.
- The combined policy/hunt/service/campaign regression run passed 133 tests;
  Python compilation and `git diff --check` also passed. These are focused
  checks, not the required synthetic operator E2E or full matrix.
- Captured-session startup now waits up to 32 seconds for the local Burp
  bridge/listener to become ready, covering the extension heartbeat interval.
  A focused 21-test hunt run passed after this change, including anonymous
  fail-closed release. The expanded affected policy/hunt/service/campaign/
  browser/Burp run then passed 184 tests. The full source-bound matrix and
  synthetic operator E2E remain pending.
- A POST Start Hunt service action now creates one durable run, rejects duplicate
  starts, and dispatches preparation asynchronously. Policy and resource
  failures have explicit response or persisted states. The dashboard proxy
  enforces authentication, CSRF, and an exact Hunt route. A basic Hunt view and
  target-detail Start Hunt action exist behind the default-off
  `HACKBOT_HUNT_UI_ENABLED` gate; no production rollout or service restart was
  performed. A local Chromium UI fixture clicked Start Hunt and observed a
  single proxied request and LOGIN_REQUIRED view. The full gateway suite passed
  25 tests and the affected BugHunter suite passed 188 tests. The browser
  fixture mocks the backend, so it does not satisfy the full operator E2E gate.
  The existing desktop/mobile UI smoke test also passed with the gated Hunt
  navigation enabled in its local fixture; the Hunt view itself was checked at
  desktop and 390px mobile widths without horizontal overflow.
- A local dashboard-to-service integration fixture now exercises authenticated,
  CSRF-protected TargetPackage creation, three-account registration, Start Hunt,
  captured login-session preparation, and a login handoff over the same gateway
  route used by operators. The Hunt view can complete login and explicitly bind
  the configured alias in one action; successful binding immediately moves
  `LOGIN_REQUIRED` to re-preparation, while automatic verification remains
  distinct and any observed partial identity conflict fails closed. A running
  identity-review browser remains reopenable for inspection. The expanded
  browser/supervisor/service suite passed 111 tests, the gateway suite passed
  25, the gateway-to-service fixture passed 2, and the local Chromium dashboard
  smoke suite passed 8. Fake browser/Burp adapters and mocked UI API responses
  mean these checks do not prove synthetic login, target capture, mapping,
  experiment execution, validation, cleanup, or finding/report completion.
- The target wizard now exposes the existing action-specific autonomy decisions
  for owned object creation, modification, deletion, and cross-identity work;
  the operator path keeps `owned_test_objects_only` true. Local target-service
  tests and the Chromium target wizard check pass. This enables policy entry,
  not automatic active experiments by itself.
- After authenticated mapping, a bounded collector promotes only verified,
  complete, in-scope Burp GET/200 JavaScript captures with original body-hash
  matches into current JS artifacts and static analysis. No script is refetched.
  The API specialist can parse REST and GraphQL operations from these artifacts
  even when recon is absent. The collector now treats a clean JS asset with no
  connected DOM signal as analyzed rather than failed. The Hunt mapping step
  automatically runs bounded API/GraphQL inventory over captured traffic and
  current JS; the Hunt status endpoint and view show current JS, API, observed
  API, and GraphQL counts. Expected cold-start recon absence and static GraphQL
  endpoint uncertainty remain inventory gaps, not mapping failures. The latest
  captured-JS/hunt/API/service suite passed 126 tests, the gateway-to-service
  intake passed 2, and the local Chromium Hunt view check passed. These tests
  do not prove the full operator E2E; the source-bound Phase 30-33 matrix is
  still pending.
- A local synthetic dashboard/gateway/service run now uses real headless
  Chromium, three isolated owned accounts across two tenants, three contiguous
  loopback Burp-compatible capture listeners, and the two-tenant SaaS fixture.
  Through the operator routes alone it creates a target, saves/registers three
  accounts, starts a hunt, reaches LOGIN_REQUIRED, completes each synthetic
  login and OPERATOR_CONFIRMED binding, maps all three accounts, records
  identity-attributed TrafficStore exchanges, acquires current JS, inventories
  REST/GraphQL operations, and links a campaign. The test passed in about 91
  seconds under a 1 request/second target policy. It has **not** yet proved
  disposable-object creation, cross-tenant experiment, validation, cleanup,
  finding, or report, so the required full E2E gate remains open.
- That browser-backed test exposed a capture deadlock: Burp ingestion called
  `PlaywrightBrowserActor.is_running()` while the actor thread was waiting for
  the captured browser response. The actor now publishes a locked running-
  session snapshot; a deterministic concurrency regression passes. The local
  synthetic capture fixture supports only exact-loopback plaintext CONNECT
  tunnels, and the mapper skips an alternate-scheme root for the already
  authenticated host. Focused actor, mapper, and capture tests passed (5 tests,
  one optional Chromium check skipped); the three-account gateway E2E passed.
  No production service was restarted and no real-target request was sent.
- A verified `MANUAL_LOGIN` browser can now provide only destination-matching
  cookies to `TrafficExecutor` at its trusted execution boundary. The path
  requires the same target, identity, AuthContext, live browser, verified
  session, and capture-required transport; URL scope and cookie domain/path/
  secure/expiry are checked in the owning browser thread. The cookie value is
  not persisted or returned to the dashboard. Missing browser support, stale
  sessions, invalid material, and absent capture fail closed. A focused
  executor test passed a captured local GET with the owned cookie and rejected
  later requests after malformed material or browser teardown. The
  three-account synthetic browser run passed again
  with an in-scope cookie handoff and out-of-scope rejection. It still only
  proves mapping and campaign handoff, not an autonomous vulnerability result.
- Authenticated mapping now asks the API specialist for at most twelve
  passive candidates from its current, bounded REST/GraphQL inventory before
  handing work to the Planner. Candidate count and ready count are visible in
  the Hunt view, but candidates with missing owned-object/actor controls stay
  leads. The local three-account dashboard-to-campaign test proved that API
  leads appear without a manual generation call; the 24-test supervisor suite
  and JavaScript syntax check passed. No additional target requests are
  authorized by this generation step.
- Authenticated mapping now retains only scoped, query-free static form action,
  method, and non-secret field-name/type metadata in structural Evidence. It
  never captures form values or submits forms. The existing ObjectFactory
  recipe serializer accepts a tightly restricted single-`name` URL-encoded
  POST body for an observed HTML form. Current first-party JS extraction can
  recognize a literal API path prefix plus one `encodeURIComponent(id)`
  segment, including one static suffix; these remain passive route hints.
  Synthetic Chromium and focused mapper/recipe/AST checks pass. No learned
  recipe has been created and no active experiment has run yet.
- The supervised campaign policy now permits only ObjectFactory-sourced,
  policy-allowed safe disposable create/update/delete actions without a
  redundant approval. Arbitrary caller-authored writes, cross-identity
  actions, provisioning objects, and elevated side effects retain their
  existing approval/deny behavior. A focused policy regression passed; this
  does not yet produce an autonomous fixture or vulnerability finding.
- A passive learner now correlates a mapped name-only create form, current
  hash-verified first-party JavaScript detail/delete routes, and a captured
  owner JSON response before adding a private atomic ObjectFactory recipe.
  The three-account local operator journey learned separate org1/org2 document
  recipes and reached campaign handoff. Its shared 30-request/minute ceiling
  initially cut off the third account; browser navigation now waits for the
  next legal rate slot before page startup. The rerun passed in 103 seconds
  without changing the TargetPackage rate. Focused rate/navigation/recipe
  tests passed (10 tests). This remains a passive recipe and campaign-handoff
  proof, not active validation or a finding.
- Schema 51 now links Hunt-owned fixture plans to the run before a write is
  dispatched. The supervisor created two distinct-tenant synthetic documents,
  verified them through ObjectFactory, and followed current JS-advertised owner
  preview routes. The three-account dashboard-to-campaign test passed with at
  least one READY API authorization candidate. Focused recipe/ObjectFactory/
  Hunt-store tests passed 28/28; a separate orchestrator/executor run passed
  33/33. The required cross-tenant experiment, validation, cleanup, and report
  are still unproven.
- The first terminal E2E check exposed a real integration gap: the plan runner
  rejected verified manual-login sessions as `BOUND_IDENTITY_UNVERIFIED` even
  though the executor has a captured, destination-matched browser-cookie path.
  The orchestrator now accepts only an exact valid, identity-matched,
  capture-required browser session and leaves cookie extraction in the
  executor. The next local synthetic run reached and completed an active plan
  under the existing 1 req/s policy, then incorrectly requested login for a
  static API lead that the API specialist had marked `PLAN_ONLY`. The
  autonomous Planner now leaves such API leads deferred until their proof
  prerequisites exist. A focused ranking regression passed; the full journey
  has not yet been rerun successfully after that change.
- A validated planner finding now wakes the existing notification worker and
  requests a deterministic report draft immediately after the validation
  task, without waiting for campaign completion. Raw candidates do not trigger
  report generation. The focused handoff test passed. Existing confirmed-
  finding notification deduplication and evidence gates remain unchanged.
- The latest browser-backed rerun could not reach target creation because the
  local gateway returned 503 while the VPS had under 200 MiB available RAM
  and full swap. The broader synthetic planner suite also suffered fixture
  timeouts under that pressure. These are not acceptance results; production
  services and the operator browser were left untouched. No real-target
  traffic or production restart occurred.
- After resource recovery, the full local dashboard/gateway/service/operator
  journey passed for both the planted cross-tenant flaw and its secure
  counterpart. The vulnerable fixture produced a validated finding and report
  draft; the secure fixture produced none. Both runs used three owned accounts,
  isolated captured browsers, current JS/REST/GraphQL inventory, learned
  disposable recipes, an active authorization experiment, and verified cleanup
  of the two synthetic documents. The two acceptance tests passed separately
  in 123 and 125 seconds. No real target was contacted.
- Autonomous planner selection now defers API leads whose proof prerequisites
  are not READY, avoids reusing one owned object for parallel branches, and
  suppresses already attempted campaign sources. A legacy stale-refresh test
  now supplies an explicit READY registry fixture; missing-source deferral has
  its own negative control. The focused supervisor/planner suites passed 110
  tests.
- Failure checks now cover browser crash, account-session expiry, Burp listener
  loss, gateway restart, service restart, stale anonymous capture, missing
  anonymous capture, recon absence, subdomain/wildcard resolution, resource
  admission, timeout, and bounded oversized HTML across focused tests. On
  production WSGI startup, only runs marked safe by durable reconciliation are
  relaunched; synthetic app construction remains traffic-free. The gateway
  suite passed 26 tests. These are focused cases, not yet the final source-
  bound matrix result.
- Temporary preparation capacity pauses now receive a bounded retry on the
  existing production scheduler's 60-second cadence. A linked campaign pause
  is not replayed. Focused retry and scheduler tests passed; global adaptive
  information-gain depth remains future work.
- The first full source-bound matrix passed the first eight groups but failed
  in the final planted-bug E2E: the Planner tested a secure detail route first,
  then `KNOWLEDGE_STABLE` stopped the campaign while a distinct preview route
  for the same owned object remained deferred. Campaigns now preserve the
  one-branch-per-object-per-cycle guard, but continue a bounded next cycle for
  that deferred sibling route. Two focused regressions pass. An isolated
  planted-bug journey passed after this change, though the VPS's full swap and
  concurrent workload stretched its runtime to five minutes. Synthetic wait
  deadlines were widened without changing target rates or security gates.
- The rerun of the full source-bound Phase 30-33 matrix completed successfully
  on 2026-10-21: all nine groups and 92 test modules passed, including the
  planted cross-tenant flaw and its secure counterpart in the local operator
  E2E. This verifies the settled source against the matrix, but does not
  deploy the default-off Hunt UI or authorize any real-target traffic.
- The final local dashboard Chromium smoke suite passed 8/8 tests; dashboard
  and API-AST JavaScript syntax checks and `git diff --check` also passed.
- The normal Start Hunt path now uses a global Hunt campaign ceiling of eight
  cycles, 160 requests, 64 browser actions, four research requests, and four
  owned setup objects with twelve cleanup-reserved requests. Per-cycle work
  contracts under observed host/browser/Burp/latency/duplicate pressure; a
  recent in-scope captured 429 pauses new work for a two-minute cooldown.
  Distinct current candidates can extend a stable-context cycle only when
  they fit the next bounded tranche. Policy and TargetPackage rates are
  unchanged. Focused adaptive/resource/campaign/Hunt/service/scheduler tests
  passed 185/185; the planted-bug local E2E passed and the secure counterpart
  passed on a focused rerun after one intermittent failure under VPS load.
- The primary Hunt endpoint and view now show campaign progress, findings,
  report drafts, cleanup, CPU/RAM/swap/disk, browser/Burp occupancy, median
  response time, and the next request tranche or throttle reason. The local
  Hunt UI desktop/mobile smoke check passed. These source edits invalidate the
  earlier full-matrix fingerprint, so a new authoritative matrix run remains
  required.
- The final source-bound Phase 30-33 matrix completed on 2026-10-21 with all
  93 modules in nine groups passing (fingerprint
  `c47eed4bc6c17846bcaa98844d0be632236f480bf52dabe47f02d3f28cbfb248`).
  Its local operator E2E passed both the planted cross-tenant flaw and secure
  counterpart, including owned disposable creation, captured browser sessions,
  current JS/API/GraphQL inventory, active authorization proof, cleanup, and a
  finding/report only for the planted case. The full local dashboard gateway
  suite passed 28 tests; the Chromium UI smoke passed eight. Dashboard and
  API-AST JavaScript syntax checks and `git diff --check` passed.
- The matrix exposed and then cleared two integration regressions: non-API
  plans no longer receive an API-only exact-traffic argument, and non-Hunt
  campaigns do not enter the Hunt-owned object recheck. The synthetic browser
  benchmark now uses fixed local resource observations so ambient VPS swap does
  not turn a planted postMessage case into a false miss; production resource
  admission and pressure tests remain unchanged. Skill context traffic is
  constrained to the exact TargetPackage as well as target ID.

## Deployment Boundary

The requested synthetic completion gate is met. Focused failure-injection
tests cover restart, session expiry/crash, lost Burp capture, anonymous capture,
resource pressure, recon outage and wildcard resolution, timeout, and bounded
oversized HTML. The dashboard restart is covered inside the local operator
E2E. These tests do not claim every combination was reproduced as a separate
process-level browser E2E.

The deployed `bughunter-agent.service` remains inactive: its local BugHunter
SQLite schema is 49 while this source expects schema 51. The Hunt UI is
default-off in the dashboard. Before an operator can use Start Hunt on a real
target, review and back up the local BugHunter store, migrate it to schema 51,
deploy/restart the matching service, enable the Hunt UI in a controlled window,
and verify readiness without starting target traffic. No production recon
write, real-target request, service restart, or real campaign was part of this
implementation/verification.

## Next Operator Step

Plan a reviewed deployment window for the backed-up schema migration and
service/UI rollout. Keep Start Hunt disabled until the tested source and local
schema match; path-restricted browser targets remain fail-closed until a
path-aware capture transport exists. The synthetic finding is acceptance
evidence, not a real bug-bounty finding.
Do not create a second target persistence model or bypass capture/permits.
