# Phase 18: Disposable Object Factory

Phase 18 adds a BugHunter-owned, target-scoped ledger for researcher-created disposable application objects. It does not discover target operations, create accounts, run a worker, or authorize traffic from recon inventory. All HTTP requests pass through the existing Phase 13 policy and Phase 14 `TrafficExecutor`/`TrafficStore` boundary. Tests use a loopback fixture, not bounty targets.

## TestObject and lifecycle

SQLite schema 14 stores a stable `TESTOBJ-*` ID and Phase 4-style `OBJECT-*` reference, target/package, object type, creator Identity, tenant, optional parent/PlanRun/Hypothesis, creation action/exchange, recipe ID/hash, lifecycle timestamps, cleanup strategy, budget counts, Evidence links, and append-only events. The application ID is retained only in SECRET Evidence; SQLite and the dashboard expose a salted fingerprint. No cookie, token, or credential is stored in the object ledger.

| State | Meaning |
| --- | --- |
| `PLANNED` | Valid recipe and target-owned creator/tenant recorded; no request sent. |
| `CREATING` | Create was policy-allowed and dispatch may have begun. |
| `CREATED` | Response supplied a constrained object ID; ownership is not yet proved. |
| `VERIFYING` | Owner read-back is in progress. |
| `READY` | ID, generated name, owner, and tenant matched a current owner read-back. |
| `IN_USE` | Leased to a plan or undergoing a verified local update. |
| `CLEANUP_PENDING` | Plan released the object; cleanup is still required. |
| `CLEANING` | Delete/absence read-back is in progress. |
| `CLEANED` | Absence was read back, or an operator explicitly marked external cleanup. |
| `ORPHANED` | Cleanup failed or its outcome is ambiguous; manual review is needed. |
| `FAILED` | Setup failed without a proven object; do not retry automatically. |
| `UNKNOWN` | Setup, read-back, update, or lease outcome is uncertain; do not reuse automatically. |

Startup reconciliation turns interrupted `CREATING`/`VERIFYING` into `UNKNOWN`, interrupted `CLEANING` into `ORPHANED`, and expired/unreserved `IN_USE` into `UNKNOWN`. It does not replay a create, update, or delete. Metadata and events survive cleanup.

## Recipes and execution

Recipes live under `[objects].recipe_root/<package-id>/<recipe-id>.json` (default `<HACKBOT_HOME>/recipes`). They are operator-reviewed JSON data, not executable code or model output. A recipe fixes the target/package, object and optional parent type, REST/GraphQL/RPC protocol metadata, creator alias, tenant label, creation and owner-read operations, constrained JSON-pointer ID extraction, optional rename/delete operations, and cleanup strategy. An optional typed `side_effect` value can raise risk but cannot downgrade an operation. Account, user, tenant, organization, and workspace provisioning types are rejected. URLs must be exact, in-scope at execution, and have no query. Body interpolation is limited to `$test_name`, `$parent_id`, and `$object_id`. The factory does not guess an endpoint, recursively create parents, or automate a browser-only workflow. Missing recipes return `MISSING_CREATION_RECIPE`; missing parents return `BLOCKED_MISSING_PARENT`.

The factory requires an active target-owned Identity and tenant membership, a valid verified SessionContext declaring that identity and tenant, a current target package, and a recipe that has not changed since the object was planned. A generated `hackbot-test-<random>` name distinguishes fixtures from business data. Policy is evaluated anew for every create/read/update/delete, followed by a one-use executor permit and recorded TrafficExchange. A policy approval is not granted by the factory; the same action must be resumed explicitly after approval. There is no anonymous creation fallback.

The shared Phase 13 `SideEffectClassifier` recognizes camel-case operations and path signals. External communication, permission changes, financial/billing, destructive actions, and unfamiliar state-changing operation verbs cannot be promoted to `SAFE_CREATE`/`SAFE_UPDATE`/`SAFE_DELETE` by a recipe category or HTTP method. `SAFE_UPDATE`/`SAFE_DELETE` additionally need a verified, unreserved registered object. Unknown or real objects fail closed. The factory only executes the exact expected safe class for each operation; a high-risk classification is not a route to automatic execution.

Creation uses the returned ID only as a candidate. A separate owner GET must match ID, generated name, creator alias, and tenant label before `READY`. These observations create Evidence-linked Facts for `created_by`, `resource_tenant`, and `disposable`; configured intent alone does not. Cleanup uses the registered object's known recipe and verified ID, then a bounded GET must return 404/410 before `CLEANED`. Ambiguous post-dispatch results are `UNKNOWN` or `ORPHANED` and are never automatically retried.

## Budgets, reservations, and plans

Configuration defaults: depth 2; three objects per plan; 20 new objects per target/hour; four setup requests and three cleanup requests per object. The cleanup allowance is separate from setup and plan experiment budgets. Every dispatch reserves an allowance before sending, including verification. The factory sends at most one request per operation invocation.

Plan requirements are explicitly registered by object type, recipe, Identity, tenant, and optional parent before any run starts. Existing `CHECKING_PREREQUISITES` holds a run until a matching `READY` object can be leased; an operator can create it via the known-recipe API and then advance the run. No plan can silently create an account, send an invite, or improvise a recipe. SQLite transactions and a unique active-reservation index prevent competing runs from leasing the same object. A lease lasts at most an hour; expiry makes the object `UNKNOWN`, not reusable. Terminal plan release moves an in-use object to `CLEANUP_PENDING`.

The cleanup-pending metric counts every cleanup-required object that may still exist, including `READY` fixtures not yet leased. If a pinned recipe disappears or changes, cleanup is not improvised; the object becomes `ORPHANED` for manual review.

## Dashboard and API

The authenticated recon dashboard facade provides `/hackbot/objects` and an Objects tab on target detail. Lists are target-scoped, filtered, paginated, and show safe ID fingerprints, creator, tenant, status, timestamps, cleanup state, and orphan highlighting. Detail shows Evidence IDs, audit events, creation run, and reservation holder, not raw contents. The private service exposes `GET /v1/objects`, `/v1/objects/recipes`, `/v1/objects/<id>`, plus known-recipe create, resume-create, cleanup, and explicit manual `mark-cleaned`. The facade enforces dashboard auth and CSRF for POST. Manual mark-cleaned records `source=MANUAL` and keeps Evidence/history; it does not itself call a target.

## Phase 19 handoff

Phase 19 can consume only observed, Evidence-linked ownership Facts and verified disposable object references for authorization controls. It must still obtain an independent owner baseline, negative control, unauthorized effect/read-back, and duplicate review. `disposable=true` is not a finding or proof of an authorization bug. Browser-only creation, autonomous recipe discovery, real-account provisioning, and live target testing remain deferred.
