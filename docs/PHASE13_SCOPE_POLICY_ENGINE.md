# Phase 13: Scope, Risk, Rate, and Approval Policy

Phase 13 adds a deterministic pre-execution policy boundary. It does not send
target requests, replay traffic, navigate a browser, or issue executable
permits. The authoritative Target Package remains separate from recon inventory.
An LLM or browser client may propose an action but cannot decide its scope or
risk.

## Action and decision contract

`ProposedAction` is a typed, stable-ID proposal with target/package,
category, actor mode, optional hypothesis/evidence references, URL and method,
operation and object classification, identity/session references, side-effect
and risk hints, source, purpose, and timestamp. It never contains credentials.
The raw URL stays in memory for scope evaluation; local audit rows retain only
an action fingerprint and safe metadata, not URL queries or bodies. Object
references are SHA-256 fingerprints, not raw application IDs. Client hints can
raise risk but cannot lower deterministic classification.

`PolicyEngine.evaluate` returns an immutable `ActionDecision` with ALLOW,
DENY, or REQUIRE_APPROVAL, stable reason code, scope result/matched rule,
matched policy layer, classified risk/side effect, target, timestamp, and a
digest identifying the Target Package policy and engine version. The decision
is a **simulation**, not permission to send a request. The engine records
ACTION_PROPOSED, SCOPE_EVALUATED, POLICY_DECIDED, and approval lifecycle events
in append-only BugHunter SQLite history (schema version 9). It never writes to
recon PostgreSQL or copies Evidence bodies.

## Scope and risk gates

`ScopeGuard` requires an affirmative `ProgramScope` decision for every
network action. Missing, malformed, ambiguous, encoded-path, userinfo,
unsupported-scheme, excluded, or unlisted destinations deny. Explicit
exclusions override inclusions. A local passive action may omit a URL;
active actions may not. Recon presence is never an input to authorization.
`evaluate_redirect` creates a new action for the destination; future
executors must check **every hop** before following it. They must also
revalidate destination identity where DNS resolution/rebinding or IP-sensitive
behavior can change the effective target. This phase does not implement a
network sandbox or DNS pinning.

`MethodPolicy` rejects incompatible or missing methods but does not infer
harmlessness from GET or danger from POST alone. `SideEffectClassifier`
deterministically maps category, method, known operation/path verbs, object
type, and non-downgrading hints to PASSIVE, SAFE_READ, SAFE_CREATE,
SAFE_UPDATE, SAFE_DELETE, EXTERNAL_SIDE_EFFECT, PERMISSION_CHANGE,
FINANCIAL, DESTRUCTIVE, or UNKNOWN. Unknown effects require approval when
the package permits a review path, otherwise deny. Financial and destructive
actions default to DENY. Structured forbidden actions and excluded
vulnerability classes are checked before autonomy.
Creating an account/user/identity uses the package's separate account-creation
policy, not the generic disposable-object creation permission. Sensitive
operation/path labels such as invite, role change, checkout, and purge can
raise the classification even when a caller selects a generic object category.

`AutonomyPolicy` and `ProgramRules` from the package determine the
effective decision. Client-supplied ownership flags cannot authorize changes
to existing objects: the engine requires a trusted owned-object verifier.
Without one, update/delete and cross-identity actions on an alleged disposable
object deny. Creation requires disposable intent and a package policy that
allows it. Authenticated actions require an ACTIVE target-matched Identity
and a running, identity-matched, VALID BrowserSession/AuthContext. Anonymous
read actions need no Identity. Future executors must ensure ANONYMOUS actions
carry no ambient cookies or credentials.

## Rate and budgets

`RateLimiter` is a bounded, target-scoped in-memory token bucket with
per-second refill, optional rolling per-minute cap, burst capacity, and
concurrency reservations. Its trusted `ExperimentBudget` accounts for
requests, mutations, object creations, and retries. Simulation checks
availability without consuming tokens. A future executor must reserve
atomically immediately before execution and release its concurrency slot
afterward. One trusted service process owns this state; restart persistence,
distributed coordination, and crash recovery are Phase 14 design work, not
claims of current enforcement.

## Approvals and permits

REQUIRE_APPROVAL creates a target-scoped request bound by a fingerprint to
the exact action ID, target, category, risk, hypothesis, identity/session,
operation, object fingerprint, and policy version. It expires after 30
minutes. The authenticated dashboard supports Approve once and Reject; no
broad hunt-wide approval is implemented. Duplicate same-state decisions are
idempotent. An approved request affects only an identical re-evaluation
while current scope, identity, program policy, and rate checks still pass.
`claim_once` atomically consumes it for a future permit issuer; wrong action,
target, version, or expiry fails.

`PolicyPermit` describes the future short-lived, action-bound executor
contract. Phase 13 **does not issue permits**. Phase 14 must require an
unexpired permit/decision ID, re-evaluate the current package, claim a
one-time approval if needed, reserve rate/budget capacity, and bind the
permit to action fingerprint, scope, target, and identity. State-changing
permits must be one-time. No TrafficExecutor, BrowserAction executor, Burp
replay, ObjectFactory, or specialist agent may receive unrestricted target
networking that bypasses this boundary. Policy service failure means no
active execution.

## API, CLI, and dashboard

The private service exposes `POST /v1/policy/evaluate`,
`GET /v1/approvals`, `POST /v1/approvals/{id}/approve|reject`,
`GET /v1/policy/actions/{id}/history`, and
`GET /v1/targets/{package}/policy`. The existing dashboard gateway forwards
them under `/api/hackbot/*` with its authentication and POST CSRF gate; it
does not forward dashboard credentials. The HackBot Scope page contains a
simulation form, the target detail has a Policy tab, and Approvals has a
target-scoped list. UI strings are rendered as text, not HTML. CLI
`hackbot policy check <target> <url> --action safe-read` records a local
simulation; `hackbot approvals list <target>` reads local approval metadata.
Neither command sends target traffic.

## Phase 14 handoff

Implement the vendor-neutral TrafficExecutor behind this policy boundary.
Begin with a local fixture transport and prove permit binding, one-time
consumption, current-policy recheck, redirect/DNS checks, verified identity
and anonymous separation, rate reservation/release, and protected TrafficStore
capture before enabling any in-scope live request. Do not let Burp, browser
navigation, ObjectFactory, or agents bypass the same executor policy.
