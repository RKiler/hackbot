# Phase 22: Browser Messaging Specialist

Phase 22 analyzes current first-party JavaScript from the Phase 21 artifact
cache. It does not import recon findings as BugHunter findings, fetch a second
JavaScript corpus, execute downloaded code, or call a model. A Target Package
remains the authority for active scope; recon metadata is only an inventory.

## Protocol reconstruction

The bounded Babel parser shared with Phase 21 extracts window/self message
handlers, senders, accepted and reply message constants, origin/source checks,
MessageChannel creation, `event.ports`, port binding, and statically visible RPC
method names, argument-field hints, result shape, and read/write hints. A
bounded pass also recovers constant message types, indirect listener registration
through `call`, `apply`, `Reflect.apply`, `Object.defineProperty`, `Reflect.set`,
or `Object.assign`, and constant handler-map RPC keys selected by
`event.data.method`. Dynamic registrations and mutable handler maps remain
manual-review coverage gaps. A selected skill context receives an AST-derived
protocol packet under 2 KiB with handler location, sender/dispatch summaries,
trust-check kinds, port flags, and RPC names; it receives no raw bundle body.
A candidate records the current asset hash, receiver location,
sender contexts, protocol sequence, sensitive-operation hints, and Evidence
references. Reply/receive constants link candidates across assets without a
graph database. A handler fingerprint deduplicates bundled copies. These
links and keywords are hypotheses, not demonstrated reachability or impact.

Origin checks distinguish missing, exact, substring, prefix/suffix, and
unresolved/regex review cases. A check counts as protective only when its
branch guards the first privileged effect; OR-based early returns are
decomposed only when each rejection independently blocks it. Source checks
are tracked independently because
the intended relationship may require both an origin and a specific parent,
opener, popup, or frame. A transferred MessagePort is treated as a capability:
the investigation records who sends or accepts it, whether the receiver binds
an RPC handler, and which read-only method is statically visible. Worker,
SharedWorker, and BroadcastChannel handlers are classified as static-only
architectures; the window-origin browser experiment rejects them. A wildcard
`postMessage` target alone is not a finding. Parsing of wrapper dispatch,
payload shape, dynamic RPC arguments/return types, workers, and port lifetime
remains bounded or requires manual review. The analyzer version is bumped when
trust-classification semantics change so old candidate links cannot silently
be treated as current.

Analysis is capped at 16 ranked assets per inventory, 64 handlers and senders
per asset, 32 protocols per asset, and 16 RPC methods per candidate. The
analyzer version and artifact hash key the cache. Candidate-to-asset links
retain each analysis version; runtime requires a current-version link and a
current recon/retained-body hash match. Current first-party source maps use
the Phase 21 map acquisition and location mapping path.
An explicit reanalysis retries a prior parser failure on the same artifact
instead of treating a transient Node timeout or resource failure as a cleared
asset. Successful or no-signal analyses remain cached.

## Browser experiment

A selected candidate is linked to a successfully observed in-scope HTML page,
an evidence-backed hypothesis, the versioned postMessage skill, and a frozen
Phase 15 plan. Phase 16 claims the browser step before any dispatch. The
browser executor accepts only a current target-bound browser session, exact
observed message type, optional statically discovered method from a short
read-only allowlist whose current AST capability is READ, and an in-scope route
and bundle. The planner and executor both reject a read-named method classified
as WRITE or UNKNOWN. There is no arbitrary
message, RPC, script-evaluation, or URL box.

Each variant starts a fresh isolated Chromium context. The local sender fixture
can embed the victim or open it as a popup when the static protocol references
`window.opener`. Its own page is fulfilled locally; every victim navigation
and subrequest is checked against the current Target Package and Phase 13
policy before the browser request proceeds. Each permitted victim request also
reserves a slot in the service's shared Phase 14 rate limiter and releases it
after the network fetch or on abort. An exception inside the policy/rate route
callback aborts the request before it reaches the victim and counts as a denial.
Per-second rate limits are paced only
within the trial deadline; concurrency and exhausted budgets block proof
immediately. Redirect responses
fail closed: Playwright's route hook cannot be relied on to intercept every
redirected hop, so the specialist does not follow them without a separately
gated transport. A denied request blocks proof.
The fixture attests the exact popup, parent, or sibling WindowProxy used to
send in that trial and binds that attestation to the fresh context ID; an
unattested sender blocks runtime proof. This establishes fixture-side sender
identity, not independent proof that a real attacker controls a same-origin
sender page.
The fixture never reads cookies, storage, or tokens for a proof and records
only bounded synthetic marker/result metadata. For a Phase 21-linked
`event.data.<field>` sink, the frozen plan may add exactly one analyzer-derived
message field carrying a harmless DOM attribute marker. Dispatch keys and
prototype-sensitive properties are excluded. The fixture checks the
attribute only in the exact victim route's document; it does not offer an
operator-supplied payload field or script. Authenticated sessions are
transferred opaquely into the isolated browser context; raw session values are
not put into plans, Evidence, or API output.
For an authenticated read-only `readCanary` RPC, the plan may instead bind one
Phase 18 verified, disposable object owned by that exact identity. It freezes
the BugHunter object ID, the SHA-256 of its test name, and verification time;
the run reserves that object. The current name is passed only in memory to
the local sender fixture as an exact-match comparison value, never as an
attacker message field or persisted trial payload. A matching RPC response
records only its hash and an `OWNED_MATCH` event. The validator reads the
bounded `SENSITIVE` trial Evidence explicitly and checks the current object,
ownership Facts and their target-bound Evidence, the Phase 18 external-ID hash
binding, run reservation window, controls, and fresh context. For non-fixture
assets, private-object visibility must have a trusted target-bound Fact, and
anonymous-read denial must be backed by a BugHunter GET exchange for the same
verified external object ID, captured after object verification and before the
messaging trial. A public owned name or a manually asserted denial is not a
confirmed confidentiality issue.
The harmless DOM marker also sends its marker ID to the local fixture, which
records the browser-provided `MessageEvent.origin`. A matching target URL is
not treated as target-origin execution when a sandbox gives the document an
opaque origin; missing origin attestation stays review-only.
Each trial also records a payload-free, bounded event trace using event names
and milliseconds relative to fixture start. It covers sender attestation,
message dispatch, READY, port creation/transfer, RPC call/response, and proof
marker. The executor and Phase 17 validator share the same counter and ordering
checks; a trace is corroborating protocol evidence, not proof that a real
attacker controls a trusted-origin page.

The fixed controls are no message, one wrong type, a trusted-context baseline,
no port where applicable, a foreign-origin port/message, a wrong source window
for iframe mode, and a lookalike origin only when static origin logic suggests
one. The lookalike fixture uses a same-scheme subdomain for substring/prefix
checks and an `evil-` host for suffix checks; Phase 17 verifies that exact
derived origin. An IP-literal suffix probe is not a valid browser URL, and a
derived host inside the authoritative Target Package scope is not proof of an
unrelated origin. Both are skipped and retained for manual review. The probe
is locally fulfilled rather than sent to that hostname. A proven unrelated-origin effect with a matching trusted control skips a
redundant lookalike-origin trial and proceeds to fresh reproduction. The
wrong-type control retains the same port and read-only RPC call as a
valid message so the type is the only changed dispatch condition. Successful
protected capability proof gets one fresh-context reproduction
and stops. At most eight variants are possible, with at most three messages,
one port, one RPC call, and 24 policy-gated victim requests per variant. There
is no brute-force message-type search or unrestricted RPC invocation.

A separate loopback-only state-change fixture uses a Phase 18 verified,
disposable object and a Phase 20 `TypedMutation(RENAME)` label. It sends a
fixed foreign-origin MessagePort RPC, reads the changed synthetic object state
independently through the victim DOM, and restores the original value. This
fixture validates the browser trust-boundary pattern but does not authorize
production write RPC dispatch or produce a state-change Finding. The current
planner and executor reject methods classified as WRITE or UNKNOWN.

## Validation and data handling

Phase 17 reads the completed run, frozen skill hash and binding, current JS
asset, policy decisions, dispatch ledger, and target-bound MESSAGE_PROOF
Evidence. It requires negative controls, trusted baseline, an unauthorized
origin or window, a protected synthetic data or DOM execution effect, and a
separate fresh context. For a MessagePort disclosure it also requires transfer
evidence, not just channel creation, and a READY event before transfer when the
bound protocol has a second-stage port message. It does not send traffic. A
foreign-origin MessagePort disclosure can be confirmed without an XSS sink; a
listener, wildcard send, status code, or
console message cannot.

The fixed `HACKBOT_SYNTHETIC_PRIVATE` marker can confirm only a locally sourced
`FIXTURE` asset. An identical response from a controlled-HTTP asset remains
manual review. A controlled-HTTP asset can use the separately verified owned
canary path; an unverified or unreserved object blocks before browser dispatch.
The synthetic same-origin sibling fixture confirms missing `event.source`
enforcement only for a locally sourced `FIXTURE` asset. It does not establish
that a real attacker controls content on the trusted origin; non-fixture
source-only outcomes remain manual-review leads until that separate premise is
evidenced. Any excessive
or non-synthetic RPC response is classified for review, not automatically
retained as protected data or promoted to a finding. State-changing messaging
is not dispatched here; a real target still needs a Phase 18 verified
disposable object and a Phase 20 policy/Traffic/read-back/restore chain.

When the shared Phase 21 DOM parser finds a connected `event.data.<field>` to HTML
sink flow on the same current artifact, Messaging exposes the Phase 21
candidate ID as a handoff. Static linkage is not DOM XSS confirmation. A
bounded browser marker can be routed through that field; Phase 17 invokes
`DOMXSSValidator.message_handoff` to verify the current Phase 21 sink trace,
target-document execution, origin, and fresh marker before classifying a
messaging-rooted `DOM_XSS` finding. This does not weaken Phase 21's separate
check-before-transform validator or allow arbitrary message payloads.

## API, dashboard, and audit

The private service exposes bounded inventory, candidate list/detail, analyze,
observed-route binding, plan preparation/binding, runtime status, and metrics
endpoints. The existing authenticated, CSRF-protected recon dashboard gateway
allowlists these routes under `Client-Side > Messaging`. It shows protocol
sequence, trust checks, port/RPC metadata, current hashes, source-map location,
Phase 21 handoffs, plan/run/validation links, and sanitized trial references.
There is no generic message-send endpoint. Skill details and routing metadata
include validation outcome counts without treating them as proof.

The intended audit path is candidate and current JS Evidence to Hypothesis,
frozen skill/plan, Phase 16 run, policy decisions, browser trial Evidence,
Phase 17 validation, and deduplicated BugHunter Finding. Candidate, run, and
validation state is BugHunter-owned SQLite; recon PostgreSQL is unchanged.
A local reopen test verifies that the candidate, artifact hash, run, validation,
and finding still join through that chain after the store is re-instantiated.

## Verification to date

The package-aware full suite passed 478 tests in 1,895.001 seconds on
2026-10-12 using the installed Chromium path for browser fixtures. This covers
the origin-shape probe, current-hash invalidation, owned-canary privacy gates,
wrong-source fixture and non-fixture classification, read-only RPC method gate,
typed local state-change fixture, rate reservations, redirect and gate-exception
fail-closed behavior, and fresh-context proof. A reopened-store test covers
candidate/run/validation/finding persistence. The wheel contains the shared
AST resources, messaging parser, migrations 018-021, and postMessage skill.
The authenticated gateway tests passed 6 cases and the localhost dashboard
smoke test passed at desktop and mobile sizes. All browser proofs used local
fixtures; no bounty target was contacted.

## Deferred boundaries

The production messaging executor intentionally remains read-only. A future
write-capable variant needs a Phase 20 policy, TrafficExchange, independent
read-back, and restore chain before it may reach a real target. Independent
attacker control of a trusted-origin sender is likewise required before a
non-fixture source-only lead can be confirmed. Dynamic RPC maps,
worker/channel runtime experiments, and port lifetime after sender navigation
or closure remain manual-review coverage gaps. These are not covered by the
local state-change or sibling-window fixtures. Phase 23 is a separate
sensitive-exposure specialist and must not begin as part of this work.

Current proof limitations are explicit: the fixed confidentiality marker is
synthetic-fixture-only; the new owned canary path needs a target-implemented
`readCanary`-style method and a fresh Phase 18 object, and no real target has
been tested in Phase 22. Only one analyzer-linked message property is
dispatched per DOM trial. The loopback state-change fixture uses Phase 20's
typed mutation contract and restores its synthetic DOM state, but the
production messaging executor has no Phase 20 MutationResult or restore path.
Worker/channel receivers are classified but not browser-tested. A same-origin
sibling fulfilled by the local fixture cannot establish attacker control of a
real trusted-origin page. Port capability after sender navigation/closure is
not attested. Redirecting victim routes are intentionally blocked until a
transport can enforce policy on every actual hop.
