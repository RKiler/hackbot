# Phase 26 - GraphQL and API Specialist Expansion

Status: complete for the bounded Phase 26 contract. The limits below remain
explicit; completion does not imply exhaustive GraphQL or API coverage.

## Authority and data flow

`APISpecialist` reads bounded current `TrafficStore` exchanges, saved first-party
JavaScript artifacts, recon API-surface hints, and Phase 25 behavior observations.
The Target Package, not recon membership or a JS reference, controls scope.
An imported JS artifact needs a matching scoped capture or current scoped recon
record before its operations enter the registry. A recon API surface without an
observed document is only an `UNKNOWN` inventory hint.
Researcher-supplied endpoint context enters only through a target-bound Evidence
record and remains an `UNKNOWN`, non-executable hint. A JS-only operation never
borrows an endpoint from runtime traffic merely because the operation names
match; exact runtime capture is required to bind a request shape for execution.

`APIOperationRegistry` persists target-scoped operation and candidate metadata
in BugHunter SQLite. It links to `TrafficExchange` and Evidence IDs rather than
copying raw request or response bodies. An operation key separates endpoint,
method, name, and type; a document/version hash separates exact templates.
Distinct traffic-observed documents may coexist under one operation name,
because role-specific selection sets are not deployment supersessions.
Persisted-query hashes
are accepted only from observed request metadata; they are never guessed.
Profiling and plan preparation also retire JS-only operations when their exact
saved asset hash has no current JS artifact, including when a replacement bundle
removes the operation entirely. Unresolved candidates become stale. A runtime-
observed operation retains its separate traffic provenance and is not retired
merely because a JS asset changed.
The registry retains the 16 most recent observed exchange references per
operation. A retired traffic template can become current again only after a
newer capture of that exact template; replaying older capture metadata,
including an exchange whose reference aged out of the bounded list, does not
reopen it.
If the exact operation later reappears in a current bundle, only an unplanned,
unexecuted candidate may be regenerated; prior plan/run/validation history is
never revived automatically.

The bounded GraphQL parser uses `graphql-core` on observed documents. The
existing Babel static-analysis dependency extracts literal GraphQL documents
from saved JS; there is no second JS parser or default introspection pass.
The same bounded Babel pass extracts literal same-origin `/api/` paths from
`fetch` and `axios` calls. They remain relative, `PLAN_ONLY` REST hints without
a host or request template until exact scoped traffic is observed; dynamic
URLs and query-bearing literals are ignored.
Variables, input type names, aliases, fragments, selected fields, and root
fields are recorded. `__typename` in a saved response can enrich parent and
nested field types. Per-field identity and role observations require an actual
non-null response field; selecting a field is not proof of access. Missing
schema context is recorded as a gap, not inferred.

## Candidates and execution

Candidates are bounded by `APIAnalysisLimits` and ranked using current
operation evidence, verified owned objects, a second tenant, and Phase 25
role/operation gaps. `NOT_OBSERVED` is only a prioritization clue. Field names
such as `secret` or `billingInfo` are also only clues: executable field tests
require trusted, evidence-backed privacy and field-visibility Facts. Where a
Phase 25 profile informed ranking, its run ID is retained on the candidate;
observed denials and configured expectations affect priority only.

The base executable API-specific read path is an exact observed REST GET/HEAD
or single-root GraphQL query on one verified disposable object. It freezes five
controls: owner read, boundary actor's own-object read, invalid-object read,
and two foreign reads. Dispatch rechecks the current operation/version, observed
request body, source exchange, identity, object reservation, ownership Facts,
and target scope. Only the declared ID variable changes; Phase 14 supplies
authentication. Phase 13/14 gate every request, Phase 16 owns the run, and
Phase 17 alone classifies and creates a Finding.

For exact matching observed boundaries, the API candidate delegates REST
parent-child reads, small REST batches, lower-role BFLA, and typed REST/GraphQL
mutations to Phase 19/20. The API candidate records the delegated candidate,
plan, run, and validation IDs. It does not dispatch a second request path or
create a second mutation validator. Known disposable object IDs may normalize
their TrafficStore path placeholders into one route shape; unknown path
segments stay distinct. Autonomous mode considers one ready read candidate
per call, caps the plan at five requests, requires explicit package automation
permission, and stops at an existing approval or other non-ready run state.

For an object read already confirmed by Phase 19, preparation can link its
existing validation instead of dispatching another plan. Reuse requires the
same current API version, exact owner capture, owned object, foreign identity,
current verified sessions and private-boundary Facts, an unreserved disposable
object that is ready or awaiting cleanup, and a Phase 17 confirmation newer
than the last operation observation. An exact owner capture is resolved
directly when it has aged out of Phase 19's bounded recent profile. A denial,
cleaned object, newer capture, or mismatched binding is not reusable. This is
reuse of an already validated finding, not offline confirmation from raw
TrafficStore observations.

An observed single-root GraphQL parent query can form a nested child candidate
only when a verified disposable child has a trusted `belongs_to` Fact, private
child policy Facts, and actual scalar data under that parent and selected field
in the saved owner response. Its plan reuses the five fixed API read controls,
reserves both parent and child, and changes only the observed parent ID. The
Phase 17 nested validator accepts a disclosure only when the foreign response
returns the same protected child ID and scalar value under the exact parent
and field path, twice. A public parent, unrelated response branch, ignored
parent parameter, null/filtered child, or field-name match alone does not
confirm a finding. The local fixture covers both child disclosure and filtering.

GraphQL HTTP 200 with only permission errors or null protected fields does not
confirm access. The API read validator requires trusted privacy and tenant
Facts, verified identity memberships, semantic owner and actor-owned controls,
an invalid-object negative control, and two foreign reproductions. Field proof
must be attached to the same owned object branch, with an owner-visible actual
value. Partial data plus errors can still confirm a disclosure when the
protected field is returned. Candidate, operation, plan, run, validation, and
finding links remain separately auditable.

For one bounded field-selection differential, the owner and lower-role actor
may have separate current, traffic-observed documents with the same endpoint,
operation name, single ID variable, and single-root shape. The actor's
selection must differ by exactly one protected scalar, either directly under
the root or one level inside an embedded object. Both documents must retain
the root ID, use the same field structure otherwise, and contain no field
arguments below the root, aliases below the root, directives, or fragments.
The five-request plan uses the actor document only for its own-object control;
owner, invalid, and both foreign requests use the owner's exact observed
selection. Phase 16 freezes this slot distinction and
Phase 17 re-parses both executed documents before deciding. For an embedded
field, the response must bind the root ID to the verified object and any
nested ID must be that same object; an independently identified child belongs
to the nested-object authorization path instead. Deeper selections, extra
variables, and invented fields are not eligible for this variant.

Observed `node(id:)` queries may use a canonical base64 `Type:ID` global ID.
The specialist recognizes that shape only when the decoded ID exactly matches
an already verified disposable object and the document binds one declared
variable to `node(id:)`. The registry stores only the type label. Dispatch
rechecks the observed request and generates an invalid control using the same
type prefix. The encoding is not authorization evidence; owner/boundary object
proof and GraphQL response semantics remain mandatory. Conflicting observed
type prefixes fail closed.

An observed single-root `nodes(ids:)` query, including a saved root alias, or
an observed two-operation HTTP JSON array of the same single-root `node(id:)`
query may form a two-ID batch plan only when captured owner and actor controls
each return scalar data for two distinct verified disposable objects in their
own tenant. The exact document, envelope, variable, ID representation,
endpoint, and two captured responses are rechecked at dispatch. The five
requests are owner pair, actor pair, invalid pair, and two identical mixed
owner/actor pairs. Exactly four objects are reserved for this batch plan; the
ordinary three-object plan cap is unchanged. Phase 17 requires both known
objects and matching protected scalar data in each mixed result. Filtered/null
foreign items and HTTP 200 permission errors are not findings. Unobserved
arrays, extra root fields, unknown IDs, and larger batches remain leads only.

Nested GraphQL rename mutations use only a reviewed recipe with exact
`parentId`, `id`, and `name` variables and a single parent/child operation.
The child, its verified owner parent, and a disposable foreign parent are all
reserved. The seven-stage Phase 20 plan sends owner-parent controls, one
foreign-parent/owner-child boundary write, independent child read-back, and
restore. The binder rechecks ownership Facts and the relationship before every
stage; Phase 17 independently checks the three objects and the parent IDs in
the executed writes. HTTP 200 or a mutation response alone never confirms a
state change. This is still a typed rename, not a general GraphQL mutation
editor or permission-field update.

An observed REST `POST` to the verified disposable object's exact
`/{object_id}/rename` action is eligible when a reviewed recipe binds only
`{"name":"$test_name"}`. Its GET read-back is the object's verified route;
the same action restores the original name. The API candidate delegates to
the same seven-stage Phase 20 plan, and Phase 17 confirms only the durable
foreign rename after owner control, independent read-back, and restoration.
Other POST actions, unsupported fields, and non-disposable objects remain
leads. This POST contract does not authorize arbitrary action bodies.

The reviewed `DELETE_DISPOSABLE` recipe binds exactly the REST DELETE already
used by Phase 18 ObjectFactory cleanup and its verified owner GET route. A
separate eight-stage Phase 20 plan reserves two distinct verified disposable
objects: owner GET/DELETE/absence control; owner GET confirming the target is
still present; foreign DELETE; owner read-back; conditional owner cleanup;
final owner absence read-back. A confirmed foreign deletion skips the redundant
cleanup DELETE (seven requests); a denied attempt uses owner cleanup (eight
requests). Each dispatch uses Phase 13/14. A missing target preflight
blocks before the foreign request, and invalid sessions block before dispatch.
Phase 17 independently checks the two objects, policy/permit audit, exact
request paths, mutation ledger, authorization Facts, and durable absence before
it can create a finding. The orchestrator reconciles each already-deleted
object to `CLEANED` only after its own absence proof, including partial runs.
The API specialist selects this contract only when a completed, owner-authenticated
DELETE exchange exactly matches the reviewed cleanup URL of a verified CLEANED
fixture and two distinct current READY fixtures share its owner, tenant,
parent, object type, pinned recipe, and trusted private-access expectation.
It first resolves exact ObjectFactory cleanup or verified typed-mutation
exchange links through target-scoped local indexes, including older fixtures
outside the newest 50. An unlinked observation may still match the bounded
recent-fixture fallback, but older unlinked observations remain leads. The
specialist independently rechecks the URL, recipe, actor, and object binding
at preparation and creates the existing typed plan; a past deleted object is
never reused as the live owner control. Without that evidence DELETE remains a
lead. The local positive and denied end-to-end API fixtures pass. Autonomous
analysis never starts the mutation plan.

Mass-assignment detection recognizes observed privilege-like input names, but
always leaves the candidate in `REVIEW`. A loopback fixture demonstrates that
a synthetic disposable object's `can_share_test` property can change and be
read back; specialist preparation still sends zero writes and produces no
finding. A real target would need a separately reviewed typed, disposable
proof contract before this category could be executed or confirmed.

## Dashboard and API

The `API / GraphQL` dashboard section shows exact current/stale operation
counts, current query/mutation totals, bounded operation and candidate lists,
observed roles and tenants, field context, and links to existing Plans/Runs.
The authenticated gateway allowlists target-scoped inventory, detail, analysis,
prepare, start, and advance routes. POSTs require its existing CSRF control;
dashboard credentials are not forwarded to the private service. There is no
arbitrary GraphQL editor or arbitrary REST request endpoint. `PLAN_ONLY`
analysis reads existing data; explicitly requested `BOUNDED_AUTONOMOUS`
analysis may run one eligible read plan through the existing policy path.
Coverage includes deduplicated plan/run/request counts and per-category
confirmed, rejected, and manual-review outcomes, plus exact discovered,
traffic-observed, tested, blocked, validated, current, and stale operation
counts. Operations and candidates have target-bound keyset cursors. Candidate
pages can be bound to one operation, so detail views do not omit hypotheses
behind unrelated target-wide rows. List responses do not imply complete schema
coverage. A researcher can analyze one exact current operation ID outside the
default newest-100 pass; the focused pass keeps the same candidate and request
caps and rejects stale or foreign operation IDs. The coverage API also reports
whether traffic, current-JS, or candidate-generation backlog cursors remain.

## Bounded limits and deferred expansion

- Extend selection-set variation beyond the implemented single-root,
  one-scalar differential (direct or one embedded level) only when a current
  observed document, exact AST binder, and independent field policy support it.
  No free-form field addition or schema guessing is available.
- Extend pre-test reuse beyond an exact previously confirmed Phase 19 object
  boundary. Previously captured owner/boundary traffic alone is still not an
  independent Phase 17 validation and may need a fresh bounded plan.
- Keep real-target mass-assignment observations as review leads. The synthetic
  fixture demonstrates a local property change and read-back, not a Phase 17
  mass-assignment confirmation path or a production write contract.
- Untargeted generation advances a target-bound operation cursor across calls,
  while reserving a bounded hot slot for a newly observed operation. Traffic
  and current-JS inventory also resume across calls. Dense JS assets now keep
  an asset-local extraction offset and can yield operations after the old
  first-24 limit without skipping the rest of the asset. Extraction is capped
  at 1 MiB per saved JS body and 1,024 literal hints per asset; oversized or
  unavailable bodies remain explicit gaps, and hint overflow is reported as
  `JS_EXTRACTION_TRUNCATED`, not silently counted as coverage. Broader
  nested/batch shapes require observed client evidence and safe binders.
- Recon API surfaces are metadata hints only. Each analysis pass reads a
  bounded first page by surface type; it does not claim to have inventoried
  every historical recon surface or an entire GraphQL schema.
- Native binary/gRPC protocols, unrestricted introspection, arbitrary query
  editors, and schema-wide field or ID fuzzing are outside Phase 26.

Unknown protocol or GraphQL semantics may be emitted as `NEEDS_RESEARCH` for
Phase 27, but Phase 26 does not implement research retrieval or allow outside
material to become execution authority.

## Verification and handoff

- Full BugHunter suite: 650 passed, one `TestObject` collection warning, in
  1:18:25. Acceptance fixtures cover GraphQL object, field, nested, global-ID,
  batch, partial-data, and mutation authorization; REST object/BFLA/bulk and
  disposable DELETE; mass-assignment review-only behavior; stale operations,
  existing-evidence reuse, request caps, wrong identities, and the audit chain.
- Dashboard gateway suite: 10 passed. The API panel shares authentication and
  CSRF gates, forwards no dashboard credentials, and rejects arbitrary API
  execution routes. Its operation and candidate lists use bounded cursors.
- The panel JavaScript passed `node --check`; the install wheel includes the
  API modules, Babel helper, API skill, and migrations 025-033.
- Acceptance traffic used local fixtures only. No live bounty target requests
  or production recon database writes were part of Phase 26 verification.

Phase 27 should implement `ResearchCoordinator` as bounded, source-backed
research over structured `NEEDS_RESEARCH` gaps. Persist concise, attributed
ResearchBriefs, cache repeat questions, and keep research advisory: it must
not grant scope, create an executable request, or bypass the Phase 13-17 gates.
