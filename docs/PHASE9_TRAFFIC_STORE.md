# Phase 9: Vendor-Neutral Traffic Store

Phase 9 records logical HTTP observations in BugHunter-owned SQLite. It sends
no requests and does not import recon traffic automatically. The operator's
Phase 9 numbering overrides the original roadmap, which labels this work as
Phase 8. Burp integration is deferred to Phase 10.

## Contract

`hackbot.traffic.TrafficStore` accepts a registered `TargetPackage`, a typed
`CapturedRequest`, optional `CapturedResponse`, `TrafficSource`, and a validated
capture-provider label. `store_request` creates a `REQUEST_ONLY` exchange;
`store_response` completes it. `store_exchange` is a convenience for a packet
with an optional response. A request can instead become `FAILED`, `ABORTED`,
or `TIMEOUT` without losing its observation. Request and response base rows
are immutable; only exchange completion state changes.

The store reuses Phase 4 `RequestRecord` and `ResponseRecord`, linked by a
stable `EXCHANGE-...` ID. `TrafficRequest` and `TrafficResponse` add compact
HTTP metadata and Phase 3 Evidence references. Provider capture is generic:
`TrafficCaptureProvider.read_batch(limit=...)` returns bounded `CapturePacket`
objects. `BURP`, `BROWSER`, `HACKBOT`, `HAR_IMPORT`, `MANUAL_IMPORT`, `FIXTURE`,
and the earlier `IMPORT` source are recognized without a vendor-specific
request model. Neither TLS interception nor a live provider is implemented.

## Attribution And Scope

Each exchange stores target/package, source/provider, timestamps, optional
endpoint/operation IDs, scope result, and authentication state. A
`BrowserSessionManager` supplies current `SessionContext` when a browser
session ID is provided. Only a running `VALID` session with a `MATCH` identity
verification and linked valid AuthContext becomes `VERIFIED`. A declared
account in an unverified or wrong-identity session remains
`UNVERIFIED_IDENTITY`; it has no verified identity or principal. An anonymous
session is `ANONYMOUS` with no fake Identity when no authentication material is
observed. Non-browser records are unverified by default; a provider must set
`anonymous=True` explicitly to label one anonymous, and observed auth-like
headers/query fields downgrade that label to unverified. A non-browser record
with a declared Identity also remains unverified in this phase.

An observed, evidence-backed principal relationship may be recorded for a
verified Identity. Configured-only principal links are not promoted. Tenant
and role IDs copied from Phase 8 SessionContext are explicitly **declared
metadata**, not proof of the effective live role or tenant. If the bounded
membership page is incomplete, these hints are omitted. Stored attribution
is a capture-time snapshot; later session expiry does not rewrite history.

`ProgramScope.evaluate_url` supplies `IN_SCOPE`, `OUT_OF_SCOPE`, or `UNKNOWN`
plus a reason. Even out-of-scope observations may be stored for provenance.
This result never authorizes a future request; a later ScopeGuard must make
the execution decision. Traffic rows do not create recon endpoints or change
production PostgreSQL.

## Evidence And Secrets

Every request has protected `HTTP_REQUEST` Evidence; every response has
protected `HTTP_RESPONSE` Evidence. Bodies, when present, are separate
content-addressed `HTTP_REQUEST_BODY`/`HTTP_RESPONSE_BODY` artifacts. All
traffic Evidence defaults to `SECRET`, including anonymous responses, so
`read_content` requires explicit `allow_sensitive=True` and a byte limit.
Identical bytes share one SHA-256 artifact file even if multiple Evidence
records refer to them. The request/response rows hold hashes and Evidence
IDs, never body bytes.

The protected request observation preserves method, original URL spelling,
header order, HTTP version, and body reference, subject to deliberate removal
of authentication material. Authorization, Cookie, Set-Cookie,
Proxy-Authorization, API-key, CSRF, signature, and similar header values are
replaced by `[AUTH_CONTEXT]`. Query values with credential-like names are
replaced likewise. These captured values are **not** stored for replay;
future execution must resolve current authentication and CSRF material through
AuthContext. Other query values and body bytes can contain sensitive data and
are accessible only through explicit protected Evidence reads. A body with
credential-like patterns is withheld entirely; its original size/SHA-256 and
an artifact containing only a withholding marker remain. Thus captured
passwords and tokens are not put into Evidence, while non-credential bodies
remain available for later controlled comparison. This is a conservative
pattern guard, not proof that arbitrary unlabelled bytes are credential-free;
future providers must classify unusual credential formats before ingestion.
A generic header may itself contain a secret, so all observations remain protected.
Response Set-Cookie values are also removed. This is logical HTTP evidence,
not a raw wire/TLS dump.

Searchable rows contain only normalized origin, a safe path display shape,
query and non-secret header **names**, MIME type, status, timing, body size,
hashes, and relationship IDs. Path segments outside a small static route
vocabulary are replaced by short SHA-256 labels; encoded and case-sensitive
segments remain distinct by hash. No query/body value is indexed. The Phase 4
`RequestRecord.url` is `None` when reloaded; the protected observation holds
the retained original spelling. CLI and default `to_dict()` output never
include raw request/response content, credential headers, or full query
values. A future replay component must reconstruct a sanitized template from
Evidence under explicit policy and apply fresh AuthContext credentials; this
phase exposes no replay API.

## Fingerprints And Queries

The structural request fingerprint is SHA-256 of a deterministic JSON tuple:
uppercase method, normalized scheme/host/port, safe path shape, sorted unique
query parameter names, MIME type, and optional operation ID. Authentication
and parameter values do not enter it. The response body hash is SHA-256 of the
captured body; its artifact hash is the hash of retained bytes and may differ
when withheld. Later validators can compare status, MIME type, body hashes,
and, with explicit Evidence access, JSON structure and selected semantic
fields. No authorization validator exists in this phase.

Target, verified/declared Identity, session, anonymous, endpoint, operation,
correlation, browser action, and recent queries require a target ID and use
bounded keyset pagination. Matching indexes cover target/time, identity/time,
session/time, endpoint/time, operation/time, method/path/time, and request
fingerprint. `find_by_fingerprint` retrieves structurally similar exchanges.
Correlation and browser-action inputs are stored as hashes; the
raw labels do not enter ordinary metadata. `stats` samples at most 1,000
newest rows and reports whether truncated; it is not an all-history count.

`hackbot traffic list <target>`, `traffic show <exchange>`, and
`traffic stats <target>` read only local metadata. `list` shows a verified
identity alias only after verified attribution, otherwise an explicit state.
No command requires PostgreSQL or sends traffic.

## Retention And Limits

An exchange snapshots `retain`, `expires_at`, `pinned`, and
`finding_related`; its Evidence receives the same initial Phase 3 policy.
There is no expiration worker or automatic cleanup. A later retention service
must reconcile policy updates; Phase 9 does not choose a final block-volume
layout, encryption scheme, or backup policy.

The store creates protected Evidence before inserting relational traffic
metadata. If a later SQLite insert fails, an immutable orphan Evidence record
may remain for manual audit; it never becomes a fabricated traffic exchange.
Providers should bound body bytes before passing them to the in-memory capture
models. Source-to-endpoint association is caller supplied and optional; this
phase does not mine GraphQL operations, infer browser actions, or validate
vulnerabilities. The optional real Chromium smoke test needs a local binary;
deterministic Phase 8 fake-browser fixtures exercise attribution without
network target requests.

## Phase 10 Handoff

Implement a `BurpTrafficCaptureProvider` that converts bounded Montoya/Burp
observations to the existing `CapturePacket` and `TrafficSource.BURP`, supplies
source and session provenance, applies the same protected-evidence policy,
and tests imports/capture against local fixtures. It must not replace this
generic data model or grant active-test authorization. Burp proxy setup,
traffic execution, and replay remain separate responsibilities.
