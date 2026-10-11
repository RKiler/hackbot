# Phase 14: Controlled Traffic Executor

## Boundary

`TrafficExecutor` is the single BugHunter HTTP execution boundary. It is owned by the Phase 11 single-process runtime alongside the shared `RateLimiter`; no arbitrary-request CLI, API, dashboard action, crawler, agent, skill, or replay feature was added. A future experiment supplies a `ProposedAction` and immutable, non-secret `RequestTemplate`. The trusted caller obtains a persisted `PolicyPermit` with `authorize()`, then calls `execute()` with that exact action/template/permit. This local Python interface is not a remotely exposed authorization endpoint.

The target package is loaded from its authoritative local repository both during authorization and immediately before each send. Recon inventory is never scope authority. `execute()` re-evaluates Phase 13 policy, including current scope, identity, rules, and rate state. A permit binds the persisted ALLOW decision, action ID/fingerprint, target/package, category, identity, policy version, request fingerprint, scope rule, and any exact approval. It expires after 30 seconds and is atomically consumed before secret resolution or HTTP dispatch. An approval-backed permit atomically consumes its `APPROVED_ONCE` approval in the same transaction. Failed execution does not restore a permit; a retry requires a fresh action and authorization.

## Request and identity

`RequestTemplate` accepts GET, HEAD, OPTIONS, POST, PUT, PATCH, and DELETE, exact URL, non-secret headers, and bounded bytes. It rejects caller-supplied Cookie, Authorization, Host, proxy/routing, framing, and internal correlation headers. The executor adds only a fixed `Accept-Encoding` baseline and current auth resolved through Phase 7 `SecretProvider`. The raw secret is neither embedded in a template nor returned in `ExecutionResult`. Cookie, bearer, and API-token-header modes require a `VALID` AuthContext tied to the same currently verified Phase 8 browser session and the registered identity's secret reference. Anonymous requests use a fresh client session with no inherited cookies or environment proxy/netrc. Manual-login and imported-browser-only contexts have no HTTP credential export and return `AUTH_UNAVAILABLE`.

Prepared cookie/bearer/header contexts may now enter the existing human-operated BrowserSession verification flow. Browser login is still manual; no secret is copied from the browser. A verified browser identity does not independently prove that an operator-configured HTTP secret names the same account. Target-specific identity verification of direct HTTP credentials is a later validation prerequisite before relying on cross-account conclusions.
CSRF-bearing or other per-request signed authentication is not synthesized in this phase; such requests remain unsupported until a trusted token resolver can supply current values without putting them in templates.

## Send path and redirects

The executor uses `requests` as its only production HTTP client, with `trust_env=False`, certificate verification enabled, fresh session per hop, finite connect/read timeouts, and a monotonic overall deadline. The HTTP library never auto-follows redirects. For each GET/HEAD redirect, the executor constructs a new action and template, applies current scope/policy, issues a new short-lived permit, reserves rate capacity, and sends only if allowed. Out-of-scope, malformed, cross-origin authenticated, state-changing, and over-limit redirects stop before the next request. The prior in-scope response is still recorded. DNS rebinding/internal-address safeguards are an explicit future extension point; this phase does not probe internal networks. Python's synchronous resolver can outlive the monotonic deadline, so a hard wall-clock kill requires a future isolated transport process.

Phase 13 `RateLimiter.reserve()` is invoked for each hop with the target's policy and optional per-experiment budget; the shared reservation is released in `finally`. Denied capacity returns a classified result without busy waiting. The executor does not retry automatically, particularly for state-changing methods. The caller must establish a new policy action and permit for any retry. No wordlists or autonomous mutations are present.

## Capture, proxy, and results

The request is written to Phase 9 `TrafficStore` as `HACKBOT` before dispatch; the response or an incomplete state is attached to the same exchange. Attribution is anonymous or comes from the current verified BrowserSession. The internal execution correlation ID is hashed by TrafficStore and is never sent as a target header. Request/response bodies remain protected Evidence; `ExecutionResult` exposes only safe IDs, status/content-type, captured size, truncation, redirect destination hashes, error class, timestamps, and evidence references. A successful HTTP response is an observation, never a vulnerability conclusion.

Direct mode requires explicit `[executor] allow_direct = true`; the default is off. `capture_required = true` requires a ready proxy route. `BurpExecutionProxyAdapter` can use an existing Phase 10 session listener and isolated CA; it neither requires Burp in local fixtures nor installs global trust. A missing capture route fails closed. The generic `ExecutionProxyProvider` and `ProxyRoute` keep the core traffic model vendor-neutral.

Response bodies are streamed in bounded chunks. Gzip and zlib-deflate are decoded incrementally with a decompressed output cap and a compressed-input cap. A truncated observation retains at most `max_response_bytes` and adds an internal capture marker; downloads are never unpacked or executed. Unsupported encodings fail closed and leave an incomplete exchange. Header parsing and TLS handshakes remain bounded by the HTTP stack's own limits, not a separate sandbox.

`ExecutionError` classifies policy/scope/permit/rate/auth/proxy/redirect, timeout, DNS/TLS/connection, body, and generic failures without echoing request material. `executor_events` stores safe lifecycle codes, not bodies or secrets. The existing TrafficStore remains the canonical execution-history store.

## Configuration and handoff

Optional `[executor]` keys: `allow_direct`, `capture_required`, `connect_timeout_seconds`, `read_timeout_seconds`, `overall_timeout_seconds`, `max_redirects`, `max_request_bytes`, `max_response_bytes`. Defaults are fail-closed direct mode, 3/10/30 second timeouts, 3 redirects, and 256 KiB request/response limits. Target `RatePolicy` can be stricter. This phase intentionally has no public arbitrary-request route, browser-mediated HTTP execution, replay API, DNS pinning, dynamic VHOST/Host override, skill engine, agent, or bug validator.

The recommended Phase 15 task is a policy-gated Skill Engine that takes bounded, evidence-linked hypotheses and produces explicit proposed actions and request templates, without bypassing this executor or promoting HTTP observations to confirmed findings.
