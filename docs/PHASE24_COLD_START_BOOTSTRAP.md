# Phase 24: Cold-Start Target Bootstrapper

## Boundary

A tracked Target Package is the sole scope authority. ReconRepository is an optional, read-only accelerator: a missing recon row selects `COLD_START`, while a matching row selects `RECON_BACKED`. Neither result changes the target identity or authorizes a host. Bootstrap never writes to production recon and never sends vulnerability payloads, submits forms, clicks controls, enumerates subdomains, guesses paths, or invokes a specialist experiment. Phase 25 owns normal-behaviour learning.

## State and ownership

BugHunter stores bootstrap runs, compact observations, and the target discovery state in its own SQLite schema 23. States are `COLD_START`, `PARTIAL`, `BROWSER_PROFILED`, `TRAFFIC_PROFILED`, `RECON_BACKED`, and reserved `MATURE`; `MATURE` is not a security judgment and Phase 24 does not assert it. Runs use `CREATED`, `READY`, `RUNNING`, `WAITING_LOGIN`, `PARTIAL`, `COMPLETED`, `BLOCKED`, `FAILED`, `BUDGET_EXHAUSTED`, or `CANCELLED`. The normal no-account default may finish `PARTIAL` with `AUTHENTICATED_COVERAGE_UNAVAILABLE` while still recording public coverage. An interrupted active run becomes partial on service restart and is not replayed automatically. One active run per target is enforced by SQLite.

`BootstrapResult` includes mode, status, UTC timestamps, request/page/JS/API/technology/feature/traffic/fact counts, source-map and JS-change counts, budgets, redacted Evidence IDs, limitations, cancellation state, and stop reason. Run history and observations are bounded. Raw HTML, JavaScript, secrets, cookies, and query values are never returned in bootstrap API summaries.

## Providers and knowledge

`TargetBootstrapper` uses `DiscoveryProvider`-style boundaries for manual Target Package features, bounded recon observations, existing TrafficStore exchanges, verified browser-page metadata, and acquired JS. Observations retain source, safe surface digest, Evidence ID, and local source reference. Recon and cold-start observations coexist; a later recon match updates discovery state to `RECON_BACKED` on the same Target ID without deleting prior Evidence, Facts, Traffic, JS artifacts, or hypotheses. Recon disagreement is preserved as separate source observations.

The bootstrap begins with exact hosts listed in scope. A wildcard alone is not a seed and never triggers subdomain enumeration. Each anonymous GET uses Phase 13 policy and Phase 14 TrafficExecutor, including per-hop redirect and rate checks. The bootstrap-only redirect guard also rejects unsafe in-scope destinations such as logout routes before a second request. Out-of-scope redirects stop before the next request. The frontier follows only bounded, in-scope, safe HTML links, prioritizing application routes. Tracking parameters and fragments are removed; credential-like queries, ambiguous encodings, dangerous action routes (including logout), and unsupported methods are rejected. Form metadata may be observed but forms are never submitted. Third-party scripts are references only.

Query-bearing links that are unsafe to follow may still contribute in-scope API/OAuth path and parameter-name observations after their query values are removed. Bootstrap never requests those URLs, stores their values, or treats the metadata as proof that an API operation is callable.

Observed version query parameters on script URLs may be retained; unknown or credential-like query names are not followed. If TrafficStore withholds a credential-like HTML response, bootstrap does not parse its placeholder or claim page coverage: the run records `HTML_BODY_UNAVAILABLE` and remains partial.

An already-open, currently verified primary browser session can contribute its page URL, script, link, and form metadata; this does not navigate or evaluate arbitrary JavaScript. Existing browser/proxy captures are consumed from the ordinary TrafficStore. Phase 24 does not synthesize a TrafficExchange for a page it did not actually capture. Anonymous and verified-session coverage are counted separately. A selected identity must have an active verified session. Manual-login sessions without an exportable HTTP credential are not converted into authenticated executor requests.

Current first-party JS is fetched only through the executor and saved in the Phase 21 content-addressed artifact store. A normal repeat reuses cached current JS; an explicit `refresh` re-fetches and detects a changed hash, leaving old artifacts and evidence auditable. Referenced in-scope source maps are bounded optional reads. Deterministic JS/HTML analysis records preliminary API, route, framework, WebSocket, messaging, DOM, and exposure signals. Existing Phase 21/22/23 static analyzers may create candidate records for acquired assets, but no active specialist run, report, or finding is started. Directly linked in-scope OpenAPI JSON may be read and recognized; filenames are not guessed. API and role/feature hints are not permission facts.

An HTML fallback returned from a script URL is recorded as `JS_NON_SCRIPT_RESPONSE`, not cached or counted as analyzed JavaScript.

Phase 12 TargetProfile is regenerated from normalized local observations, traffic, facts, and any available recon data. The passive hypothesis generator may add hypotheses; it does not execute them. Each bootstrap observation has an Evidence link, and only conservative signals are converted to Facts. Phase 25 should use these sources to identify workflows, owned objects, tenant/role relationships, and legitimate request baselines rather than infer them from route names.

## Budgets and stop rules

Defaults: 16 HTTP dispatches (redirect hops count), 5 parsed pages, navigation depth 1, 6 JS bodies, 1 MiB per asset, 2 redirects, and 120 seconds. Hard caps: 60 dispatches, 12 pages, depth 2, 20 JS bodies, 1 MiB per asset, 3 redirects, and 600 seconds. The Target Package's rate policy may be stricter. A dispatch is reserved immediately before the wire send. Bootstrap stops on cancellation, time/request budget, policy denial, authentication gate, or an exhausted frontier; it does not keep requesting to fill a quota. An unavailable parser, source map, browser, proxy, or account is a recorded limitation rather than an invented coverage claim.

Phase 14's transport gate remains authoritative. With direct HTTP disabled and no available capture proxy, the run is `BLOCKED` with zero requests; deployment does not enable direct traffic implicitly. The service also rejects a new run with HTTP 409 before creating it when its local transport preflight is blocked. The executor rechecks the route before every dispatch, so a listener or bridge failure after preflight still fails closed.

For a capture-required pilot, configure `[executor]` with `allow_direct = false` and `capture_required = true`. Create a dedicated anonymous Burp browser session for the tracked target and start it before bootstrap. Its binding must have a reachable loopback listener and a current target bridge heartbeat. Only anonymous `GET` actions from `cold_start_bootstrap` may use that target-scoped listener; authenticated actions continue to require their own verified session binding. Each request still passes Target Package scope, policy, one-use permit, rate/budget checks, and TrafficStore/Evidence recording. A Burp capture is attributed to `ANONYMOUS`, not to a synthetic identity. This does not require a system-wide proxy or CA change.

## API and dashboard

The private service exposes target-scoped `GET`/`POST /v1/targets/{package_id}/bootstrap`, `GET /v1/targets/{package_id}/bootstrap/{run_id}`, and `POST /v1/targets/{package_id}/bootstrap/{run_id}/cancel`. There is no arbitrary-URL bootstrap endpoint. The existing authenticated dashboard gateway proxies these routes under `/api/hackbot/` and requires CSRF on POST. The target detail `Bootstrap` tab shows discovery/recon state, executor/transport/Burp readiness, the blocking reason, coverage, verified identity selection, bounded start/refresh/cancel controls, history, and redacted run detail. It offers anonymous Burp-session provisioning when needed and disables Start until preflight passes. The private BugHunter service must remain behind the gateway; the dashboard must not expose raw Evidence bodies or credentials.

## Verification and limitations

Local loopback fixtures cover no-recon and recon-backed targets, verified and absent accounts, a login gate, exact-host scope, out-of-scope redirects, third-party references, logout/form avoidance, source maps, JS cache/refresh, GraphQL/REST/WebSocket signals, budgets, and stop-on-frontier exhaustion. Gateway tests cover authentication, CSRF, and credential stripping. No live bounty target or production recon database is used in Phase 24 tests.

The browser provider only snapshots an already-open page; it does not launch a general browsing tour. Browser traffic must be captured by the existing traffic infrastructure to be available as a full exchange. Normal-behaviour models, role comparisons, deep GraphQL/API work, campaigns, and continuous delta scheduling remain deferred to their reconciled roadmap phases.
