# Phase 21: DOM XSS Specialist

## Boundary

The specialist uses production recon only as a bounded, read-only source of JS metadata, analysis signals, and recent delta events. The authoritative Target Package, not recon membership, controls scope and active testing. BugHunter owns the artifact, candidate, plan, run, validation, and finding records in its local SQLite store. It does not copy the recon corpus or create production recon tables.

`DOMXSSSpecialist.inventory()` ranks at most 16 JS assets. It considers up to eight assets on each of the first eight scoped hosts, plus up to 24 JS asset IDs from the latest two completed delta snapshots. Delta IDs use an exact, root-scoped, read-only lookup, so a changed asset is not excluded merely because its host is outside the initial host page. Current recon hashes raise priority. A changed or unknown body hash does not inherit previous analysis. Acquisition uses a Phase 13-approved, Phase 14-executed GET with redirect checks, a one-MiB JS limit, no implicit credentials, and protected content-addressed Evidence. Referenced first-party source maps use the same boundary with a separate size limit. External assets are not fetched on the authority of an in-scope page.

## Static Analysis

The bounded Babel AST child process parses current JavaScript without executing it. It identifies connected source, validation, transformation, and sink steps in a function-local flow. It records source/sink locations, post-transform checks, sanitizers, unresolved helpers, score, status, asset SHA-256, analyzer version, Evidence references, and mapped source where a current source map exists. A source and sink in the same bundle without a reachable path remain a lead. Parser failures and oversized bodies are recorded as analysis limits, not cleared coverage. Reanalysis is keyed by asset hash and analyzer version.

The optional static-analysis runtime needs `node` plus locally resolvable `@babel/parser`, `@babel/traverse`, and `@jridgewell/trace-mapping`. The current VPS provides these as system Node packages. Missing dependencies fail closed as parser/source-map unavailable; they do not become a negative security result. Installing the Python package alone does not install these Node modules.

The Phase 21 proof path is intentionally narrow: supported `location.search` or `location.hash` source, security check before one or two observed decode operations, and an executable HTML or URL sink. Other client-side flows remain manual/static candidates. There is no arbitrary payload generator, broad crawler, model call, postMessage specialist, or server-reflected/stored-XSS campaign.

## Plan And Runtime

A current candidate can create a Phase 12 DOM XSS hypothesis and a Phase 15 `check-before-transform-dom-xss` plan. A browser entry route must come from a successful, in-scope observed HTML GET; a browser plan then freezes the candidate, route, exact JS URL, input kind/name, and browser session. URLs with credential-bearing query strings are excluded from the active plan. Phase 16 owns the `VERIFY_BROWSER` step and reserves at most six navigations for the plan. A restart does not replay an in-flight browser step.

`DOMBrowserExperimentExecutor` generates only fixed harmless probes: inert marker, benign same-origin URL, direct dangerous negative control, single-encoded candidate, optional double-encoded candidate when two decode operations were observed, and one fresh-context reproduction. It stops after proof plus reproduction. Each navigation and browser subrequest passes Phase 13 policy and target scope; non-GET methods, out-of-scope redirects, and excess requests are aborted. Playwright uses a fresh isolated context for each variant, blocks service workers, captures the exact loaded JS body hash, and reads only a nonce-bound DOM attribute. It does not read cookies, storage, account data, or response bodies as proof, and it has no arbitrary page-evaluation API.

The browser records CSP, Trusted Types, iframe sandbox flags, document origin, browser blocking, navigation-only behavior, action decision IDs, and redacted Evidence references. Marker execution in an unexpected origin, missing controls, changed bundle, blocked browser, or missing fresh reproduction cannot confirm XSS. An isolated iframe marker is identified as iframe execution, not parent-document access.

## Validation And Retention

Phase 17 alone creates a DOM XSS Finding. Its deterministic validator checks current asset/trace, frozen candidate-hypothesis-plan-run links, completed ordered trial Evidence, policy audit, inert/benign/direct-negative controls, transformed marker execution, fresh context and nonce, target-origin execution, CSP/TT/sandbox observation, and optional source-map provenance. Root-cause fingerprints deduplicate related routes; validation status and Evidence remain separate from recon findings. A confirmed finding pins its supporting JS, source-map, and browser Evidence and binds the validation to the candidate.

Fake-driver unit tests exercise state and validator logic. A loopback-only Chromium fixture separately verifies real check-before-decode execution, direct rejection, benign handling, iframe origin, CSP/sandbox/Trusted Types blocking, reflection-only, and redirect-only behavior. These fixtures do not contact bounty targets.

## Private View And API

The private BugHunter control plane serves `/domxss` and target-scoped `/v1/domxss/<package_id>/...` endpoints for ranked inventory, candidates, metrics, detail, observed-route binding, preparation, plan binding, analysis, and runtime state. Asset URLs are represented by hashes in inventory responses; there is no raw JS or arbitrary payload endpoint. Target summaries include candidate and high-priority counts. The view uses `textContent` for dynamic values and a restrictive CSP.

For candidates scoring at least 75, analysis requests a directly referenced first-party source map through the same policy-gated executor and maps candidate locations when the map is usable. A missing, blocked, or malformed map leaves the static candidate intact and returns a separate source-map status; it never creates a finding.

As in earlier phases, this service is intended to remain on a private Unix socket behind an authenticated dashboard gateway. The current production gateway proxies the JSON route family but does not mount `/domxss`, inject a CSRF token into the page, or grant DOM XSS POST routes its longer operation timeout. Thus the private page is implemented and locally testable, but is not yet accessible as an operational tab in the public recon dashboard. Its mutating buttons remain disabled without a gateway-supplied CSRF token. This phase does not modify or restart the production gateway. Directly exposing the private service is unsupported.

## Limits And Next Phase

Phase 21 uses a bounded function-local AST trace, not whole-program taint analysis. Dynamic helpers, absent route evidence, parser failures, stale hashes, unsupported browser/proxy trust configurations, and ambiguous execution contexts remain review items. The browser action count is conservative; exact target request count may differ because one navigation loads several resources. No notification is sent for candidates.

Recommended Phase 22: a separate postMessage/MessagePort specialist using the same Target Package, policy-gated browser, Evidence, and deterministic-validator boundaries. It should confirm a foreign-origin data or privileged-effect boundary, not classify a message listener or wildcard as a finding by itself.
