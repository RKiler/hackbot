# Phase 12: Passive Attack-Surface Profiling and Hypotheses

## Contract

Profiling requires an authoritative local Target Package. Recon domain membership is
inventory, never authorization. The explicit `Profile Target` action reads bounded
metadata from the read-only `ReconRepository`, local Evidence/Facts, owned identity
metadata, and local TrafficStore metadata. It issues no target HTTP requests and
does not read stored request/response bodies or raw JavaScript. A missing recon
adapter is an explicit coverage gap; local-only profiling remains available.

`TargetProfile` is a typed, timestamped snapshot containing source-tagged signals,
technologies, API styles, features, boundaries, candidate object types, identity
capabilities, recent changes, coverage counters, and gaps. Its sources are
`RECON`, `JS_ANALYSIS`, `TRAFFIC`, `MANUAL`, `TARGET_PACKAGE`, `IDENTITY_REGISTRY`,
`FACT`, and `EVIDENCE`. A signal's confidence measures observation quality, not
exploitability or severity. A hostname, route, parameter, or JS extraction is a
lead, never a bug. Object ownership remains unknown until explicitly learned.
Sensitive/secret Facts are excluded from profile labels and hypothesis context;
Evidence references remain metadata-only.
`javascript_heavy` means at least three JS assets occurred in the bounded sample;
`message_passing` and `source_map_count` are also sample indicators, not whole-
target coverage claims. Organization, workspace, feature-permission, cross-origin,
client/server, internal/external, and ownership labels are explicitly candidates
unless an authoritative observed/configured relationship exists. Ownership gaps
are recorded as `OBJECT_OWNERSHIP_UNKNOWN`.

The profiler checks the latest two delta snapshots available in at most three
eight-row snapshot pages, at most 24 events, 12 hosts, 12 endpoints and five JS
assets per host, 12 JS analyses, 20 parameter pages, eight endpoint-JS reference
pages, six API surfaces per type,
20 traffic exchanges, 16 facts, and 12 evidence records. Limits are configurable
in `ProfileLimits`; truncation is recorded. Out-of-scope hosts and routes are
filtered through the Target Package before they become actionable signals.
Unknown paths are represented as safe shapes rather than full URL values.

## Detection

Deterministic indicators recognize REST, GraphQL, WebSocket, RPC, OAuth,
postMessage, source maps, admin/internal hosts and routes, downloads/exports,
uploads, webhook/URL/redirect parameters, and token-like JS extraction counts.
Features include organizations, workspaces, projects, teams, roles, integrations,
webhooks, uploads, exports, sharing, billing, invitations, admin functions,
dashboards, documents, comments, and API keys. Boundaries come only from
configured identities, observed auth signals, or explicit route/parameter
metadata; candidate ownership is labeled as such.

## Hypothesis Engine

Each hypothesis has a stable target/concept/surface/boundary hash, category,
statement, non-confirming status, priority, confidence, potential impact,
supporting Evidence/Fact IDs, prerequisites, missing prerequisites, an abstract
future experiment, positive/negative signals, skill hints, provenance, and
timestamps. Initial rules cover cross-tenant object IDs, role/admin routes,
GraphQL with multiple identities, postMessage plus MessageChannel on the same
asset, decoder plus DOM sink on the same asset, authenticated downloads,
internal hosts/routes, person-level exports, token-like JS exposure, URL parameters,
and redirects.
Unknown technology creates a `NEEDS_RESEARCH` task, not a guessed exploit.

Rules are intentionally narrow. `READY_FOR_EXPERIMENT` means listed structural
prerequisites were observed or configured, not that permission to execute has
been independently rechecked. Missing second tenant or different-role identity
blocks an applicable hypothesis; missing ownership, current JS body, request
template, or policy evidence leaves it enriching. Phase 12 never emits payloads
or confirms a vulnerability. `CONFIRMED` is absent from both the Python enum and
SQLite status constraint.

Priority starts from rule-specific base weights (75 cross-tenant, 72 role, 68
download, 65 GraphQL/postMessage, 62 person-level export, 60 DOM, 55/53 internal, 45 credential lead,
43 URL parameter, 35 redirect). Add 6 for observed recon/traffic/JS/fact evidence,
8 for recent delta, 5 for captured traffic, 3 for an endpoint-JS reference,
and subtract 5 per missing prerequisite
up to 30. Clamp to 0-100. This is triage priority, **not** vulnerability probability,
CVSS, bounty value, or confirmed severity. Confidence is the average of supporting
signal confidence, capped at 0.9.

Every machine-generated hypothesis links to target-matched Evidence and/or Facts.
Compact evidence is materialized from source pointers only once per source revision,
never from raw response or secret values. Researchers may add unsupported manual
hypotheses, explicitly labeled `MANUAL`. The unique target/dedupe key suppresses
repeat hypotheses; repeat profiling preserves IDs and records status/priority
changes in append-only history. Simple `DUPLICATE_OF`, `DEPENDS_ON`, `VARIANT_OF`,
and `SUPERSEDES` relationships are available, not a task graph.

`ContextPacketBuilder` returns one hypothesis, a compact profile summary, up to
four matching signals, six evidence references, and four fact references. It
does not include source bodies, all traffic, all JS, or all notes. Processing
order is bounded repository filters, deterministic rules, then compact packet;
model reasoning is deferred. No LLM or skill is executed here.

## Dashboard and API

The authenticated Phase 11 dashboard adds `/hackbot/hypotheses`, a target Profile
tab, list/detail views, manual hypothesis entry, and explicit `Profile Target`.
The Unix-socket gateway preserves dashboard authentication and CSRF protection
for POSTs; no client cookies or authorization headers are forwarded to BugHunter.
Core endpoints are `/v1/targets/{package}/profile`, `/v1/hypotheses`,
`/v1/hypotheses/{id}`, and `/v1/hypotheses/manual`. There is no background
schedule. The private service API is not a public internet endpoint.

## Phase 13 Handoff

The explicit Phase 12 brief names normal-behavior/ownership learning as a later
need, but `docs/blueprint/02_ROADMAP.md` currently labels Phase 13 as
ScopeGuard/RiskPolicy/RatePolicy/MethodPolicy/TargetPolicy. Resolve the phase
numbering before implementation. The recommended immediate Phase 13 task is
the policy guard and prerequisite contract, with deterministic ALLOW/DENY/
REQUIRE_APPROVAL decisions, no active executor yet. Owned object/tenant mapping
and genuine request-template learning should follow behind that guard. No
future component may promote a passive hypothesis directly to a finding.
