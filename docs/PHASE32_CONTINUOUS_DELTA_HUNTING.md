# Phase 32: Continuous Recon-Delta Hunting

Phase 32 adds a target-scoped, opt-in DeltaWatcher above the Phase 31 campaign
path. It observes recon and BugHunter cold-start records but never treats a
recon record as testing authorization or a vulnerability. The current
TargetPackage and Phase 13 policy remain authoritative for all campaign work.
The watcher itself has no HTTP executor, browser, or target credentials.

## Sources and checkpoints

- Recon-backed targets use the Phase 2 read-only ReconRepository. The watcher
  resolves the exact target domain, takes a latest-snapshot marker, then reads
  `asset_events` by domain, bounded timestamp window, and keyset cursor. The
  first watch establishes a current high-water mark without enqueuing old
  events. Later watches process at most 100 events per page; a persisted cursor
  drains a backlog before advancing the committed high-water mark. An overlap
  and unique delta key make repeated input idempotent.
- Targets absent from recon use only BugHunter-owned `COLD_START_JS`
  observations and locally saved current JS bodies. A missing or inconsistent
  local artifact degrades the watch without advancing its checkpoint. When a
  target appears in recon, the same watcher identity takes a recon baseline;
  existing cold-start candidates remain linked and are not replayed.
- Recon outages, interrupted watches, or unavailable local provenance remain
  visible as degraded state. No outage falls back to unapproved target traffic.
  Recon PostgreSQL is read-only; all delta state lives in BugHunter SQLite
  schema 48. No production recon schema is changed.

## Classification and evidence

The deterministic classifier recognizes new live hosts, bare discovered
subdomains, endpoints, JS assets, changed JS hashes, API surfaces, and host
fingerprint changes. A bare subdomain is explicitly marked unverified and is
not treated as a live host. Path words raise relevance for privileged and
export/debug surfaces; they are leads, never vulnerability findings. Scope is
checked against the TargetPackage before recording a candidate and again
before launching a campaign. Third-party and removed-from-scope events do not
become runnable work.

When a current JS body is already saved locally, the bounded static pass
compares extracted API routes, GraphQL operations, message handlers,
MessageChannel use, origin/source references, DOM sinks, decoders, source-map
references, and config-pattern presence. It neither executes JS nor fetches
every changed bundle. Same security-relevant signature with a new body hash is
recorded but ignored for automatic work. Missing prior content/hash is marked
unknown or deferred rather than claiming a new vulnerability. A later focused
campaign may use Phase 21 artifact acquisition through normal policy gates.

Candidates retain source ID, entity, redacted display path, old/new hashes,
semantic hash, relevance, specialist hints, status, and campaign linkage.
Each has minimal redacted Evidence with source provenance; no raw recon JSON,
cookies, credentials, or full request/response bodies are copied. Identical
events do not create duplicate candidates. A later meaningful entity state
supersedes an unstarted older candidate. Cooldowns key on root surface and
semantic state, so a genuine state change can be reconsidered without
repeating unchanged work.

## Campaigns and scheduling

Only an explicitly enabled, tracked TargetPackage is scheduled. Per-target
settings include hourly/six-hourly/daily cadence, minimum relevance, allowed
specialists, cooldown, daily focused-campaign cap, and request cap. The
single-process scheduler persists due times, processes at most eight due
targets per tick, and reconciles interrupted watches. Pause, resume, and Check
Now are separate operator actions. The watcher never starts target traffic.

At most one relevant delta starts a focused Phase 31 campaign per pass. Its
seed contains the exact delta, linked passive hypotheses, specialist hints,
and current in-scope source hash. Automatic campaigns use `ANALYZE_ONLY`, one
cycle, at most 12 request slots and no research or setup objects. The existing
CampaignStore atomically enforces target ownership, current scope, active
campaign exclusivity, daily cap, cooldown, and policy/resource limits. An
operator may explicitly start one selected delta in an allowed planner mode;
that action still uses the same campaign and policy path. Specialist and
validator components, not DeltaWatcher, decide whether a Finding exists.

## Control plane and metrics

The private service exposes target-filtered `/v1/continuous/status`,
`/v1/continuous/targets/<package>` controls, and paginated `/v1/deltas`
details/explicit campaign start. The existing dashboard gateway allowlists
only those operations under its login and CSRF protection. `/hackbot/deltas`
shows settings, health, candidate filters, provenance, evidence/hypothesis
links, and campaign/Finding outcomes. Operations shows watcher health.

Metrics expose watch cycles, actual event rows scanned, classified/ignored
deltas, backlog lower-bound count and age, focused campaigns, planner
rejections, Findings, conservative reserved request slots, and average
detection/validation intervals. Yield ratios are Phase 33 inputs, not bounty
value optimization. A null ratio means insufficient denominator; a completed
campaign does not imply that the target is secure.

The recon event stream currently does not provide a dedicated new-parameter
event or per-operation GraphQL event. Those signals arise only when a current
endpoint or saved JS/API artifact supplies reliable metadata. Raw JS and
source-map bodies are not first-class recon records, so semantic coverage is
limited to BugHunter-owned current artifacts. This is an explicit coverage
limit, not a clean result.

## Verification and handoff

Acceptance uses a synthetic eight-snapshot progression, restart/outage,
scope, duplicate, cooldown, cap, cold-start/transition, resource-pressure,
Evidence-retention, and full delta-to-Finding audit-chain fixtures. The Phase
30 source-bound complete test matrix and dashboard gateway/browser tests are
required before controlled schema-48 rollout. No live bounty-target traffic
or recon PostgreSQL write is part of acceptance. Real targets remain disabled
until an operator opts in. Phase 33 may evaluate yield and false-positive
rates; it must not retroactively treat delta signals as confirmed Findings.

On 2026-10-18, the source-bound authoritative matrix passed all 62 assigned
modules in nine groups, including 29 Phase 32 delta tests. The dashboard
gateway passed 16 tests, its four browser smoke tests passed, and the panel
JavaScript passed `node --check`. `git diff --check` passed. The live schema-47
store was backed up as encrypted generation `20261018T194249Z-323a76fa` and
rehearsed in isolation to schema 48 with integrity OK and all 80 Evidence rows
preserved. After a byte-identical quarantine copy and a BugHunter-only service
stop, the live migration reached schema 48 with integrity and foreign keys OK.
The BugHunter service returned health `ok`, readiness `READY`, and continuous
status `explicit_opt_in` with zero enabled targets; the dashboard-only reload
served `/hackbot/deltas` behind its login redirect. Encrypted schema-48 backup
`20261018T194639Z-34c392c8` verified and rehearsed cleanly. Recon PostgreSQL
and the recon worker were not restarted or written to; no bounty-target request
was part of acceptance.
