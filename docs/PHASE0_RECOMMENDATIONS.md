# Phase 0 Recommendations

## Reuse

- Reuse the production PostgreSQL recon inventory through a future narrow,
  read-only repository. Reuse proven join/query patterns from
  `agentic_hunter_worker.py` and dashboard endpoints, and pure parsing logic
  from `js_analysis.py` where it can be extracted without startup effects.
- Use `scan_snapshots` and `asset_events` for delta candidates; use
  `endpoint_js_references` and `js_analysis_results` to connect endpoint
  hypotheses to JS provenance. Validate all signals independently.
- Reuse the existing block volume for future BugHunter artifacts after a
  separate storage decision. Reuse existing notification conventions only
  after BugHunter has its own evidence and deduplication gate.

## Keep separate and do not duplicate

- Keep BugHunter's hypotheses, experiments, evidence, identity metadata, and
  task state in its own future persistence layer. Do not add BugHunter state to
  recon tables or claim its `bug_jobs` queue during this project.
- Do not copy millions of endpoints/events or duplicate crawlers, ffuf,
  screenshots, dashboard jobs, or existing Agentic/Hunts workers. Do not
  repurpose recon `findings` as confirmed BugHunter reports.
- Keep credentials and sessions in a dedicated future secret/session boundary;
  the recon DB's `auth_profiles` and `hunt_credentials` are not permission for
  model access to secrets. No credential value belongs in a Phase 0 document.

## Constraints and blueprint corrections

- The database is large: planner estimates were about 7.2 million endpoints
  and 10.4 million events. Every future query needs indexed domain filters,
  bounded results, and pagination; bulk export is unsuitable.
- `database_schema.sql` is not the full live schema because startup code adds
  tables and columns. Phase 2 must be tested against the live catalog.
- Raw JS and source-map bodies are not first-class core DB records. Current
  JS metadata and extracted signals can seed analysis, but historical byte
  comparison requires separately retained artifacts or a new, scoped fetch
  in a later authorized phase.
- No central Burp/request-history or GraphQL-operation table was found. Saved
  request files are heterogeneous, and GraphQL evidence is in JS extraction
  and API-surface metadata. Do not promise authenticated traffic attribution
  from recon alone.
- `scope_rules` currently has no rows and `scope.md` is per-hunt prose. The
  target package must supply an explicit program scope source; recon domain
  membership is insufficient. Existing URL/CDN references do not expand it.
- The blueprint mentions Telegram, but inspected runtime alerting is Discord
  with optional SMTP. BugHunter should not assume a Telegram integration.
- PostgreSQL, screenshots, and `codex_artifacts` are block-backed, but the
  Docker `exports_data` named volume remains on the root disk. Storage design
  must specify the artifact location explicitly.

## Exact Phase 1 task

Create only a standalone Python project foundation: typed configuration,
structured redacted logging, CLI commands `version`, `health`, and `status`,
local persistence/artifact path conventions, and tests. `health` may report
configured dependencies but must not mutate or require the production DB;
`status` reports BugHunter's own state only. Add no recon adapter, active
traffic executor, model calls, account login, queue, service, or schema
migration. Run tests and document decisions, then stop for Phase 2 approval.

## Open questions for later phases

- Who provisions a least-privilege database login with `SELECT` on only the
  required recon tables? Creating one would change production and was not
  attempted in Phase 0.
- Which authoritative program-rule source accompanies each target package?
- Which saved HTTP/Burp corpora outside this repository are deliberately
  imported for a target, and under what redaction/retention rules?
- What block-volume directory and retention budget will BugHunter own?
