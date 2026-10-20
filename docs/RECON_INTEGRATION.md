# Recon Integration: Read-Only Contract

This describes the **observed** production schema and the Phase 0 adapter
guidance. The Phase 2 implementation and verification are documented in
[`PHASE2_RECON_REPOSITORY.md`](PHASE2_RECON_REPOSITORY.md). Catalog
inspection used `BEGIN READ ONLY` with a five- or ten-second statement
timeout; source references are under `/root/enhanced_recon_framework`.

## Tables and relationships

| Entity | Key fields useful to BugHunter | Relationship / caveat |
| --- | --- | --- |
| `domains` | `id`, `domain`, `active`, `include_subdomains`, `last_scan`, `scan_interval_hours`, feature toggles | Root recon configuration; **not** proof of bounty scope. |
| `subdomains` | `id`, `domain_id`, `subdomain`, `is_resolved`, `ip_addresses`, first/last seen | FK to `domains`; DNS resolution is not HTTP liveness. |
| `live_hosts` | `id`, `subdomain_id`, `url`, `protocol`, `port`, status, title, fingerprint, first/last seen | FK to `subdomains`; URL is unique. |
| `endpoints` | `id`, `live_host_id`, `path`, `path_hash`, `method`, `status_code`, `source`, `parameters`, `risk_tags`, first/last seen | FK to `live_hosts`; unique by host, path hash, method, source. Discovery/probe metadata is not a full HTTP exchange. |
| `url_parameters` | `id`, `endpoint_id`, `param_name`, `example_value`, `risk_tags`, first/last seen | FK to `endpoints`; example values may be sensitive and should not enter model context by default. |
| `js_assets` | `id`, `live_host_id`, `asset_url`, `sha256`, `size_bytes`, `http_status`, `source`, first/last seen | FK to `live_hosts`; latest metadata only, no raw body column. |
| `js_analysis_results` | `js_asset_id`, `extraction`, `risk_summary`, `analyzed_at` | One row per JS asset; extracted signals, not vulnerability proof. |
| `endpoint_js_references` | `endpoint_id`, `js_asset_id`, `found_value`, first/last seen | FKs to both sides; links discovered endpoint strings to JS. |
| `scan_snapshots` | `id`, `domain_id`, start/finish, `first_run`, `totals`, `new_counts`, `metadata` | Domain-level scan windows and aggregate results. |
| `asset_events` | `id`, `domain_id`, `event_key`, `event_type`, `entity_type`, `entity_id`, `location`, `payload`, first/last seen | Domain FK and indexed `(domain_id,last_seen)`; entity pointer is polymorphic, not a general FK. |
| `api_surfaces` | `domain_id`, `live_host_id`, `surface_type`, `location`, status, methods, operations count, risk flags, metadata | Useful GraphQL/OpenAPI surface hints, not observed request bodies. |
| `findings` | `domain_id`, `finding_key`, type, severity, location, details, first/last seen | Recon signals may be noisy; do not promote to confirmed BugHunter findings. |
| `scope_rules`, `auth_profiles` | domain linkage, rule/host pattern or secret reference | `scope_rules` was empty; never copy or dereference auth secrets in this adapter. |

The FK joins are verified from the live catalog. Useful live indexes include
`endpoints(live_host_id,last_seen DESC)`, `js_assets(live_host_id,last_seen
DESC)`, `url_parameters(endpoint_id,last_seen DESC)`,
`asset_events(domain_id,last_seen DESC)`, and
`scan_snapshots(domain_id,scan_finished_at DESC)`. Inspect catalog/indexes
again before Phase 2 because this database evolves at runtime.

## Recommended adapter boundary

Build a separate `ReconRepository` in Phase 2, not in Phase 0. Use a dedicated
read-only connection when provisioned; until then, every query must run inside
a read-only transaction with a short statement timeout. Do not import the
production application's startup classes: their `ensure_schema()` paths can
write to the database. Reuse its SQL patterns and pure parsing/hostname
helpers only after isolating and testing them.

Minimum operations: resolve a root and exact host; page hosts, endpoints,
parameters and JS assets for a selected root; fetch one asset's extraction;
list endpoint-JS references and API-surface hints; select completed delta
windows; and page matching asset events. Each result should carry source
table/row ID, observed time, current-versus-historical qualification, and a
separate authorization/scope decision. Use parameterized queries, a required
domain ID, strict `LIMIT`, and keyset cursors on indexed columns. Do not use
unbounded offsets or transfer whole JSON extraction fields into model prompts.

## Delta and provenance limits

The existing Agentic worker's `latest_delta_window()` selects up to the two
newest completed snapshots where `first_run=FALSE`, and `export_packet()`
queries bounded host/endpoint/JS/event samples. These are useful reference
patterns, not an exhaustive or stable adapter. Snapshot windows plus
`first_seen` can identify candidates, while `asset_events` provides additional
change signals. Neither proves that today's JS bytes equal the bytes served
in an old scan. Hash changes overwrite the prior `js_assets.sha256`; use an
explicit saved corpus if historical body comparison is required later.

Before any active operation in a later phase, independently validate the
program's scope source and the parsed request hostname. A row in this DB,
an `active` domain flag, a CDN reference, or an allowed recon crawler target
does not authorize BugHunter testing.

## Focus-host and wildcard resolution

`ReconDomainResolver` first checks the exact `domains` row, then the exact
`subdomains` row and its `domain_id` foreign key (whether or not a `live_hosts`
row exists). Only if neither exists does it try a bounded parent suffix that
must itself have a `domains` row. This is recon identity, not authorization.
For an explicit TargetPackage wildcard, the read-only adapter counts known,
live-host, and latest-scan subdomains and pages at most 200 recent live-host
origins per wildcard. The resolver checks each candidate against the package's
full origin scope, scores up to 32 host records, and selects at most four
related hosts. Bootstrap still has its own smaller request and seed budgets;
no wildcard host is contacted merely because it appears in recon. In this
schema endpoints and JS assets are children of `live_hosts`, so an exact
subdomain without a live host can resolve the recon root but cannot provide
host-bound endpoint/JS seeds.
