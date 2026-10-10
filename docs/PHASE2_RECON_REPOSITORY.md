# Phase 2 ReconRepository

The read-only contract is `hackbot.recon.ReconRepository`. Its PostgreSQL
implementation is `hackbot.recon_postgres.PostgresReconRepository`. Importing
either module does not connect to production. No BugHunter state is stored in
recon tables, and recon observations are not findings or program authorization.

## Contract

| Method | Required scope | Returned information |
| --- | --- | --- |
| `resolve_target(identity)` | Exact root name or positive integer `domains.id` | One recon root, or `None` |
| `resolve_host(domain_id, exact_url)` | Root ID and exact stored HTTP(S) origin URL | One live-host record, or `None` |
| `list_hosts` | Root ID | Host pages |
| `list_endpoints`, `list_js_assets` | Root ID and owned host ID | Endpoint or JS metadata pages |
| `list_parameters`, `list_endpoint_js_references` | Root ID and owned endpoint ID | Parameter names/tags or linkage IDs |
| `get_js_analysis` | Root ID and owned JS asset ID | Extraction byte size and six bounded signal counts |
| `list_api_surfaces` | Root ID and exact surface type | API-surface hint pages |
| `list_scan_snapshots` | Root ID | Completed scan-window pages |
| `list_asset_events` | Root ID and naive start/end timestamps, at most 31 days apart | Event pages without payload JSON |

Methods return compact frozen DTOs and `Page(items, next_cursor)`. They do not
return a Boolean authorization decision. `recon_present` means only that a root
is in the recon inventory. Future `ProgramScope` must independently establish
active-test authorization. A hostname in the database, a CDN URL, or
`domains.active` never supplies that authority.

## Pagination and provenance

Pages are limited to a configurable maximum of 1-100 items (default 50).
Requests above that maximum are clamped. The SQL fetches at most one extra
row to determine whether a next cursor exists. Cursors contain a version,
operation kind, exact root/child/window scope, and a keyset position. Reusing
a cursor for another scope or method is rejected. Hosts use
`(subdomain ASC, host_id ASC)`; other pages use `(last_seen DESC, id DESC)`;
scan windows use `(scan_finished_at DESC, id DESC)`. No OFFSET or total-count
query is used. Since recon rows can be updated between page calls, pagination
is best-effort rather than an immutable snapshot.

Every DTO includes `Provenance(source_table, source_id, observed_at,
qualification)`. `latest_recon_row` means the latest stored row metadata, not
proof that an asset is currently deployed. `recon_hint`, `recon_event`,
`completed_scan`, and `extraction_metadata` are distinct. `js_assets.sha256`
is the latest stored hash, not a historical body. Raw JS, source maps, and
canonical Burp/full HTTP traffic are unavailable through this contract.

## Credentials and transactions

Runtime requires the optional `recon` package extra (psycopg2). Configuration
contains only an environment-variable name, never a DSN value:

```toml
[recon]
dsn_env = "HACKBOT_RECON_DSN"
max_page_size = 50
statement_timeout_ms = 3000
```

The timeout is constrained to 100-5000 ms. `from_config()` resolves the
environment variable only when the adapter is explicitly constructed.
`version`, `health`, and `status` never connect. Every adapter call uses a
fresh connection, `BEGIN READ ONLY`, transaction-local `statement_timeout`,
parameterized `SELECT`, explicit rollback, and close. Database exceptions are
converted to a generic error without SQL parameters or credentials. No
production module, schema initializer, worker, or migration is imported.

Provision a dedicated BugHunter role later with `SELECT` only on the necessary
recon tables and no DDL/DML privileges. No role or GRANT was created in Phase
2. Until such a role exists, read-only transactions and bounded queries are
mandatory even if the supplied account has broader permissions.

## Sensitive fields

The repository never selects `url_parameters.example_value`, raw
`js_analysis_results.extraction`, `risk_summary`,
`endpoint_js_references.found_value`, event `payload`, or recon credential and
auth-profile tables. JS analysis returns only `pg_column_size` and counts for
selected array-like signal categories. API-surface `metadata` and scan JSON
aggregates are omitted. Callers must still treat URLs and paths as untrusted
data and never log DTOs wholesale; Phase 1 redaction remains an output guard.

## Live verification and limits

On 2026-10-10 UTC, the live catalog was checked for the 11 referenced tables,
columns, non-null cursor timestamps, and indexes. Planner estimates remained
large (about 7.16 million endpoints, 10.38 million events, 8.07 million
endpoint-JS references, and 812,677 API-surface hints). Bounded `EXPLAIN`
showed indexed access for `subdomains(domain_id,subdomain)`,
`live_hosts(subdomain_id)`, `endpoints(live_host_id,last_seen)`,
`api_surfaces(domain_id,surface_type,last_seen)`, and
`asset_events(domain_id,last_seen)`. The `(last_seen,id)` ordering uses a small
incremental tie sort where `id` is not part of the index. A joined endpoint
query preferred a host index plus sort, so the adapter checks host ownership
first and then pages endpoints directly by host using the composite index.
Parameter and endpoint-JS reference pages use their verified `endpoint_id`
indexes but may sort the rows of one selected endpoint; the short timeout
remains a guard for an unusually large fan-out.

Production verification used only explicit `BEGIN READ ONLY` transactions,
3-5 second statement timeouts, bounded `LIMIT 1-3` selections, and `EXPLAIN`
without `ANALYZE`. A representative root (ID 5) and host (ID 1272) resolved;
small endpoint, JS metadata, analysis-count, GraphQL-surface, completed-scan,
and event selections succeeded. The selected endpoint had no parameter or
endpoint-JS reference rows; those query shapes are covered by fixture tests.
The generated six-count JS-analysis query itself returned one bounded row.
`SELECT set_config(..., true)` inside a read-only transaction was verified.
No production SQL writes, service changes, or target requests were made.

The optional Python PostgreSQL driver was not present in the VPS environment
during this phase. Production SQL was verified via `psql`, while the Python
adapter was exercised through deterministic DB-API fakes. A future live
adapter smoke test should use the dedicated SELECT-only role after it is
provisioned; this phase does not claim that such a role or credential exists.
