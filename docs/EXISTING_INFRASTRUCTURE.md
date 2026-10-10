# Existing Infrastructure

Observed on the VPS on 2026-10-10 UTC. This is a read-only inventory, not a
health certification or permission to test any target. Sources: production
`/root/enhanced_recon_framework/docker-compose.yml`, `database_schema.sql`,
`continuous_recon.py`, `dashboard.py`, `config.yaml` key names, process lists,
mount metadata, and bounded read-only `pg_catalog` queries. No secrets or
customer records were read for this document.

## Runtime and storage

- The main Compose project runs PostgreSQL 16, Redis 7, the recon scheduler,
  the dashboard, monitor/port/Shodan/search/ffuf workers, bug-job worker and
  curator, hunt coordinator, Agentic hunt and mail bridge, delta-intelligence
  and AI-assistant workers, plus Prometheus, Grafana, and postgres-exporter.
  All were listed as running at inspection time. `nordvpn-egress` exists behind
  an optional Compose profile and was not listed as running. See
  `docker-compose.yml` service definitions.
- `continuous_recon.py` uses `asyncpg` against `recon_framework`. PostgreSQL
  publishes only on host `127.0.0.1:5432`; its data directory is a bind mount
  at `/mnt/volume_sfo2_1788290659423/postgres_data` on `/dev/sda`. Redis is
  published on `127.0.0.1:6379`. The dashboard is bound to host
  `127.0.0.1:5000`; public routing is handled outside this Compose project.
- Screenshots and `/root/codex_artifacts` are block-backed. The Compose
  `exports_data` named volume resides under `/var/lib/docker/volumes` on the
  root disk. Do not assume every saved artifact is on the block volume.
- Separate `interaction-hub-proxy`, callback, and XSS Hunter containers also
  exist. They are not part of the recon Compose project and were not changed.
- `codex-human-browser.service` and `codex-hunt-login-broker.service` were
  active. Recon scheduling is in the recon application; no relevant systemd
  timer or root crontab entry was found. There were 72 tmux sessions, which
  is not evidence that 72 hunts were active.

## Recon model

The live PostgreSQL schema, not just `database_schema.sql`, was checked. It
contains 65 root-domain rows, all active, and 1,613 completed non-first-run
scan snapshots at inspection time. Core foreign-key chain:

`domains -> subdomains -> live_hosts -> endpoints -> url_parameters`

`live_hosts -> js_assets -> js_analysis_results`

`endpoints <-> js_assets` through `endpoint_js_references`.

`scan_snapshots`, `asset_events`, `findings`, `scope_rules`, `auth_profiles`,
and `api_surfaces` are domain-level or domain/host-linked side tables. See
`RECON_INTEGRATION.md` for exact fields and adapter guidance.

PostgreSQL planner estimates were roughly 7.2 million `endpoints`, 10.4
million `asset_events`, and 1.8 million `bug_jobs`; these are estimates, not
exact counts. Any adapter must filter by domain/host and use indexed, bounded
keyset queries. `database_schema.sql` and startup code both create or alter
tables; the live catalog must be checked before relying on a field or index.

## Scope, content, and traffic

- `domains.active`, `include_subdomains`, and stored hosts describe recon
  configuration, not program authorization. The live `scope_rules` table had
  no rows. Repository `scope.md` contains hunt-specific operator notes, not a
  complete machine-readable global scope registry. Program rules still need
  independent confirmation for each target.
- `js_assets` stores URL, SHA-256, size, HTTP status, source, and seen times;
  `js_analysis_results` stores extracted signals and summaries. The core DB
  does **not** store raw JavaScript response bodies. Source-map discovery and
  parsing helpers exist in `js_analysis.py`, but no dedicated source-map
  table appeared in the live schema. A current fetch or a separate saved
  corpus would be needed later for raw-body analysis; no fetch occurred here.
- `endpoints` stores method, path, source, parameters JSON, risk tags, status,
  and seen times. It is a discovery inventory, not a complete record of
  authenticated request bodies or response content.
- No public-schema table named for Burp, HTTP request history, or GraphQL
  operations was found. There are ad-hoc artifacts under `requests/` and
  `exports/`, which may contain sensitive material and were not opened.
  GraphQL signals instead appear in JS extraction and `api_surfaces` metadata.
- `scan_snapshots` has run windows and aggregate counts; `asset_events` has
  event type, entity reference, payload, and first/last seen. `js_assets` is
  upserted with the latest hash. These do not constitute immutable historical
  JS bodies or full per-request history.

## Notifications

`continuous_recon.py` provides Discord alerts and optional SMTP; alert
metadata also exists in `alerts`. A dedicated confirmed-bug Discord helper
exists. No Telegram implementation was found in the inspected recon code or
configuration. Phase 0 sent no notification and read no webhook value.
