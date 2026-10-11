# Read-only recon operator setup

BugHunter uses the dedicated PostgreSQL login `bughunter_recon_reader` to read
production recon metadata. It is not a target-testing authorization source.
The role has `CONNECT` on `recon_framework`, `USAGE` on `public`, and explicit
`SELECT` grants on these tables only:

`domains`, `subdomains`, `live_hosts`, `endpoints`, `url_parameters`,
`js_assets`, `js_analysis_results`, `endpoint_js_references`,
`scan_snapshots`, `asset_events`, and `api_surfaces`.

The role has no elevated attributes, schema ownership, or table write grants.
`hunt_credentials` and `auth_profiles` are intentionally inaccessible. Its
session defaults to read-only transactions and a five-second statement timeout;
the Phase 2 adapter additionally uses `BEGIN READ ONLY` and a three-second
transaction-local statement timeout.

The root-owned mode-0600 file
`/root/.config/bughunter-agent/recon.env` supplies `HACKBOT_RECON_DSN` to
`bughunter-agent.service` through the systemd drop-in
`/etc/systemd/system/bughunter-agent.service.d/recon-reader.conf`. The DSN and
password must never be committed, documented, printed, or included in support
logs. The optional `recon` Python extra must be installed in BugHunter's own
virtualenv, not globally.

Check local service health with:

```sh
curl --silent --unix-socket /run/bughunter-agent/control.sock http://localhost/v1/health
```

`recon_integration: configured_read_only` means the adapter was constructed;
it is not a live database probe. Verify database connectivity separately with
a bounded `PostgresReconRepository` lookup under the service environment.
Do not use the production recon login for BugHunter or grant access to all
tables by default.
