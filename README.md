# BugHunter Agent

Phase 10 adds a Burp capture adapter and identity-aware proxy routing on top of
the local, vendor-neutral Traffic Store. Burp is not installed on this VPS, so
real Burp/HTTPS interception remains unverified; local bridge fixtures pass.
There is no replay or active scanning.
The source blueprint is preserved in
[`docs/blueprint/`](docs/blueprint/README.md). The discovery results are in
[`docs/EXISTING_INFRASTRUCTURE.md`](docs/EXISTING_INFRASTRUCTURE.md),
[`docs/RECON_INTEGRATION.md`](docs/RECON_INTEGRATION.md),
[`docs/PHASE0_RECOMMENDATIONS.md`](docs/PHASE0_RECOMMENDATIONS.md), and
[`docs/DECISIONS.md`](docs/DECISIONS.md).

Install and inspect locally:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/hackbot version
.venv/bin/hackbot health
.venv/bin/hackbot status
.venv/bin/hackbot target validate tests/examples/targets/example
.venv/bin/hackbot identity import example
.venv/bin/hackbot identity list example
.venv/bin/hackbot identity show example org1_admin
.venv/bin/hackbot secret check ref:fixture_admin
.venv/bin/hackbot auth status example org1_admin
.venv/bin/hackbot browser create example --anonymous
.venv/bin/hackbot browser list example
.venv/bin/hackbot traffic list example
.venv/bin/hackbot traffic stats example
.venv/bin/hackbot burp check
.venv/bin/hackbot burp status
```

The `example` commands require `[targets].root` to point at
`tests/examples/targets`; `secret check` reports unavailable until an explicit
provider binding is configured. No fixture credential is supplied.

The install includes PyYAML for strict local Target Package loading. Install
`.[browser]` to use the optional Playwright browser driver. In an
offline environment, use preinstalled or locally supplied wheels. Run tests with
`.venv/bin/python -m unittest discover -s tests -t . -v`.
If Playwright is installed but its default Chromium is not, set
`HACKBOT_TEST_CHROMIUM` to an absolute Chromium executable path for browser
fixture tests.

Configuration is optional TOML. Use `hackbot --config /path/to/config.toml
health` or set `HACKBOT_CONFIG`. An explicitly selected missing file is an
error; with no file selected, safe defaults apply. For example:

```toml
[paths]
root = "/path/to/local/bughunter-data"

[logging]
level = "INFO"

[targets]
root = "/path/to/local/targets"

[secrets]
allowed_env_prefixes = ["HACKBOT_SECRET_"]

[secrets.references."ref:fixture_admin"]
provider_ref = "env:HACKBOT_SECRET_FIXTURE_ADMIN"
kind = "COOKIE"

[browser]
profile_root = "/path/to/local/bughunter-data/browser-profiles"
# Optional dedicated manual-login display and loopback noVNC URL:
# display = ":901"
# vnc_url = "http://127.0.0.1:6901/vnc.html"
# chromium_executable = "/path/to/trusted/chromium"
```

`HACKBOT_HOME` overrides the default state root when TOML does not specify
one. `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are also respected. The default
config path is `~/.config/bughunter-agent/config.toml`; the temporary local
state root is `~/.local/state/bughunter-agent`. A relative TOML root resolves
from the config file directory; a relative `HACKBOT_HOME` resolves from the
working directory. `version`, `health`, and `status` do not create them;
explicit state-changing commands may.

Under the configured root, `state/` is reserved for BugHunter-owned runtime
state, `artifacts/` for generated outputs, `artifacts/evidence/` for
content-addressed evidence, `logs/` for future persisted logs, and `tmp/` for
temporary files. This is a development default, not a final block-volume or
retention decision. The
Phase 1 logger writes redacted JSON to stderr; it does not persist logs.

The optional PostgreSQL adapter is documented in
[`docs/PHASE2_RECON_REPOSITORY.md`](docs/PHASE2_RECON_REPOSITORY.md). It is
never initialized by `version`, `health`, or `status`. Its credential is read
only from the environment variable named by `[recon].dsn_env`; no DSN or
password belongs in TOML. Install the optional `recon` extra before using
the adapter outside fixture tests.

The standalone SQLite Evidence and Fact Store is documented in
[`docs/PHASE3_EVIDENCE_FACT_STORE.md`](docs/PHASE3_EVIDENCE_FACT_STORE.md).
It is initialized only by explicit registry/library operations, never by
`version`, `health`, or `status`. It has no
production PostgreSQL dependency and performs no automatic ingestion.

The typed attack-surface, identity-boundary, object, operation, and traffic
records are documented in
[`docs/PHASE4_CORE_DOMAIN_MODEL.md`](docs/PHASE4_CORE_DOMAIN_MODEL.md).
They have no Phase 4 persistence or active traffic executor.

Target Package layout, authoritative scope, pure autonomy/rate policy, and
secret-safe account references are documented in
[`docs/PHASE5_TARGET_PACKAGE_SCOPE.md`](docs/PHASE5_TARGET_PACKAGE_SCOPE.md).
`hackbot target show <id>` reads only the configured local target root. A
recon host's presence never authorizes testing. Phase 5 uses PyYAML for strict
local package loading; it does not add target requests or services.

The local, secret-free Identity Registry is documented in
[`docs/PHASE6_IDENTITY_REGISTRY.md`](docs/PHASE6_IDENTITY_REGISTRY.md).
It reuses the BugHunter SQLite file through an explicit version-2 migration.
Use `identity import` explicitly after configuring `[targets].root`; no account
declaration is imported automatically. Phase 6 itself did not provide
credentials or browser sessions; later phases add those pieces without
changing the registry's secret-free data model.

`health` checks only configuration and local paths. `status` reports only
BugHunter's local foundation and adapter availability. Neither contacts
PostgreSQL, reads recon data, sends target requests, or starts services.
There is no running agent, target executor, production database migration, or
active traffic execution or replay. The optional Phase 10 Burp adapter captures
traffic only when an operator separately configures and starts its components.

Secret values belong only in the selected provider, never in TOML, SQLite,
Target Packages, evidence, CLI output, or prompts. `secret check` reports only
availability; it does not resolve or print values. `auth status` reads local
metadata. See [`docs/PHASE7_SECRET_PROVIDER_AUTH_CONTEXT.md`](docs/PHASE7_SECRET_PROVIDER_AUTH_CONTEXT.md).

Browser session design, manual VNC login, imported-cookie limits, and the
identity-verification gate are documented in
[`docs/PHASE8_BROWSER_SESSION_MANAGER.md`](docs/PHASE8_BROWSER_SESSION_MANAGER.md).
`browser create` only allocates metadata/profile storage. A trusted long-running
caller uses the manager API to launch and verify a session; the CLI does not
start target browsing or own a background browser process. The optional VNC
helper is not started automatically.

Traffic storage, redacted CLI views, bounded queries, and the later Burp handoff
are documented in [`docs/PHASE9_TRAFFIC_STORE.md`](docs/PHASE9_TRAFFIC_STORE.md).
Burp project/listener setup, the capture-only Montoya extension, authenticated
loopback bridge, profile-only CA trust, and local verification are documented
in [`docs/PHASE10_BURP_INTEGRATION.md`](docs/PHASE10_BURP_INTEGRATION.md).
