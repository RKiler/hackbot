# BugHunter Agent

Phase 3 adds a local Evidence and Fact Store to the standalone Python
foundation. The source blueprint is preserved in
[`docs/blueprint/`](docs/blueprint/README.md). The discovery results are in
[`docs/EXISTING_INFRASTRUCTURE.md`](docs/EXISTING_INFRASTRUCTURE.md),
[`docs/RECON_INTEGRATION.md`](docs/RECON_INTEGRATION.md),
[`docs/PHASE0_RECOMMENDATIONS.md`](docs/PHASE0_RECOMMENDATIONS.md), and
[`docs/DECISIONS.md`](docs/DECISIONS.md).

Install and inspect locally:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/hackbot version
.venv/bin/hackbot health
.venv/bin/hackbot status
```

The virtualenv command above uses the VPS's existing `setuptools` for an
offline install. Run tests with
`.venv/bin/python -m unittest discover -s tests -v`.

Configuration is optional TOML. Use `hackbot --config /path/to/config.toml
health` or set `HACKBOT_CONFIG`. An explicitly selected missing file is an
error; with no file selected, safe defaults apply. For example:

```toml
[paths]
root = "/path/to/local/bughunter-data"

[logging]
level = "INFO"
```

`HACKBOT_HOME` overrides the default state root when TOML does not specify
one. `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are also respected. The default
config path is `~/.config/bughunter-agent/config.toml`; the temporary local
state root is `~/.local/state/bughunter-agent`. A relative TOML root resolves
from the config file directory; a relative `HACKBOT_HOME` resolves from the
working directory. No command creates these directories.

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
It is initialized only by explicit library use, never by the CLI. It has no
production PostgreSQL dependency and performs no automatic ingestion.

`health` checks only configuration and local paths. `status` reports only
BugHunter's local foundation and adapter availability. Neither contacts
PostgreSQL, reads recon data, sends target requests, or starts services.
There is no running agent, target executor, production database migration, or
active traffic integration.
