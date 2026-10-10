Dashboard architecture decision:

BugHunter will eventually expose a dedicated API and UI, but the preferred
frontend is integration into the existing recon dashboard rather than creating
an unrelated second dashboard.

BugHunter backend state remains logically separate from recon state.

The existing dashboard may consume BugHunter APIs for targets, identities,
hunts, hypotheses, evidence, traffic, skills, approvals, and findings.

Do not implement the dashboard during Phase 1. Implement it only after the
core BugHunter domain models and API contracts have stabilized.

# Architecture Decisions

Decisions recorded 2026-10-10 UTC. Revisit when the relevant later phase is
explicitly requested; none authorizes production mutation now.

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-001 | Use a separate `/root/bughunter-agent` Git repo. | The bootstrap requires isolation; the recon Compose project is already live and multi-worker. |
| D-002 | Treat recon code, containers, and database as read-only through Phase 0. | Production PostgreSQL and workers are running; discovery does not require writes. |
| D-003 | Defer `ReconRepository` implementation to Phase 2. | Phase 0 is documentation; the roadmap assigns the adapter to Phase 2. |
| D-004 | Resolve authorization outside recon inventory. | `domains.active` is recon state and the live `scope_rules` table has no rows. |
| D-005 | Query the live catalog before coding against it. | Startup code creates/alters tables beyond `database_schema.sql`. |
| D-006 | Page by indexed keys and avoid whole-table/context dumps. | Live planner estimates show multi-million-row endpoint and event tables. |
| D-007 | Keep raw secrets and customer traffic out of docs and prompts. | Existing credential references and ad-hoc request artifacts may be sensitive. |
| D-008 | No alert, target request, agent, container, migration, or scheduled job in Phase 0. | The bootstrap and roadmap explicitly exclude them. |
| D-009 | Package Phase 1 as a stdlib-only Python 3.11+ `hackbot` CLI with typed, optional TOML configuration. | Keeps startup side-effect-free and installation simple; config rejects unknown keys and never contains recon credentials. |
| D-010 | Use a configurable local state root with separate `state`, `artifacts`, `artifacts/evidence`, `logs`, and `tmp` conventions. Do not create them during `health` or `status`. | Phase 1 needs path ownership without choosing an unverified block-volume placement or retention policy. |
| D-011 | Emit JSON logs only through a redacting formatter that masks sensitive keys, common free-text credentials, and known credential-like environment values. Omit exception messages and tracebacks. | Prevents routine diagnostics from disclosing credentials while keeping logs machine-readable. |
| D-012 | Defer browser/HTTP capture and execution interfaces. Future traffic records must be generic and proxy-agnostic, with source provenance such as BURP, BROWSER, HACKBOT, IMPORT, or FIXTURE. Burp may be a capture/interception backend, not the core model or reasoning engine. | The blueprint places traffic models and execution in later phases; Phase 0 found no central request-history store. |

No dedicated read-only DB role, target package scope authority, or BugHunter
artifact retention policy was created or selected here. They remain later
integration decisions, not silent defaults.

## Phase 2

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-013 | Expose a typed, read-only `ReconRepository` protocol; put PostgreSQL SQL in a separate adapter. | Later consumers should not depend on production table names or SQL. |
| D-014 | Resolve only exact root names or integer domain IDs, and resolve hosts by exact stored origin URL. Recon presence never authorizes testing. | Avoid accidental wildcard/hostname inference and scope confusion. |
| D-015 | Require a host, endpoint, asset, or API-surface type for large related lists; use `(last_seen,id)` or `(subdomain,id)` keyset cursors and clamp pages to a configured maximum. | Live catalog indexes and bounded `EXPLAIN` plans support these shapes; domain-wide endpoint/JS scans are not a Phase 2 API. |
| D-016 | Read with a fresh `BEGIN READ ONLY` transaction, transaction-local timeout, and rollback. Resolve DSN only from a named environment variable; recommend a dedicated SELECT-only role without creating one. | Production isolation and credential handling must hold even when current integration credentials are privileged. |
| D-017 | Return compact extraction counts and provenance, never raw JS/source-map bodies, full extraction JSON, parameter examples, or endpoint-JS found values. | The live schema stores metadata/extracted signals, not immutable JS bodies or canonical traffic. |
