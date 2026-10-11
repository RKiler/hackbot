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

## Phase 3

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-018 | Persist BugHunter Evidence and Facts in an explicitly initialized local SQLite store, separate from recon PostgreSQL. | The Phase 3 state is BugHunter-owned; no production schema changes or recon ingestion are needed. |
| D-019 | Give Evidence and Facts generated namespaced IDs, immutable base rows, and append-only retention/status histories. Correct evidence by replacement link. | Historical observations and contradictions must remain auditable and cannot be silently rewritten. |
| D-020 | Keep large and restricted evidence bytes in a configurable SHA-256 content-addressed artifact store; permit small PUBLIC/INTERNAL bytes inline. | Multiple evidence records can share one artifact without duplicating large bodies in SQLite. |
| D-021 | Require supporting Evidence for non-manual Facts; make confidence bounded but not equivalent to vulnerability confirmation. | Facts are traceable observations or inferences, not unsupported model assertions or confirmed findings. |
| D-022 | Mask SENSITIVE/SECRET references by default and separate bounded content retrieval from metadata lookup. | Context packets and routine logs should not expose protected values. |
| D-023 | Leave the final production block-volume path, encryption, backup/restore, and artifact expiration policy unresolved. | Phase 0 did not establish ownership/retention requirements; Phase 3 provides only safe local defaults and policy metadata. |

## Phase 4

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-024 | Use frozen, typed, vendor-neutral logical domain models with generated namespaced BugHunter IDs; keep recon row IDs as provenance only. | Facts and later components need stable references without inheriting production recon schema or ID semantics. |
| D-025 | Keep generic entity relationships in Phase 3 Facts; treat ObjectReference tenant/owner/creator fields as non-authoritative hints. | Ownership and permission conclusions must remain evidence-backed and revisable. |
| D-026 | Default model serialization is redacted; complete private serialization requires an explicit opt-in. Store raw request/response content through Evidence later. | URLs, external IDs, and correlation labels may contain secrets and should not leak through ordinary logs or context packets. |
| D-027 | Keep Phase 4 models unpersisted; add only pure Phase 2 recon DTO mapping with caller-supplied BugHunter IDs and creation times. | The roadmap asks for the logical model, and the blueprint warns against premature duplicate host/endpoint/JS tables. |
| D-028 | Represent traffic with generic RequestRecord/ResponseRecord and a source enum; Burp is a possible provider, not a core type. | Future capture/interception can be inserted without changing reasoning or domain records. |

## Phase 5

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-029 | Put program-authoritative scope in versioned local Target Packages; recon inventory is never an authorization source. | Phase 0 found recon domain membership insufficient for active testing, and Phase 2 recon is technical observation only. |
| D-030 | Evaluate exact/wildcard host, origin, and optional path rules deterministically with exclusions first; ambiguous path/URL input is not affirmative scope. Wildcards cover descendants but not the apex. | This avoids hostname-suffix confusion, normalization ambiguity, and accidental widening from broad recon wildcards. |
| D-031 | Model program rules, autonomy, and rate limits as pure typed policy data; active execution, throttling, approvals, and the final ScopeGuard remain deferred. | Phase 5 defines a safe contract without introducing traffic or workers. |
| D-032 | Use strict, bounded PyYAML local package loading and reject obvious credential fields/values; account entries are alias/reference metadata only. | Human-edited packages need readable structure but must not become plaintext credential storage. This is the first non-stdlib core dependency after Phase 1. |
| D-033 | Preserve source kind, configured timestamp, and private reference/operator in package memory while omitting private text and full markdown from default serialization. | Program provenance is needed for audit, but routine CLI/context output should remain compact and non-sensitive. |

## Phase 6

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-034 | Model Identity separately from Phase 4 Principal, with target-scoped aliases and append-only Principal links. | An owned test account can exist before its application user ID is known; conflicting later observations must not silently replace configuration. |
| D-035 | Model tenant-scoped memberships with zero or more Phase 4 Role IDs; configured and observed/inferred records remain separate. | Multi-tenant accounts and role differences are first-class, while observed claims retain evidence and Fact links. |
| D-036 | Extend the BugHunter-owned SQLite file to schema version 2 with a deterministic forward migration; store only opaque secret references, never credentials or session material. | Phase 6 needs durable local metadata without a second database or production recon writes. |
| D-037 | Require existing target-matched Evidence and a non-manual Fact for observed/inferred relationship records; leave configured metadata as configuration, not confidence-1.0 observation. | This preserves the Phase 3 evidence boundary and avoids silent promotion of account hints into facts. |
| D-038 | Import Phase 5 account aliases transactionally, creating provisional configured Tenant/Role records only from declared hints and rejecting conflicting re-imports. | The package remains the source of target context; the registry must not discover or authenticate accounts in Phase 6. |

## Phase 7

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-039 | Resolve Phase 6 opaque `secret_ref` through an explicit local binding and typed `SecretProvider`; Phase 7 ships only allowlisted environment and metadata-only manual providers. Do not implement a file provider without an approved root and safe-open policy. | Keeps credentials out of registry/config values and prevents arbitrary VPS file reads while allowing later backends behind one protocol. |
| D-040 | Return raw material only as `SecretValue` at a trusted execution boundary; LLMs, agents, ordinary domain serialization, CLI, SQLite, Evidence, and logs receive IDs/status/metadata only. | Authentication material is a capability, not general research context. |
| D-041 | Persist one stable local AuthContext per target/Identity in SQLite schema version 3, with status events and opaque references but no credential values. `READY` means available material, never verified session; Phase 7 cannot assert `VALID`. | Prepares Phase 8 session management without pretending login, target validation, or traffic execution already exists. |

## Phase 8

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-042 | Partially reuse the VPS browser technology, not recon's shared browser service or broker state. BugHunter owns a dedicated display/VNC endpoint, per-session Chromium profile, and session metadata. | Recon's active browser on `:99`/`:6080`/CDP `:9222` and login broker own credential-bearing profiles/storage-state and recon run IDs; direct reuse would cross isolation boundaries. |
| D-043 | Keep `BrowserDriver` and `SessionVerifier` as small vendor-neutral protocols. Ship an optional Playwright persistent-context driver and a current-page exact identity verifier; no agent, browser navigation, or traffic store yet. | One driver can support isolated manual login without coupling higher layers to Playwright or Burp. A target-specific trusted self/profile rule is necessary for verified identity. |
| D-044 | Store only non-secret BrowserSession metadata/events in BugHunter SQLite schema version 4. Put each profile under a generated target/identity/session path, require a BugHunter ownership marker, and preserve authenticated profiles unless explicitly purged. | Session continuity needs durable references, but cookies/browser storage are sensitive capabilities and never belong in SQLite or CLI output. |
| D-045 | Treat manual completion and imported cookies as `VERIFYING_IDENTITY`, never `VALID`. Atomically mark BrowserSession and AuthContext valid only after an exact expected user/tenant match; missing or wrong proof fails closed. | The recon broker's generic completion marker is not reliable account proof, and cookies/browser launch do not establish who is logged in. |
| D-046 | Keep browser proxy configuration generic and CA trust explicit. Do not attach to recon CDP, install Burp CA globally, or introduce Burp-specific core models. | A later interception proxy can be inserted behind a browser provider without changing session identity or traffic provenance. |

## Phase 9

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-047 | Persist vendor-neutral logical HTTP observations in BugHunter SQLite schema version 5, with immutable request/response rows and a mutable completion state for each exchange. | Phase 9 needs traceable complete and incomplete captures without touching recon PostgreSQL or coupling to Burp. |
| D-048 | Keep retained request/response observations in SECRET Phase 3 Evidence/Artifact storage; omit captured authentication headers and credential-like query values, and withhold bodies with recognizable credential material. Preserve original body size/hash separately. | Non-auth structure remains available under explicit access, while replay must resolve current credentials through AuthContext. |
| D-049 | Trust an Identity for browser traffic only from a currently verified Phase 8 SessionContext. Preserve declared identity separately; treat tenant/role metadata as declared hints and principal as observed only when evidence-backed. | A wrong, stale, or unverified browser session must never become another account's traffic baseline. |
| D-050 | Index only safe structural metadata, hash correlation labels, page all traffic queries by target and keyset, and cap statistics to a recent sample. | Future high traffic volume and sensitive URLs rule out unbounded scans and value indexing. |
| D-051 | Defer Burp capture to Phase 10 behind `TrafficCaptureProvider`; no browser service, replay, active executor, or validator is introduced in Phase 9. | Burp is a source/proxy backend, not the canonical traffic or reasoning model. |

## Phase 10

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-052 | Use one exact loopback Burp listener per active BrowserSession and one isolated Burp project per target; do not insert a target-visible correlation header. | Montoya supplies exact listener identity and a request/response message ID. Listener mapping is deterministic without modifying requests or trusting cookies. |
| D-053 | Keep a capture-only Montoya extension and authenticated loopback bridge outside production recon; map observations into Phase 9 `TrafficStore` with a small local idempotency index. | Burp remains one vendor-neutral traffic source, not a second traffic database or reasoning engine. |
| D-054 | Start capture-required browsers only after bridge heartbeat and listener reachability; trust the public Burp CA only in the isolated research profile's NSS store. | Failed capture must not silently become direct browsing or trigger global CA trust changes. |
| D-055 | Default to dropping non-in-scope/unknown Burp observations; optional metadata-only retention discards third-party path, query, headers, and bodies. | Captured traffic is not authorization, and third-party content should not enter future agent context by default. |
| D-056 | Keep Burp startup, browser ownership, and bridge lifecycle in one future long-running BugHunter service; Phase 10 exposes local provider/bridge/status APIs but starts no daemon. | Phase 8 browser driver availability is process-local; a short-lived CLI bridge would reject or misattribute sessions. |
| D-057 | Treat Montoya as a bounded push capture provider into the existing TrafficStore, rather than forcing its callbacks through Phase 9's polling `read_batch` protocol. | Preserves request-only events, response completion, idempotent bridge retries, and the vendor-neutral core without adding an unnecessary worker or second traffic database. |
