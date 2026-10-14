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

## Phase 11

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-058 | Host HackBot UI and an authenticated, CSRF-protected JSON facade in the existing recon Flask dashboard; run BugHunter separately behind a private Unix socket. | Existing dashboard login, navigation, and whole-domain Caddy proxy can be reused without exposing a second public API or merging persistence. |
| D-059 | Run BugHunter's Flask service with exactly one Gunicorn worker/thread and reconcile browser sessions on startup. | Phase 8 browser handles are process-local; multiple workers or stale persisted states could falsely claim session ownership or validity. |
| D-060 | Keep the dedicated BugHunter VNC display loopback-only and separate from recon's browser; require a server-side exact identity rule before manual login can become verified. | Manual completion and shared recon profiles are not identity proof, and VNC is a privileged browser surface. |
| D-061 | Keep dashboard traffic browsing metadata-only, target-scoped, bounded, and cursor-paginated; defer raw evidence viewing and optional recon summaries. | Captured bodies and authentication values are protected artifacts, while production recon inventory is large and not an authorization source. |
| D-062 | Store only allowlisted safe service activity metadata in a local SQLite table; do not put BugHunter events or findings into production recon PostgreSQL. | Gives the control plane a small audit trail without conflating findings or creating a second event platform. |

## Phase 12

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-063 | Store bounded, on-demand TargetProfile snapshots and evidence-linked hypotheses in BugHunter SQLite schema version 8; keep recon read-only and Target Package scope authoritative. | Passive reasoning must be reproducible without copying the recon corpus or treating inventory as authorization. |
| D-064 | Use deterministic rules and stable target/concept/surface/boundary keys; prohibit `CONFIRMED` in the hypothesis type and database constraint. | A passive indicator is a research lead, not a validated vulnerability. |
| D-065 | Materialize compact source-pointer Evidence for profile signals, maintain append-only hypothesis status/priority history, and pass only bounded metadata in context packets. | The research layer needs provenance and repeatability without raw JS, credentials, or unbounded model context. |
| D-066 | Keep profiling explicit and use the existing authenticated dashboard/CSRF/Unix-socket boundary; defer scheduling, model calls, skills, and target traffic. | Phase 12 is passive-only; later phases own execution and validation. |

## Phase 13

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-067 | Reuse Phase 5 ProgramScope, AutonomyPolicy, RiskLevel, and RatePolicy as the only authority inputs for a deterministic Phase 13 PolicyEngine. | Recon presence and model/client risk claims cannot confer testing authorization. |
| D-068 | Persist secret-free proposed-action fingerprints, immutable decisions/events, and exact-action 30-minute approval requests in BugHunter SQLite schema version 9. | Approval and audit must be target-scoped, explainable, and non-replayable for unrelated work without copying request bodies or credentials. |
| D-069 | Treat policy evaluation and dashboard checks as simulations; do not issue permits or consume rate tokens until a trusted Phase 14 executor exists. | A visible ALLOW decision is not itself an executable capability or proof of network enforcement. |
| D-070 | Require trusted owned-object proof and verified target-matched session state for autonomous mutations and authenticated actions; anonymous actions carry no identity. | Client flags, registry metadata, and an unverified browser cannot establish ownership or authentication. |
| D-071 | Make every future network executor re-evaluate redirects and current policy, atomically claim one-time approvals, and reserve target-scoped rate/budget capacity before traffic. | The destination, policy, identity, and rate state may change after a simulation; failure must close the active path. |

## Phase 14

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-072 | Keep one service-owned, vendor-neutral `TrafficExecutor` behind persisted, 30-second, one-use permits bound to the exact action and request fingerprint. | An in-memory ALLOW simulation or copied permit object must not authorize a send; policy and scope are rechecked against the current target package. |
| D-073 | Use `requests` with explicit no-redirect, no-environment-auth/proxy, TLS verification, finite timeouts, and bounded incremental gzip/deflate response capture. | One familiar transport suffices for controlled HTTP while protecting memory/artifact bounds and preventing implicit redirect or credential behavior. |
| D-074 | Default direct HTTP execution off; require an available explicit proxy route when capture is required, with Burp only as an optional adapter. | Proxy outage cannot silently bypass interception, and core traffic/evidence remains vendor-neutral. |
| D-075 | Allow prepared cookie, bearer, or header AuthContexts into the existing human browser verification path, but apply secrets only in the executor after a current verified session. | Phase 8 manual/imported-only creation otherwise made verified direct HTTP credentials unreachable; no login automation or browser-secret extraction is introduced. |
| D-076 | Treat each GET/HEAD redirect as a new action requiring scope/policy/rate/permit checks; deny automatic state-changing and cross-origin authenticated redirects. | A first-hop permit must not confer authority on another destination or leak auth material across origins. |

## Phase 15

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-077 | Keep skills as bounded Markdown/YAML planning data with metadata-only discovery, strict validation, and full-body loading only on selection. | Preserves token efficiency and prevents imported or personal methodology text from becoming executable code. |
| D-078 | Persist immutable, deduplicated plans with skill version and full-content SHA-256 in BugHunter SQLite schema version 11; explicit regeneration creates a new generation. | A later skill revision must not silently rewrite the evidence and controls behind an existing plan. |
| D-079 | Permit only Phase 13 simulation from the skill planner; a plan is never an approval, permit, TrafficExecutor invocation, or finding. | Scope, verified identity, current policy, and execution budgets must remain separate enforceable boundaries. |
| D-080 | Reuse the private service and authenticated, CSRF-protected dashboard gateway for catalog, routing, and plan views. | Adds researcher control without exposing a public skill-upload surface or a second API security model. |

## Phase 16

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-081 | Persist selected runs, ordered runtime steps, immutable results, and append-only audit/manual links in BugHunter SQLite schema 12; keep one open run per plan and one globally claimed step. | Explicit, durable state avoids competing dispatches without introducing a queue or external broker. |
| D-082 | Reconstruct only exact typed action/template bindings from the immutable plan snapshot, and recheck current prerequisites, scope, identity, policy, and one-use permit at execution. | A Phase 15 simulation or revised skill is not authority for a live request; old authenticated plans lacking a session binding fail closed. |
| D-083 | Atomically reserve a plan request slot for every recorded exchange before wire dispatch, including redirects; bound each executor call to the remaining budget and check pause/cancel before each hop. | Conservative pre-wire overcount is preferable to an unaccounted send; Phase 14 rate accounting remains in force. |
| D-084 | Correlate dispatches with TrafficStore before sending and reconcile stale runs into human review without automatic replay; preserve the original result when manual evidence is linked. | A crash or lost response makes state-changing outcomes ambiguous, and silent retry could duplicate a mutation. |
| D-085 | Keep orchestration service-owned and dashboard actions explicit, authenticated, CSRF-protected, target-scoped, and metadata-only; never infer a confirmed finding from a completed run. | The operator can inspect and control one plan without exposing arbitrary HTTP execution or protected artifact bodies. |

## Phase 17

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-086 | Judge only completed runs with frozen skill validator contracts and an independently audited policy/permit/Traffic/Evidence chain; keep validators read-only and model-free. | A completed plan, HTTP status, or skill assertion cannot prove a vulnerability or authorize fresh traffic. |
| D-087 | Require valid owner and negative controls, Evidence-backed identity/object relationships, semantic protected-content comparison, and two safe reproductions for automatic read confirmations. | Fail-closed confirmation avoids promoting public objects, failed controls, GraphQL error-only HTTP 200s, and response-size coincidences into findings. |
| D-088 | Store immutable, versioned validation decisions and root-cause-deduplicated findings in BugHunter SQLite schema 13, separate from recon findings; expose only target-scoped metadata through the authenticated dashboard. | Historical decisions remain auditable without duplicating production recon data or exposing protected response bodies. |
| D-089 | Defer state-changing, DOM XSS, postMessage, and external-reachability confirmations until independently attested durable readback or browser/capability proof exists. | Phase 16 has no trustworthy proof record for these effects; a Fact, static sink, or local model is insufficient. |

## Phase 18

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-090 | Persist disposable-object metadata, lifecycle events, operation journal, leases, and explicit plan requirements in BugHunter SQLite schema 14; retain application IDs only in SECRET Evidence. | The object ledger must be resumable and auditable without exposing identifiers or writing production recon PostgreSQL. |
| D-091 | Accept only local, schema-validated, target-bound data recipes for known operations; require a verified creator session, fresh Phase 13 policy decision, and one-use Phase 14 permit per request. | Recon routes and model output are not authority to create target objects, and the factory must not have an unrestricted transport. |
| D-092 | Require owner read-back matching generated name, object ID, creator, and tenant before reuse; treat ambiguous create/delete, interrupted operations, and expired leases as manual-review states without replay. | A successful status or configured disposable intent cannot establish ownership or final state. |
| D-093 | Use separate bounded setup and cleanup allowances, transactional exclusive leases, and the existing `CHECKING_PREREQUISITES` run state for explicit object requirements. | Cleanup must remain possible after experiment budget exhaustion while concurrent plans must not share mutable fixtures or proliferate run states. |
| D-094 | Keep object management in the existing authenticated, CSRF-protected dashboard facade; never expose a raw object-ID deletion API, and defer autonomous recipe discovery/browser-only creation to later phases. | Manual cleanup is limited to verified registered objects and current policy, with operator-marked external cleanup separately audited. |

## Phase 19

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-095 | Keep authorization profiling, candidates, and sparse matrix observations in BugHunter SQLite schema 15; production recon remains a bounded read-only hint source. | Discovery is not authority, and the specialist must not duplicate or rewrite production recon data. |
| D-096 | Require observed owner traffic, verified disposable ownership Facts, current session identity, exact request binding, and Phase 13/14/16 enforcement for active authorization comparisons. | A static route, guessed ID, or stale cookie cannot support a safe or defensible boundary test. |
| D-097 | Dispatch exact REST object-path reads, single-ID GraphQL queries, and one explicitly typed disposable GraphQL rename mutation through Phase 15 plans; treat GraphQL POST as approval-required and all other mutations as manual. | A verified owner before/after read-back now attests this narrow durable effect; HTTP method and mutation response text alone remain insufficient, preserving D-089 for unproven actions. |
| D-098 | Rank bounded candidate pairs before applying the hunt cap, stop autonomous execution after one confirmed root-cause proof, and reconcile interrupted runs into review without replay. | Avoid noisy matrix expansion, duplicate target traffic, and uncertain post-crash state changes. |
| D-099 | Expose target-scoped authorization metadata and controls only through the existing authenticated dashboard gateway, with no raw request or Evidence-body endpoint. | Reuses the private service and browser/CSRF boundary without creating a second public API. |
| D-100 | Attribute only newly created specialist control objects to their hunt and attempt policy-gated automatic cleanup after terminal/cancelled runs; preserve pending and failed outcomes. | A reusable operator fixture must never be deleted because a hunt happened to use it, while objects the specialist creates need accountable cleanup. |
| D-101 | Surface nested parent-child mismatches only as manual-review candidates when an observed owner request and response prove both IDs and their relationship; defer active nested-ID substitution. | A local parent pointer or route shape alone does not establish application semantics, and Phase 19 has no exact, policy-gated parent-child binder. |

## Phase 20

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-102 | Execute only recipe-pinned `RENAME(name)` for verified, reserved disposable objects; model other mutation types but do not dispatch them. | A narrow field allowlist and exact reversal/read-back contract are safer than a general JSON write surface. |
| D-103 | Require separate owner read-back after each write and after restore; persist secret-free hashes and traffic/evidence references. Never retry an ambiguous write. | Mutation response status does not prove durable effect, while replay after a lost response could duplicate a side effect. |
| D-104 | Bind nested and mixed-batch tests only to exact observed read-only operations and known, Fact-backed ObjectRegistry IDs; keep the executable batch to two IDs. | This expands Phase 19's manual-only nested lead without enabling ID guessing or mass batch mutation. |
| D-105 | Inject only recipe-declared CSRF headers via a trusted executor-side resolver; do not put token values into plans, skill context, results, or dashboard metadata. | Captured tokens can be stale, and token resolution is a trusted execution capability, not reasoning input. |
| D-106 | Expose Phase 20 metadata through the private BugHunter API and render only redacted summaries in the existing authenticated recon dashboard gateway; keep gateway routes and service configuration unchanged. | The Phase 20 dashboard requirement is an explicit integration task, while the security controls and persistence remain BugHunter-owned. |

## Phase 21

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-107 | Keep DOM XSS artifact, analysis, candidate, and trial state in BugHunter SQLite schema 17; obtain current JS and directly referenced maps only through the controlled executor and preserve content-addressed protected Evidence. | Recon stores metadata, not authoritative raw bodies; hash drift must invalidate stale traces without duplicating the recon corpus. |
| D-108 | Use bounded Babel AST function-local tracing and source maps as candidate evidence; require an observed in-scope page route and frozen Phase 12/15/16 bindings before active proof. | Static source/sink strings, source maps, and inferred routes do not demonstrate reachability or authorization. |
| D-109 | Permit only fixed harmless, transform-driven browser variants under Phase 13 scope/policy, a six-navigation plan cap, fresh contexts, and exact loaded-bundle hash checks; prohibit arbitrary browser evaluation. | Real browser interpretation is required, but payload spraying, stale bundles, unscoped redirects, and automation-created markers are not acceptable proof. |
| D-110 | Let Phase 17 alone confirm DOM XSS after controls, policy audit, target-origin marker execution, and fresh reproduction; pin supporting Evidence and expose only target-scoped metadata through the private control plane. | The confirmed Finding must have a durable candidate-to-validation audit chain, while the existing gateway remains responsible for browser authentication and CSRF. |

## Phase 22

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-111 | Reuse Phase 21's content-addressed JS/source-map artifacts and shared Babel parser; retain candidate-to-artifact links for each analyzer version. | Recon does not retain authoritative historical JS bodies, and a parser revision must not silently inherit an old candidate link or erase analysis provenance. |
| D-112 | Freeze exact messaging types, window mode, and an allowlisted RPC method classified as READ by the current AST in a Phase 15 plan; recheck that classification before dispatch. | A method name that looks read-only can still write state, and a dashboard or model-supplied payload must not become arbitrary browser execution or RPC access. |
| D-113 | Let a locally fulfilled, fixture-owned same-origin sibling confirm only a local missing-source fixture; require independent attacker-control evidence for non-fixture same-origin senders. | The synthetic sibling proves the trust-check failure in a controlled fixture, but cannot by itself establish that an external attacker controls content on the real trusted origin. |
| D-114 | Keep messaging capability validation in Phase 17 and route connected message-to-DOM HTML flows to Phase 21 candidates without making a second XSS confirmation engine. | Cross-origin data/capability impact does not require XSS, while static message sinks are not browser execution proof. |
| D-115 | Expose only bounded, target-scoped messaging metadata through the existing authenticated dashboard gateway; keep trial payloads and protected browser Evidence out of generic API output. | BugHunter state remains separate from recon, and no unrestricted send-message surface is introduced. |
| D-116 | Classify Worker, SharedWorker, BroadcastChannel, and unresolved `self` receivers as static-only messaging architectures until a transport-specific experiment exists. | A window-origin fixture cannot establish sender control or origin semantics for worker/channel messaging; reusing it would create false proof. |
| D-117 | Freeze one analyzer-linked `event.data.<field>` property for message-to-DOM trials, excluding dispatch and prototype-sensitive keys, and delegate target-document marker verification to the Phase 21 validator. | A static HTML sink is not XSS; the cross-origin messaging root cause needs a real browser execution control without arbitrary payload or a second DOM confirmation engine. |
| D-118 | Permit explicit retry of a failed messaging AST analysis for the same artifact and analyzer version while caching completed outcomes. | A transient parser timeout or resource failure must not silently suppress current candidates indefinitely. |
| D-119 | Persist only allowlisted messaging event names and bounded relative timestamps alongside trial counters; use one shared trace validator in execution and deterministic finding review. | Handshake and port-transfer evidence must be auditable without retaining message payloads, cookies, or secret-bearing RPC results. |
| D-120 | Attribute message-to-DOM execution origin using a bounded marker reply's browser-provided `MessageEvent.origin`, not the loaded frame URL. | Sandboxed documents can execute at an opaque origin despite a first-party URL; URL-derived origin would overstate a DOM XSS finding. |
| D-121 | Reserve and release shared Phase 14 capacity for every permitted messaging browser request; reject browser redirects until each actual hop can be independently policy-gated. | The browser route hook does not reliably intercept redirected hops, and a Phase 13 preflight alone does not account for network use or prevent an ungated redirect destination. |
| D-122 | Permit the fixed synthetic private marker to confirm only a locally sourced `FIXTURE` asset; controlled-HTTP assets require independently bound owned-data or other protected-effect evidence. | A response matching a hard-coded local marker demonstrates fixture behavior, not real-target confidentiality impact. |
| D-123 | Recover only statically resolvable indirect message listeners and constant handler-map RPC keys, and provide bounded AST-derived protocol metadata to the skill context. | This improves protocol coverage without executing JS, importing whole bundles into context, or treating dynamic dispatch as proven capability. |
| D-124 | Derive local-only lookalike sender origins from the current candidate's weak origin-check kind, then validate the exact derived origin; skip suffix probes for IP-literal hosts and probes that fall inside the Target Package scope. | One fixed subdomain origin cannot exercise suffix checks, while an invalid or authorized origin cannot establish a foreign-origin bypass. Unsupported probes remain manual review rather than negative coverage. |
| D-125 | Bind a Phase 18 verified disposable canary to an authenticated messaging plan by object ID, name hash, and verification time; reserve it for the run and pass its value only ephemerally to the local browser fixture. | A controlled-HTTP messaging disclosure needs independently owned protected data, while plans, logs, and trial Evidence must not persist the canary or treat a fixed synthetic marker as real-target impact. |
| D-126 | For a non-fixture owned-canary disclosure, require a private-object Fact and a matching BugHunter anonymous GET exchange denying the exact verified object before confirming confidentiality impact. | A denial Fact without observed traffic, or a denial for another object, is insufficient; matching an owned name across origins alone does not prove protected-data exposure. |
| D-127 | Exercise state-changing messaging only in a loopback fixture with a Phase 18 verified disposable object and a Phase 20 `TypedMutation`, then independently read back and restore it; keep production messaging RPC dispatch read-only. | A writable MessagePort alone is not a safe mutation contract, and browser-only writes do not yet have Phase 20 policy, TrafficExchange, read-back, or restore attribution. |

## Phase 23

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-128 | Keep exposure candidates and source links in BugHunter-owned SQLite; read recon only through bounded target-scoped adapters and do not repurpose recon findings. | Recon observations are leads, not authorization or confirmed BugHunter impact. |
| D-129 | Store credential fingerprints, classes, and redacted locations in ordinary candidate metadata; keep raw sensitive values only in protected Evidence. | Deduplication and triage must not leak secrets into APIs, plans, logs, or dashboard text. |
| D-130 | Confirm protected-resource and field exposure only against an owned disposable object, verified identity controls, trusted privacy/role Facts, and Phase 17 response comparison. | A 200, matching JSON key, public email, or anonymous page alone cannot establish an authorization violation. |
| D-131 | Permit sourced internal Host comparison only when a Target Package explicitly allows it, against one authorized external destination with normal and invalid controls and no redirect or TLS bypass. | An internal hostname string is not active-test authority; VHOST title differences are not protected impact. |
| D-132 | Reuse Phase 13/14/16/17 for every active exposure check and expose only opaque-ID operations through the authenticated CSRF-protected gateway. | Candidate analysis must not become an unrestricted fetcher, credential-login facility, or second validation engine. |
| D-133 | Deduplicate repeated credential fingerprints across current artifacts, but clear the candidate's active plan/validation link when its representative body hash changes. | Historical findings remain auditable while a new bundle cannot inherit a stale confirmed state. |
| D-134 | Reuse an unchanged target-scoped recon pointer Evidence row on repeated exposure discovery. | Recon data stays owned by recon, while repeated dashboard reviews do not multiply identical BugHunter metadata. |
| D-135 | Preserve the Phase 14 fingerprint format for ordinary requests; include Host override only when it is actually set. | Existing saved plans and permits should not change identity merely because the optional VHOST field was added. |

## Roadmap reconciliation after Phase 23

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-136 | Treat Phases 0-23 as complete and `docs/blueprint/02_ROADMAP.md` as the authoritative remaining sequence: 24 Cold-start bootstrap, 25 Target/normal-behaviour learning, 26 GraphQL/API specialist expansion, 27 ResearchCoordinator, 28 Cross-specialist planner, 29 Notifications/reports, 30 Production hardening, 31 Campaign coordination, 32 Continuous delta hunting, 33 Evaluation/benchmarking. | The original blueprint phase labels no longer match delivered Phases 5-23 or the dependencies of the remaining work. |
| D-137 | Supersede the original Phase 16 ResearchCoordinator, Phase 17 static-analysis layer, Phase 20 broad GraphQL authorization, Phase 24 planner, Phase 25 notifications, Phase 26 combined delta/campaign, and Phase 27 evaluation labels; supersede the Phase 23 recommendation to build the planner as Phase 24. | Phase 16 is the completed single-plan orchestrator, Phase 17 the validator, and Phase 20 typed mutations; cold start and target learning must precede the Phase 28 planner, while hardening and campaign controls precede continuous delta hunting. |

## Phase 24

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-138 | Treat an absent or unavailable recon target as cold-start discovery for an existing tracked Target Package; never derive scope or a new Target Package from recon. | Recon is an optional read-only accelerator, and Phase 5 scope must remain authoritative for every Phase 13/14 network action. |
| D-139 | Persist one active bounded bootstrap run per target in BugHunter SQLite, keep source-linked compact observations, and finalize interrupted runs as partial without automatic replay. | Request and browser side effects cannot be reconstructed safely after a crash; provenance and budgets must survive service restarts. |
| D-140 | Use the Phase 21 content-addressed JS cache and explicit refresh for cold-start assets; preserve old hashes and source observations when current JS or recon later changes. | Recon does not retain raw historical JS, and silently replacing a body or reusing a stale candidate would invalidate evidence. |
| D-141 | Observe only an already-open verified primary browser page in Phase 24; consume existing captured traffic, but do not synthesize browser requests or add unrestricted navigation/clicks. | Browser-side execution needs a policy-gated request path before it can safely expand; Phase 24 is bounded discovery, not behaviour learning or active testing. |
| D-142 | Serve bootstrap controls through the existing authenticated, CSRF-protected dashboard gateway, with target-scoped APIs and no arbitrary URL input. | The private service must not become a public active-request surface; operator-selected identity is limited to a currently verified session. |
| D-143 | Add an optional, fail-closed redirect destination guard to Phase 14 and use it only for cold-start bootstrap. | Phase 13 scope checks alone cannot distinguish an in-scope safe page from an in-scope logout or credential-bearing redirect; all other executor callers retain their existing behavior. |

## Phase 25

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-144 | Persist bounded BehaviourProfile, workflow, operation, matrix, expectation, and run records in BugHunter SQLite, referencing TrafficExchange and Evidence rather than copying raw traffic. | The recon and traffic stores retain their separate ownership; later specialists need durable, inspectable context without another raw request archive. |
| D-145 | Use only verified-at-capture identity attribution for trusted behavior; keep anonymous separate and never treat `NOT_OBSERVED` as denial or observed behavior as product policy. | Session confusion, UI omissions, and HTTP 200 GraphQL errors otherwise create false authorization claims. |
| D-146 | Create ownership/parent Facts only for read-back-verified disposable ObjectFactory records with matching evidence-backed creator and tenant Facts. | Path IDs and successful reads identify possible objects but cannot establish ownership or parent scope. |
| D-147 | Keep Phase 25 passive and existing-data-first; an expired account waits for the existing VNC/Burp workflow, and refresh consumes newly captured normal traffic rather than navigating or clicking automatically. | Safe browser action planning, capture policy, and state-changing setup are separate capabilities; no live target request is necessary to accept the learning model. |
| D-148 | Feed learned role-operation gaps and authenticated export controls into Phase 19/23 as bounded ranking/context only, while preserving their existing prerequisites and Phase 17 confirmation gates. | A learned normal pattern is useful prioritization, not a security finding or permission source of truth. |

## Phase 26 (complete)

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-149 | Keep API operations as target-scoped, versioned metadata referencing TrafficExchange and Evidence; require scoped capture or current scoped recon evidence before imported JS contributes operations. | Saved JS can be stale or third-party, and recon has no raw historical JS body; neither source grants active-testing authority. |
| D-150 | Execute API-specific reads only from exact observed, single-root operations and verified disposable owner/actor objects through the existing Phase 13/14/16/17 path. Reuse Phase 19/20 plans for exactly matched REST nested/batch, typed mutation, and BFLA candidates; keep unsupported GraphQL shapes and mass-assignment paths as leads until exact binders and validators exist. | A multi-root response can misattribute a protected field to a different object, while a second transport or validator would bypass established policy and evidence gates. |
| D-151 | Treat selected fields, field names, `NOT_OBSERVED` role gaps, GraphQL status 200, and parser errors as candidate signals, not authorization proof; require trusted privacy Facts and actual field data under the owned object branch for field confirmation. | Query selection, null/error behavior, and unrelated response branches can otherwise produce false findings. |
| D-152 | Link an API candidate to the exact matching Phase 19/20 authorization candidate and run its full start, advance, validation, read-back, and cleanup lifecycle; allow autonomous API work only for one policy-permitted five-request read plan per call and stop at approval gates. | Reusing the existing plan and validator avoids a second mutation executor, while an explicit one-plan cap and human approvals prevent unbounded or risky automation. |
| D-153 | Normalize redacted API route placeholders only when they match verified disposable object IDs; keep all unknown hashed path segments distinct, and retain original scoped TrafficExchange IDs for dispatch. | TrafficStore pseudonymizes object IDs, so owner/actor controls otherwise split into unrelated operations; normalizing unknown segments could merge unrelated routes or leak raw identifiers. |
| D-154 | Persist the exact completed or partial Phase 25 BehaviourProfile run ID on API candidates when learning informed ranking, and expose target-bound keyset cursors for operation/candidate inventory. | A later validation needs traceable learning provenance; bounded first-page-only lists would hide older operations on large targets. |
| D-155 | Recognize canonical GraphQL `Type:ID` base64 values only through an exact observed `node(id:)` variable and a verified disposable object's ID; store the type label and reject conflicting labels. | Decoding is useful binding metadata, not proof of access. Dispatch and Phase 17 must still establish current owner/boundary controls and actual protected data. |
| D-156 | Bind a GraphQL nested read to one observed single-root parent operation, one verified disposable child, a trusted parent Fact, and an exact selected child path; reuse the five-request API plan and validate actual child scalar data under that parent. | A parent response can be public or accessible while a nested child is private. Requiring the child relationship and data prevents an ignored parent parameter or unrelated branch from becoming a false authorization finding. |
| D-157 | Permit only an observed single-root `nodes(ids:)` GraphQL read or a two-operation HTTP array of the same `node(id:)` document, with exactly two known IDs per saved owner/actor control, four reserved verified disposable objects, and a five-request API plan. Freeze the observed envelope; extend the ObjectRegistry requirement cap from three to four only for this batch plan; validate both mixed-result objects by scalar data, not aggregate status. | Batch support needs two owner objects and two actor objects to establish per-item baselines. A narrowly scoped fourth reservation preserves Phase 18's default cap and prevents unbounded aliases or list amplification. |
| D-158 | Admit only a reviewed parent/child GraphQL rename recipe with exact `parentId`, `id`, and `name` variables, a verified child-to-owner-parent relationship, and a reserved disposable foreign parent. Reuse Phase 20's seven-stage mutation/read-back/restore plan and independently check parent IDs in the executed writes before Phase 17 confirmation. | Nested mutation testing must prove an unauthorized durable child effect, not a status or an ignored parent field; the existing typed mutation path retains policy, permit, rollback, and evidence gates. |
| D-159 | Treat manual API context as a target-bound Evidence-linked `UNKNOWN` operation and keep JS-only GraphQL operations endpoint-unbound until the exact request is captured. | A researcher note or coincidentally matching operation name must not become an executable request template or attach an unrelated service endpoint. |
| D-160 | Extract bounded literal `/api/` fetch/axios routes through the existing Babel pass, but store them as relative, non-executable hints until scoped runtime traffic supplies the host and complete request shape. | A bundle may run on a different origin from its CDN URL; static route strings alone cannot justify an active API call. |
| D-161 | Page API candidates by target and optional operation with a filter-bound cursor; report operation progress through aggregate database counts rather than first-page samples. | Large target inventories must not hide an operation's hypotheses or imply coverage from a truncated list. |
| D-162 | Permit a bounded analysis call to select one current target-bound operation ID outside the default newest-100 pass, without adding a free-form request or bypassing candidate/request caps. | High-value older operations must remain reachable for a focused researcher workflow without turning Phase 26 into an unbounded campaign planner. |
| D-163 | Retire JS-only API operations and unresolved candidates when no current saved JS artifact retains their exact source body hash; keep separately observed traffic operations current. Regenerate a stale candidate only if the exact operation reappears and it has no plan/run/validation history. | A changed bundle can remove an operation without creating a new version; version-key staleness alone cannot prevent stale template use, while immutable execution history must not be revived as current work. |
| D-164 | Keep distinct traffic-observed GraphQL document hashes current under one endpoint/name; retire a template only with affirmative stale-source evidence, not because a different role selected different fields. Retain the 16 newest exchange references; only a newer exact capture may reopen a retired traffic template, never an older replay whose reference aged out. | Role-specific query selections can coexist. Blindly treating every hash difference as a deployment supersession prevents the field-authorization differential and discards valid captured controls. |
| D-165 | Permit one observed flat GraphQL field-selection differential: the lower-role own-object control may use a separate current subset document, while the owner, invalid, and foreign slots use the exact owner document. Require identical operation/root/ID-variable AST contracts and independent Phase 17 rechecking. | UI selection differences are only leads; this bounded comparison tests whether a protected owner-selected field is returned to the lower role without inventing fields or bypassing the existing five-request policy and audit chain. |
| D-166 | Prefer an evidence-backed private disposable object as the owner-side API control when an observed operation has controls from multiple tenants; keep Phase 17's independent tenant/privacy verification unchanged. | Capture recency is not a security boundary. Selecting the newest exchange alone can reverse the intended owner/actor direction and hide a valid candidate or leave a test without the relevant privacy facts. |
| D-167 | Let a Phase 26 object-read candidate link an already confirmed Phase 19 result only for the exact current operation, owner capture, object, and foreign identity, with current verified sessions/private Facts, an unreserved disposable object awaiting cleanup or still ready, and a validation newer than the operation observation. Resolve the pinned capture directly when it has aged out of Phase 19's bounded recent profile; never use this path to claim a new finding or reuse a denial. | Replaying five requests for an unchanged, already validated boundary wastes budget, while broad historical-result reuse would mistake stale traffic or completed cleanup for current controls. |
| D-168 | Admit only an observed REST POST rename action at the verified disposable object's exact `/rename` child route, with a reviewed single-field body and the existing seven-stage Phase 20 read-back/restore plan. Keep DELETE and other action routes non-executable until separate safe contracts and validators exist. | A reversible action can reuse the existing typed mutation proof without a second executor. DELETE has no rename-style restoration and needs a distinct absence/cleanup invariant. |
| D-169 | Bind the future disposable DELETE authorization test to the exact Phase 18 ObjectFactory cleanup operation and verified GET route, but keep its recipe metadata non-executable until a two-object plan, independent absence checks, and lifecycle reconciliation are implemented. | Reusing the approved cleanup endpoint avoids inventing a destructive request; treating deletion as rename would misrecord already-absent objects and could retry DELETE during cleanup. |
| D-170 | Use an eight-stage, two-object DELETE contract with an owner target-present preflight, independent Phase 17 absence validation, and per-object cleanup reconciliation; skip the redundant cleanup DELETE after a verified foreign deletion, leaving seven dispatched requests, but use all eight when the foreign attempt is denied. Initially leave automatic API-candidate selection disabled until an observed DELETE can be bound to a current disposable target without inheriting a stale control object's identity; D-171 defines that later binding. | The seven-stage rename contract lacks a target baseline and has no reversal for irreversible deletion. Local loopback controls must prove both the deletion boundary and final disposition without speculative live target writes. |
| D-171 | Select a REST DELETE API mutation candidate only from a completed owner-authenticated exchange that exactly matches the cleanup URL of a verified CLEANED source fixture and a pinned reviewed DELETE recipe; bind it to two distinct current READY fixtures with the same owner, tenant, parent, type, recipe, and trusted private-access expectation, and recheck all evidence at preparation. Never use the cleaned source as the control or start this mutation in bounded-autonomous mode. | A successful historical DELETE normally has no returned object ID and cannot itself prove ownership of a different live object. The existing two-object typed plan supplies fresh owner control, target preflight, boundary attempt, independent absence reads, and cleanup. |
| D-172 | Page the existing Babel API extractor in 16-entry slices, persist a target-bound asset-local offset in the existing BugHunter JS progress cursor, and advance the asset cursor only after its page sequence completes. Cap literal hints at 1,024 per body and report truncation explicitly; keep the legacy first-page extractor API for existing callers. | A dense current bundle could exceed a per-pass budget or the old first-24 parser cap, causing later observed operations to be skipped permanently even though no network request was needed. |
| D-173 | Extend the observed GraphQL field-selection differential to one scalar inside a single embedded object, with the same one-ID/single-root AST contract, exactly one selected-field difference, and a root-ID-bound scalar response. Reject independently identified nested objects from this field proof path; route them to nested-object authorization. | A nested value must not be credited to the root object merely because it appears in the same response. Independent Phase 17 response checks and the existing five-request plan remain mandatory. |
| D-174 | Resolve older verified CLEANED DELETE sources by an exact, target-scoped cleanup-operation or verified typed-mutation exchange index before consulting the newest-50 fallback. Retain the full URL, recipe, owner, and live-disposable-object checks; leave older unlinked observations as leads. | A broad historical object scan is unnecessary when BugHunter has an auditable deletion exchange link, and a matching route alone cannot prove which old object was deleted. |

## Phase 27

| ID | Decision | Reason / evidence |
| --- | --- | --- |
| D-175 | Persist typed ResearchRequests, immutable versioned ResearchBriefs, source references, advisory skill proposals, and hypothesis links in BugHunter SQLite; expose research references as `DOCUMENTED`/`RESEARCHED`, never `OBSERVED`. | Research knowledge must remain source-backed and auditable without becoming target proof or mutating production recon. |
| D-176 | Trigger research only from current structured specialist/hypothesis gaps, local knowledge first, with optional bounded Brave public search using a Phase 7 secret reference. Reject private search terms, restrict source hosts and redirects, and never send bounty-target traffic. | A generic web console or automatic curiosity browsing would leak context, amplify cost, and bypass scope. |
| D-177 | Keep research deterministic and advisory: no model call is needed for compact pattern extraction, no TrafficExecutor/Finding path exists, and ephemeral skill proposals require Phase 15 validation plus researcher review. | Untrusted pages, reports, and code snippets cannot authorize execution or confirm a vulnerability. |
| D-178 | Reuse the private service and authenticated CSRF dashboard gateway for explicit research, stale refresh, cancellation, and compact citation views; keep request budgets and versioned cache in local state. | Research may be longer-running but needs no new queue, scheduler, broker, or public proxy surface in Phase 27. |
