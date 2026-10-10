# Phase 4: Core Domain Models

Phase 4 defines logical, frozen Python records in `hackbot.domain`. They are
not copies of recon PostgreSQL tables, an active-testing scope engine, or a
traffic capture store. Creating a Target or Host never authorizes requests.

## Entities

| Model | Purpose |
| --- | --- |
| `Target` | BugHunter research context, name/root domain, lifecycle, optional external reference. |
| `Host` | Target-associated hostname, optional scheme/port, derived canonical origin. |
| `Endpoint` | Host-associated method and normalized path, independent of discovery source. |
| `Parameter` | Named path/query/body/header/cookie/GraphQL/RPC input, linked to an endpoint or operation; no example value. |
| `JavaScriptAsset` | JS URL and optional current hash, size/status, and future artifact reference; no downloader. |
| `Principal` | Logical actor label and optional application user ID; no credential/session state. |
| `Role` | Application role name/ID, with no built-in privilege hierarchy. |
| `Tenant` | Typed ownership boundary such as organization, workspace, account, or team. |
| `ObjectReference` | Opaque application object identifier, type, tentative tenant/owner/creator hints, disposable flag, lifecycle. |
| `Feature` | Lightweight named product capability. |
| `Operation` | HTTP, GraphQL, RPC, or UI action composed with endpoint, GraphQL operation, feature, or object-type references. |
| `GraphQLOperation` | Query/mutation/subscription/unknown operation, variable names, optional document artifact and JS source references. |
| `RequestRecord`, `ResponseRecord` | Vendor-neutral traffic metadata, request correlation, provider, optional evidence/artifact references; no raw body or headers. |
| `Technology` | Evidence-linked technology observation with bounded confidence; not an absolute assertion. |

All first-class records use generated `PREFIX-<uuid4 hex>` IDs (for example
`TARGET-`, `ENDPOINT-`, `OBJECT-`, `REQUEST-`). IDs are independent of recon
primary keys and stable after object creation. A caller may supply a previously
assigned BugHunter ID when reconstructing a record. Entity IDs fit Phase 3
Fact subjects/objects; generic relationships such as `principal has_role role`
belong in Facts, not new hardcoded graph columns. `ObjectReference` tenant and
principal fields are explicitly **hints**, not canonical ownership claims.
Observed/inferred ownership hints require evidence references.

`ObservationState` distinguishes CONFIGURED, OBSERVED, and INFERRED records.
Lifecycle values describe record currency, not permission or target scope.
Observed entities can carry Phase 3 `EV-` references (up to 16) and a
`SourceRef` with provider, source record ID, timestamp, and qualification.
Provider identifiers are validated uppercase labels and can expand without a
database schema change. No evidence body is copied into a domain record.

## Normalization and privacy

Hostnames are lowercased, IDNA-normalized, and validated as DNS names or IP
addresses; bracketed IPv6 is supported. Schemes normalize to HTTP(S) or
WS(S). A Host's origin omits default ports. Methods become uppercase.
Endpoint paths get a leading `/` but retain case and repeated slashes; query
and fragment components are excluded rather than treated as route identity.
Object/tenant kinds are lowercase underscore labels. Opaque application IDs
are validated for bounds/control characters but **not** normalized. GraphQL
operation types are case-normalized to a small enum; variable names are
validated without storing values. Response content types retain only the MIME
type, never boundary/other parameters.

All records have deterministic `to_dict()` and `to_json()` output. Default
serialization masks private fields such as external IDs, raw URLs, endpoint
paths, free-form labels, correlation IDs, and source row IDs, and applies the
Phase 1 secret redactor. `to_reference()` gives a smaller ID/evidence pointer
for context packets. `to_dict(include_private=True)` is an **explicit trusted
storage/API operation**, not safe for logs or model prompts; it can contain
opaque IDs and URL query values. Request/response `repr` and default JSON
never expose raw URL query values. The `origin_reference` property returns
only a request origin. A private full URL may be held in the model, while
request/response bodies and headers belong in controlled Evidence.

There are no password, cookie, token, Authorization header, MFA-secret,
browser-profile, or AuthContext fields in Principal/Role/Tenant or traffic
models. Identity registry, secret provider, and browser sessions remain later
phases. Burp is only one `TrafficSource` value alongside BROWSER, HACKBOT,
IMPORT, and FIXTURE; no Burp-specific request/response class exists.

## Recon mapping and persistence

`hackbot.domain_recon` provides pure mappings for Phase 2 recon Target, Host,
Endpoint, and JS DTOs. The caller supplies a stable BugHunter ID, explicit
creation time, and optional Evidence IDs. Mapping carries recon table/row
provenance and observation time but makes no DB calls, performs no ingestion,
and never converts recon `active` or HTTP status into active-test authority.
Endpoint query values are omitted from the logical path; JS URLs are retained
privately because later asset acquisition may need the exact query. A recon
observation has `Lifecycle.UNKNOWN` until later validation establishes
currency. Phase 2 timestamps may be naive; the original observation timestamp
is preserved rather than silently assigning a timezone. BugHunter creation
timestamps must be timezone-aware.

No Phase 4 entity repository or SQLite migration is added. The roadmap only
requires a core logical model and the data-model blueprint warns against
duplicating recon host/endpoint/JS tables. Phase 3 SQLite continues to own
only Evidence and Facts. Persistence, cross-record referential checks,
traffic storage, target-package authority, and active testing are deferred.
