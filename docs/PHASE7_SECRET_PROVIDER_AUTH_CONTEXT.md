# Phase 7: SecretProvider and AuthContext

This phase defines local authentication **configuration and metadata**, not an
authenticated session. It makes no target, browser, Burp, recon DB, or model
calls. The Phase 6 Identity Registry remains the owner of stable identity IDs
and opaque `secret_ref` values; it never stores a resolved credential.
The original blueprint roadmap labels this foundation Phase 6. This document
uses the operator's current sequencing: completed Phase 6 Identity Registry,
Phase 7 SecretProvider/AuthContext, then Phase 8 Browser/Session Manager.

## Threat model and boundary

An agent, model prompt, routine log, report, database query, or status command
must not receive raw passwords, cookies, bearer/API tokens, MFA values, or
Authorization headers. Only a future trusted execution boundary may call
`SecretProvider.get(ref)` and explicitly reveal the returned `SecretValue`.
`AuthContextManager.prepare` calls only provider metadata/availability and
cannot authenticate or claim `VALID`. No global secret cache is used.

Python in-process objects cannot enforce isolation against arbitrary code with
memory inspection privileges. `SecretValue` protects normal repr, str, JSON,
dataclass dumping, copying, and pickle paths, but it is not an HSM or secure
memory primitive. Keep trusted executors separate from LLM-facing code and
discard resolved values promptly after use.

## Reference and provider contract

`Identity.secret_ref` remains a Phase 6 opaque alias such as
`ref:fixture_admin` or `program/alias`. A typed TOML binding maps it to a
provider-specific reference, never to a literal value:

```toml
[secrets]
allowed_env_prefixes = ["HACKBOT_SECRET_"]

[secrets.references."ref:fixture_admin"]
provider_ref = "env:HACKBOT_SECRET_FIXTURE_ADMIN"
kind = "COOKIE"
```

`SecretProvider` defines `get`, `exists`, and `metadata`; no list-all-values
operation exists. `EnvironmentSecretProvider` looks up only an explicitly
named, allowlisted environment variable and returns a `SecretValue` only from
`get`. Missing values and provider errors have value-free messages. Changing
the value behind that variable does not change Identity or AuthContext IDs.
`ManualLoginSecretProvider` is a metadata marker and never yields a value.
`RoutedSecretProvider` resolves the configured alias. A reference from target
content is never implicitly promoted into this routing table. Neither recon
`auth_profiles` nor `hunt_credentials` is read.

There is deliberately no file provider in Phase 7. Supporting protected files
would require a separately approved root, no-follow traversal-safe opens,
ownership and permission enforcement, and a non-dump file format. `file:`
references are rejected rather than interpreted as arbitrary VPS paths.
Future Docker/keyring/vault/cloud providers can implement the same protocol.

`SecretKind` supports PASSWORD, COOKIE, BEARER_TOKEN, API_TOKEN,
LOGIN_DESCRIPTOR, HEADER_SET, SESSION_IMPORT_REFERENCE, and UNKNOWN. It is
classification metadata, not permission to reveal a value. The protected
credential descriptors cover username/password, cookie, bearer, header,
login-file reference, manual login, and imported-session reference shapes. Secret-bearing descriptor
fields require `SecretValue`; their default representation and `to_dict()`
never include raw material. Imported-session and manual-login descriptors
contain no captured session state.

## AuthContext state

`AuthContext` has stable `AUTHCTX-...` ID per target/identity, mechanism,
status, preparation outcome, timestamps, optional expiry, opaque secret ref,
provider label, future browser/CSRF reference slots, and optional Evidence ID.
Normal `to_dict()` shows only booleans for private references. Mechanisms are
USERNAME_PASSWORD, COOKIE, BEARER, HEADER, LOGIN_FILE, MANUAL_LOGIN,
IMPORTED_SESSION, and UNKNOWN. `LOGIN_FILE` is metadata-only until a future
approved provider exists.

Statuses:

| Status | Meaning in Phase 7 |
| --- | --- |
| UNINITIALIZED | No context has been prepared. |
| READY | Configured auth material is available; **not** a verified target session. |
| VALID | Reserved for a later phase with live, identity-checked session proof; Phase 7 cannot set it. |
| EXPIRED | A caller marked the context expired; no live check is implied. |
| REAUTH_REQUIRED | Missing material, manual login, or pending imported session needs human/later-phase work. |
| INVALID | Provider or mechanism mismatch; no authentication attempt occurred. |
| LOCKED | Identity is disabled or context was administratively locked. |
| UNKNOWN | No reliable state claim. |

Preparation outcomes refine status: READY, MANUAL_LOGIN_REQUIRED,
IMPORTED_SESSION_REFERENCE_AVAILABLE, MISSING_SECRET, DISABLED,
UNSUPPORTED_PROVIDER, and UNKNOWN. An available imported-session reference
means protected material is present; no session was imported or verified.
Configured `IdentityStatus.ACTIVE` means eligible metadata, not logged in.
Disabled identities prepare as LOCKED; pending/unknown identities do not
prepare READY. `prepare` never resolves a value. The manager can mark EXPIRED,
REAUTH_REQUIRED, INVALID, LOCKED, or UNKNOWN, but cannot assert VALID or READY
via a manual status update.

## Persistence and audit

Migration `003_auth_contexts.sql` advances the local BugHunter SQLite schema
from version 2 to 3. It stores AuthContext metadata and a small status-event
history. It does not add password, cookie, Authorization, API-key, MFA,
access/refresh-token, or browser-storage value columns. It stores only opaque
references, not provider-specific environment names or resolved credentials.
No raw authentication material enters Phase 3 Evidence/Facts or artifacts.
An Evidence ID may reference **non-secret** provenance only. The status-event
table records PREPARED/STATUS_CHANGED, old/new status, and time, without
messages or values.

CLI inspection is local and redacted:

```bash
hackbot secret check ref:fixture_admin
hackbot auth status example org1_admin
```

`secret check` reports provider, kind, and available/unavailable only.
`auth status` reads an existing local context; neither command reveals secrets or
contacts target/recon services. Existing `health`/`status` remain local-only.

## Phase 8 handoff

A future BrowserSessionManager can ask `prepare(target_id, identity_id)` for
READY, MANUAL_LOGIN_REQUIRED, IMPORTED_SESSION_REFERENCE_AVAILABLE, or
MISSING_SECRET without obtaining credentials in ordinary metadata. For a
manual/VNC challenge it should leave the context REAUTH_REQUIRED, let the
researcher complete login, then verify the resulting identity and session
before setting VALID. An imported-session reference must likewise be imported
and verified later. Future traffic replay resolves the identity and AuthContext
under deterministic policy, then resolves material **inside** the executor;
agents never rewrite raw cookies or tokens themselves. No browser launch,
session capture, VNC UI, MFA/CAPTCHA handling, or traffic executor exists here.
