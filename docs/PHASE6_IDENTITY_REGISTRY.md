# Phase 6: Identity Registry

The Identity Registry stores **authorized account metadata**, not authentication
state. It is BugHunter-owned local SQLite data under the configured state root.
It never connects to production recon PostgreSQL or sends target requests.
Target Packages remain authoritative for program context and scope.

## Model

An `Identity` is a researcher-controlled account alias, such as `org1_admin`,
with a stable `IDENTITY-<uuid>` ID. Its alias is unique **within one Target**;
the same alias may be used by another program. Its account source is one of
`RESEARCHER_PROVIDED`, `PROGRAM_PROVIDED`, `PROGRAM_APPROVED_CREATED`,
`IMPORTED_SESSION`, or `UNKNOWN`. These are provenance labels, not actions.
Registry status is `ACTIVE`, `DISABLED`, `PENDING`, `REAUTH_REQUIRED`, or
`UNKNOWN`. `ACTIVE` means eligible in registry metadata, **not** logged in;
session validity belongs to a later phase. Non-secret purpose/tags can be
updated, and enabling/disabling changes only the registry status. The account
source is immutable after registration so its provenance is not silently
rewritten.

A Phase 4 `Principal` is the application's logical user; it is distinct from
the configured Identity. The Principal may be unknown initially. A configured
or evidence-backed link can be added later. Principal links are append-only;
if a later observation conflicts with a configured link, both remain visible
and the Identity's existing selected principal is not silently replaced.
Future operators must resolve the conflict before using that identity for
authorization comparisons.

`TenantMembership` has a stable `MEMBERSHIP-<uuid>` ID, target, identity,
Phase 4 `Tenant`, zero or more Phase 4 `Role` references, status, optional
primary flag, provenance, and evidence/Fact references. One Identity may have
multiple tenants and different roles in each. A roleless membership is valid.
There is no global admin assumption or built-in role hierarchy. Configured
memberships can be updated deliberately; the registry API never edits
observed/inferred membership records, which remain separate from configuration.

## Configured versus observed

Configured account declarations are operator/program claims, not confirmed
application facts. They have `CONFIGURED` observation state and are not
automatically converted into confidence-1.0 Facts. An `OBSERVED` or `INFERRED`
membership or principal link requires existing target-matched Phase 3 Evidence
and a non-manual, evidence-backed Fact. The caller chooses the Fact confidence;
the registry does not inflate it. Membership Facts use `member_of`, with the
Identity or known Principal as subject and Tenant as object. Principal-link
Facts use `resolves_to`, with Identity as subject and Principal as object.
Contradictions are preserved as separate records for review.

Comparison helpers consider **configured, active** identity/membership
metadata only. They can list identities for a target, tenant, or role; find
different-role pairs in one tenant; and find pairs with disjoint tenant
memberships. Disabled identities are excluded from pair helpers. These are
bounded metadata suggestions, never vulnerability findings or permission
proofs. Observed evidence should be assessed separately, not silently merged
into configured comparisons. A bounded same-user lookup uses the selected
Principal mapping; unresolved conflicting links are not automatically treated
as interchangeable users.

## Target Package bridge

`import_package_accounts(package)` imports Phase 5 `accounts.yaml` aliases,
tenant hints, role hints, and opaque secret references in one transaction.
It is idempotent for unchanged declarations and rejects conflicting existing
roles or references rather than overwriting them. Missing tenant hints produce
an Identity with no membership. A role hint without a tenant is invalid.
Unknown tenant labels create provisional **configured** Phase 4 Tenants of
kind `unknown`; this does not claim an observed application tenant. A role
hint creates or reuses a configured Phase 4 Role. Imports do not authenticate,
create target accounts, or discover tenants over the network.

## Persistence and privacy

Migration `002_identity_registry.sql` upgrades the existing BugHunter SQLite
file to schema version 2 without rewriting Phase 3 Evidence/Facts. Registry
tables store target/package links, Phase 4 Principal/Tenant/Role metadata,
Identity metadata, principal-link history, memberships, and role references.
There are no columns for passwords, cookies, Authorization headers, tokens,
MFA material, browser storage, or session state. `secret_ref` is only an opaque
identifier (`ref:alias` or `program/alias`), not a value or provider lookup.
The later Phase 7 SecretProvider resolves this alias outside the registry;
this Phase 6 schema still stores no credential value.

All registry reads are target-scoped and bounded by the configured local page
limit. Default serialization omits the secret-reference value, free-form
purpose/tags, private source details, and external application user IDs.
Source provider/entity and Evidence IDs are kept for provenance; detailed
source material belongs in Phase 3 Evidence, not free-form registry fields.
Obvious credential-bearing metadata fields and known secret patterns are
rejected at the registry boundary, not merely redacted after persistence.
Heuristic detection does not make arbitrary unlabelled text safe: never place
real credentials in aliases, labels, source metadata, or notes.

Initialize local state explicitly with `IdentityRegistry.initialize()` or the
explicit CLI import command; CLI list/show do not initialize or mutate it:

```bash
hackbot identity import example
hackbot identity list example
hackbot identity show example org1_admin
```

The fictional package in `tests/examples/targets/example/` contains two
tenants and three aliases, but no credentials. Phase 7 adds SecretProvider
and AuthContext metadata for `identity_id -> secret_ref`; this registry does
not resolve values or authenticate. Browser/VNC/Burp/traffic integration and
active authorization experiments remain deferred.
