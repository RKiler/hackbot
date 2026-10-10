# Phase 3: Evidence and Fact Store

This store is BugHunter-owned local state. It neither imports production recon
modules nor connects to recon PostgreSQL. Recon remains the authority for
discovery records; a future, explicit converter may attach Phase 2 provenance
to selected evidence. Presence in recon never authorizes target testing.

## Evidence

`Evidence` is an immutable observation with a generated `EV-<uuid4 hex>` ID,
type, target reference, source, observation/creation times, SHA-256 content
hash, size, provenance, sensitivity, redaction status, and bounded metadata.
The type vocabulary covers recon records, HTTP traffic, JavaScript, source
maps, browser/DOM proofs, screenshots, GraphQL, authorization observations,
research references, manual notes, and experiment results. These are types,
not implemented producers. `EvidenceProvenance.from_recon` maps Phase 2 source
table, row ID, timestamp, and qualification without copying a recon payload.

Evidence rows and content are append-only. A correction creates another
evidence row with `replaces_evidence_id`; the old row remains available.
`to_reference()` gives a compact pointer and never includes content or
metadata. For SENSITIVE/SECRET records it also masks target, source, and
provenance. Content retrieval is a separate, size-bounded operation and
requires `allow_sensitive=True` for SENSITIVE/SECRET. Do not put raw evidence
objects or artifact bytes in logs or model context; use references.

Small PUBLIC/INTERNAL bodies (default at most 2 KiB) may be inline SQLite
bytes. Larger bodies and *all* SENSITIVE/SECRET bodies are stored once by
SHA-256 under `<artifact_root>/sha256/<first-two-hex>/<full-hash>`. Digest
identifiers, not caller paths, select artifacts. Writes use restrictive modes,
an atomic link into place, and hash verification on reads. Two evidence IDs
can reference the same bytes without duplicating the artifact. An artifact
may remain unreferenced after a failed database insertion; garbage collection
is deliberately deferred.

Sensitivity is PUBLIC, INTERNAL, SENSITIVE, or SECRET. A producer must choose
the correct class; SECRET classification is required if metadata has a
credential-like key. Redaction status is ORIGINAL, REDACTED, or WITHHELD and
is fixed at creation. To redact or correct content, create a new record and
link it; do not rewrite history. Phase 1 JSON logging redaction remains the
output boundary. Avoid storing credential values in free-form metadata even
when classified SECRET.

Retention is append-only policy history with `retain`, `expires_at`, `pinned`,
and `finding_related`; a pinned record must be retained. `set_retention`
appends a new policy event. Phase 3 never deletes or expires artifacts. A
future retention service must define legal/report holds and shared-artifact
reference checks before deleting anything. Finding evidence may be pinned
once later finding workflows exist.

## Facts

`Fact` is an immutable subject/predicate/object assertion with a generated
`FA-<uuid4 hex>` ID, bounded numeric confidence [0, 1], source/producer,
timestamps, optional target, sensitivity, and up to 16 supporting evidence
IDs. Every non-MANUAL fact requires existing evidence. Fact sensitivity is
raised to the highest linked evidence class. Predicates are generic lowercase
identifiers; the schema is not limited to authorization.

Confidence is an observation/inference weight, **not** vulnerability
confirmation: 1.0 can mean a deterministic observation, about 0.8 a strong
inference, and lower values a tentative evidence-supported relationship.
The caller chooses confidence and remains responsible for its justification.

Status history is append-only. ACTIVE is initial; DISPUTED, SUPERSEDED, and
RETRACTED are explicit later events with producer, reason, optional supporting
evidence, and optional related fact. Supersession requires a replacement fact.
Contradictory role or tenant observations therefore coexist with their
timestamps and evidence instead of overwriting each other. No automatic
contradiction detector is part of Phase 3.

`get_fact`, `list_facts_for_subject`, `find_facts(subject, predicate)`, and
`find_relationships(object_ref)` return bounded, indexed results. Evidence
lists are likewise bounded and target-filterable. Keyset cursors are bound to
their query scope. The store defaults to a 50-item maximum page, configurable
between 1 and 100; no API dumps entire artifacts or all target facts.

## Persistence and configuration

The local SQLite file is `<paths.root>/state/bughunter.sqlite3`. Schema
version 2 (including the later Identity Registry migration) is packaged with
BugHunter and created only by an explicit
`EvidenceFactStore.initialize()` call. SQL triggers reject updates/deletes of
evidence, facts, links, and history events. Reads do not initialize the store.
The Phase 1 `version`, `health`, and `status` commands do not open it.

Optional TOML settings:

```toml
[store]
artifact_root = "/path/to/local/bughunter-artifacts"
max_inline_bytes = 2048
max_page_size = 50
```

Without configuration, artifacts use `<paths.root>/artifacts/evidence`. This
is a safe development default, **not** a production block-volume placement.
The final production artifact root, backup/restore strategy, encryption,
retention periods, and multi-process ownership remain unresolved. Do not move
the store into production or run concurrent writers without deciding those.
