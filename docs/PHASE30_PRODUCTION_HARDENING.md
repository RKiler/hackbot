# Phase 30: Production Hardening (in progress)

This phase hardens the standalone BugHunter service. It does not authorize target
requests, add campaigns, or make recon PostgreSQL writable. The authoritative
phase order is `docs/blueprint/02_ROADMAP.md`.

## Observed VPS and storage layout

The October 15, 2026 inventory found 2 CPUs, 7.8 GiB RAM, 4 GiB swap (full),
about 75 GiB free on the root disk, and about 58 GiB free on the 248 GiB block
volume. Production recon processes consume substantial RAM concurrently.
BugHunter's control-plane worker was small at inventory time; Burp has a
1.6 GiB systemd memory maximum and a 768 MiB Java heap. These are observations,
not capacity guarantees.

`/root/codex_artifacts` resolves to the mounted block volume. BugHunter owns:

| Class | Production location | Storage policy |
| --- | --- | --- |
| SQLite state | `/root/codex_artifacts/bughunter-agent/state/bughunter.sqlite3` | Critical durable; consistent backup |
| Evidence and JS artifacts | `/root/codex_artifacts/bughunter-agent/artifacts/evidence` | Critical when finding-linked; otherwise policy-dependent |
| Report drafts | `/root/codex_artifacts/bughunter-agent/artifacts/reports` | Critical durable when present |
| Browser profiles | `/root/codex_artifacts/bughunter-agent/browser-profiles` | Session-sensitive; excluded from ordinary backups |
| Burp runtime/config | `/root/codex_artifacts/bughunter-agent/burp-runtime` | Burp-owned operational data, not canonical evidence |
| Encrypted backups | `/root/codex_artifacts/bughunter-agent/backups` | Separate directory, same block device as active state |
| Maintenance logs | `/root/codex_artifacts/bughunter-agent/logs` | JSONL audit when created |
| Temporary data | `/root/codex_artifacts/bughunter-agent/tmp` and Burp runtime `tmp` | Ephemeral; not evidence |

Service logs use journald. The backup key reference is in the mode-0600 local
configuration; the actual key is in a separate mode-0600 systemd environment
file on the root disk. The key must be escrowed outside this VPS by the operator.
The same-volume backup is not protection against block-volume loss. The older
root-disk encrypted backup is retained as a temporary migration fallback.

On 2026-10-16 a read-only recheck found 2 CPUs, 7.8 GiB RAM with 1.9 GiB
available, and the 4 GiB swap essentially full. Root had 74 GiB free; the
block volume had 58 GiB free. BugHunter's state directory used 8.6 MiB,
artifacts 372 KiB, browser profiles 39 MiB, Burp runtime 672 MiB, and backup
directory 996 KiB. Journald occupied 2.2 GiB. The live BugHunter service was
active but still on SQLite schema 34; staged schema-43 code was not deployed.
The service and SQLite file are root-owned (state directory mode 0700,
database mode 0600); its control socket and runtime directory are mode 0700.
The configured backup and recon environment files are mode 0600. Burp
listeners on ports 38080-38083 and BugHunter noVNC on 6901 were loopback-bound
in the listener inventory. A separate `cloudflared` process listened on a
wildcard port 20241; its ownership and exposure require a separate review,
not a BugHunter listener claim. The service still runs as root; host-wide
journal limits and memory pressure were open hardening work at this inventory
point. The journal cap was applied later as described below, while memory
pressure remains open.

A later read-only 2026-10-16 listener and permission recheck found the
BugHunter control socket at `/run/bughunter-agent/control.sock` and its
runtime directory mode 0700/root-owned, with no TCP listener for the control
plane. BugHunter noVNC remained on `127.0.0.1:6901`; Burp listeners
38080-38083 remained on loopback. The wildcard `cloudflared` listener on
port 20241 was in a Docker systemd scope, not the BugHunter service. SQLite
and all three configured environment/configuration files were mode 0600;
state, Evidence, browser-profile, and backup directories were mode 0700.
The report-artifact directory did not yet exist and therefore has no live
permission claim. `systemctl show` displays staged `PrivateTmp`,
`ProtectSystem`, `ProtectHome`, and `NoNewPrivileges` settings, but the
running service began on 2026-10-14 before the Phase 30 unit rollout; this
read-only check does not prove the new sandbox is active in that process.
The read-only `hackbot storage check` reported `integrity_ok=true`,
`foreign_keys_ok=true`, rollback journal mode `DELETE`, and
`schema_actual=34` versus staged `schema_expected=43`. Its
`missing_core_tables=2` belongs to that version mismatch; no production
migration or service restart was attempted.

## Storage and retention classes

`CRITICAL_DURABLE` covers confirmed finding metadata, linked Evidence, and
report drafts. `DURABLE` covers other state needed for safe recovery, including
planner decisions, approvals, object cleanup state, and notification outbox.
`REGENERABLE` covers unlinked downloaded assets and research caches.
`EPHEMERAL` covers temporary processing files and anonymous browser state.
`SECRET_REFERENCE_ONLY` covers provider credentials and backup keys, which
belong in SecretProvider inputs rather than ordinary records.

Retention attributes are split by owner rather than forced into one generic
record: Evidence policy events hold `retain`, `expires_at`, `pinned`, and
`finding_related`; Evidence holds `content_size` and `sensitivity`; logical
payload retirement records the `retention_class`. Browser-session profile
retention uses `last_used_at` as its last-access signal and refuses cleanup
when a newer use appears. Evidence reads do not extend expiry, since doing so
would make a read mutate immutable-evidence policy or silently postpone an
operator-reviewed retirement decision.

The current artifact retention implementation collects aged, unreferenced physical
Evidence blobs and aged abandoned artifact `.tmp-` files. It checks every known direct artifact-digest column, holds a
cross-process artifact lock, caps inspected entries and deletions per pass, defaults to dry-run,
requires a dry-run review no older than 15 minutes before confirmed cleanup,
and writes a STARTED audit record before the first unlink plus a completion
record. A mode-0600 cursor under BugHunter state advances each bounded scan,
including empty truncated scans, so a large referenced filename prefix cannot
permanently hide later orphans. Cleanup rechecks only the reviewed scan window
and candidate set; the review is consumed after a successful run. Dry-run
advances this local cursor but does not delete content. It does
not proceed if live SQLite has an artifact-digest owner outside that declared
reference inventory; backup selection uses the same fail-closed check. This
schema guard covers conventional artifact/map hash column names, including
generated columns; nonconventional logical references still need an explicit
inventory review. Confirmed cleanup now performs its bounded
filesystem/reference scan before
acquiring SQLite's write transaction, then rechecks the reference guards and
each reviewed candidate under `BEGIN IMMEDIATE` before unlink. A reference
inserted after preflight therefore preserves the blob without holding the
database writer lock for the full scan. The full retention module passed 58
tests on 2026-10-17, including a simulated late-reference insertion; the
maintenance module passed 14 tests on the same source.
It does not remove immutable Evidence rows,
TrafficExchange records, JS/source-map records, or ResearchBrief versions. A
successful orphan plan is not full lifecycle-retention coverage.

Artifact writes fsync the temporary bytes, sync the parent of each newly
created artifact directory, and sync the digest directory after publishing the
final link before returning success. This
keeps a committed Evidence reference from relying only on an unflushed hard
link after a host crash. A directory sync failure is reported as a failed
write; any published but unreferenced blob remains subject to reviewed orphan
collection. Two focused durability tests passed on 2026-10-16.

Pending schema 41 adds append-only Evidence payload retirement. The separate
`retention evidence-plan` / `evidence-run --confirmed` CLI path scans a bounded
keyset window and selects only old, artifact-backed, non-secret Evidence whose
latest explicit policy is non-retained or expired. It excludes pinned,
finding-related, and directly or JSON-referenced Evidence; unknown reference
schemas and incomplete checks fail closed. Reviewed IDs expire after 15
minutes and are rechecked under a write transaction before an audited marker
is inserted. Evidence metadata remains, but `read_content` refuses the retired
payload. Physical bytes are removed only by a separate reviewed artifact-GC
pass once every other digest owner is gone; shared blobs remain available to
live owners. New Finding links and retained policy changes are rejected for
retired payloads. Schema 41 rejects new links through known direct Evidence-ID
columns, including the exposure-source column without a foreign key, and
through all 19 named Evidence-ID JSON fields on insert or update. The
reference inventory fails closed if a named JSON or direct-link guard is
missing, or if a new direct Evidence foreign key has not been reviewed. GC
also rechecks retired IDs for late direct or JSON links before unlinking.
This is a narrow standalone-Evidence path; Traffic and ResearchBrief caches have
separate reviewed paths below, while JS/source-map lifecycle retention is not
automatic. Large JSON reference scans can defer
retirement; an indexed reference graph is still needed for scale.

New DOM-owned and controlled-HTTP JS and source-map Evidence now receives `REGENERABLE` metadata
and configurable expiry (`[retention].js_artifact_hours` and
`source_map_hours`, both 2160 hours by default). The controlled capture uses the
same settings for its separate asset Evidence; its TrafficStore request/response
Evidence keeps the TrafficStore policy. Exposure captures and existing Evidence
are not rewritten. Direct DOM and possible shared
TrafficStore references still hold the payload. No JS/map retirement or
physical deletion is authorized by the expiry timestamp alone.
The local `hackbot retention dom-plan --kind JS|SOURCE_MAP` command now pages
through old DOM owners and reports only advisory candidates with an expired
`REGENERABLE` Evidence policy, exact owner link, no active target work, and no
other DOM or Evidence reference. Pins, candidate chains, malformed reference
data, and deadline-limited scans fail closed. A complete plan writes one
private, kind-bound review of exact owner/Evidence/digest/size tuples. Within
15 minutes, `hackbot retention dom-run --kind JS|SOURCE_MAP --confirmed`
rechecks those tuples and every hold in one SQLite write transaction and
appends Evidence retirement markers only for still-eligible rows. A failed or
incomplete scan does not authorize a run, and the review is consumed after a
successful run. This is logical Evidence retirement only: DOM owner rows and
digest columns remain. Schema 46 adds generated, source-inventoried late-link
guards for direct text and decoded JSON DOM-ID values and object keys. A guard follows the
owner's *current* Evidence marker, so a fresh exact same-hash refetch can bind
new Evidence without permanently banning that DOM ID. The separate reviewed
artifact collector now discounts an exact retired DOM owner's own Evidence and
digest links only after no other DOM/Evidence reference remains. Shared blobs
and all nonretired owners remain held. The version-4 `ALL` backup selector uses
the same reachability check; schema-45 snapshots retain their original DOM
digest selection. An incomplete scan or changed guard schema fails closed.
Active DOM reads now skip Evidence with an existing retirement marker. An
exact same-hash JS or source-map reacquisition can bind new Evidence to the
same DOM row after a protected-reference check; the old marker stays immutable
and a concurrent owner change fails. This rehydration path passed local DOM
store and controlled-HTTP executor fixtures. It does not itself create DOM
owner retirement markers. Local retirement fixtures also cover JS and
source-map markers, a fresh Evidence link or pin
between review and confirmation, confirmation/replay/kind/age gates, and
source-map rehydration. These tests do not authorize using this command on the
live schema-34 service before the controlled migration and rollout.
The reviewed collector fixtures prove physical reclamation and same-hash
rehydration for an unlinked retired JS or source-map blob, and preservation of
a digest still shared with an active source map. Separate backup fixtures show
new `ALL` snapshots omit only released DOM bytes while schema-45 snapshots
continue to include them. The full source-bound test matrix and controlled
deployment are still pending. These are local fixture results, not production
cleanup or proof that large-corpus retention finishes within budget.
The Evidence reference checker can now exclude one exactly verified DOM asset
or source-map ownership link while still honoring every other direct and JSON
reference. This permits the reviewed logical retirement operation; schema-46
guards and the separate GC reachability check govern later physical cleanup.
No existing production JS or map payload is retired by this source change.
An additional bounded scan checks the owning DOM ID against ordinary
SQLite text fields and decoded JSON values and keys, including escaped JSON strings.
It treats uncertain or incomplete scans as a hold. The scan is deliberately
conservative and may block on metadata-only mentions; it does not cover opaque
binary encodings. A reviewed write-time recheck, exact owner-generation
late-link guards, shared-digest GC, and safe DOM record rehydration are in
place in the staged schema-46 source. Large-table scan cost and the controlled
production rollout remain open.

New TrafficStore captures now receive class-specific expiry timestamps from
`[retention]`: 720 hours anonymous, 2160 hours authenticated/unverified, and
4320 hours for HackBot execution by default. An exact Target ID may override
those lifetimes through `[retention.traffic_target_hours]`. Explicit caller
retention, including pinned/finding-related proof, takes precedence. The
exchange and its request/response Evidence receive the same expiry; existing
rows are untouched. The staged `retention traffic-plan` / `traffic-run
--confirmed` CLI path requires schema 42, a recent review, a terminal and
expired exchange, expired policy on all of its Evidence, and no outside
Evidence or exchange/request/response reference. It marks every payload in
one write transaction and preserves immutable traffic metadata. An append-only
exchange marker and schema-derived late-link guards prevent retired exchange,
request, and response IDs from gaining new direct or JSON owners. The bounded
reference scan treats only a single complete, exactly matched Burp capture
index as deduplication metadata, while inconsistent indexes and specialist
links remain holds. Retired captures reject late bridge retries. Invalid
JSON, unknown Evidence schema, or a timed-out check fails closed. The plan
reports candidate bytes and a deduplicated **upper bound**, not guaranteed
reclaimed space. Physical deletion is a separate reviewed artifact-GC pass.
GC rechecks shared digest owners and late traffic references before unlinking.
New `ALL` backups use artifact-selection version 4 to omit truly unreferenced
retired blobs, while older manifests retain their original selection rules.
Version-4 selection pages over digest owners and applies the artifact cap to
reachable blobs, not retired candidates skipped during selection.
Operations reports `CLI_REVIEWED` and `SEPARATE_REVIEW`; there is no automatic
traffic cleanup. This staged path is not active on the live schema-34 service.
Schema 43 adds a trigger-maintained count index for exact exchange, request,
and response IDs in the existing JSON reference columns. Migration backfills
valid JSON transactionally; malformed existing JSON blocks the upgrade. New
invalid JSON writes are rejected, and reference checks fail closed if the
indexed source-column inventory or required triggers drift. Schema-42 backups
retain their original full-scan reference semantics. This removes the
per-candidate full JSON scan for TrafficStore IDs but does not index generic
Evidence references or prove count integrity after out-of-band database
tampering. Burp project/history file pruning remains separate from this
capture-index contract; no Burp project files are automatically deleted.

Pending schema 44 adds an independent trigger-maintained count index for exact
Evidence IDs in every existing JSON column. Its transactional backfill rejects
malformed JSON, and later writes maintain counts on insert, update, and delete.
Evidence retirement checks compare the indexed source-column inventory and
required triggers to the current schema before using a count; a new JSON
column or missing trigger fails closed. Schema-43 snapshots retain the older
full-scan check. This removes a full JSON scan per Evidence candidate but does
not prove count integrity after direct out-of-band edits to index tables.

Pending schema 45 adds a separate, operator-reviewed ResearchBrief cache
retirement path. `hackbot retention research-plan` scans a bounded keyset page
for briefs past both expiry and a configurable 30-day grace period. It excludes
briefs linked to hypotheses, skill proposals, planner candidates, context
events, tasks, or any nonterminal request reference. Planner references are indexed with
triggers and checked against the source JSON before retirement; missing guards
or an incomplete reference scan fail closed. `research-run --confirmed`
requires a dry-run no older than 15 minutes and rechecks the reviewed IDs,
payload sizes, and hashes inside a write transaction. It replaces only the
cached advisory JSON with
`{}` and appends an immutable retirement marker containing the old payload
hash and size. Brief IDs, version, request, topic, summary, and source metadata
remain readable; retired briefs cannot become cache hits or new planner input.
New links to retired briefs are rejected. This is logical SQLite page reuse,
not immediate filesystem reclamation. There is no scheduled ResearchBrief
cleanup and this path is not active on the live schema-34 service.

Schema 38 adds a durable finding hold: linking Evidence to a confirmed Finding
automatically appends a pinned, finding-related retention event. The migration
backfills older finding links, and SQLite rejects any later policy event that
would release the hold or give it an expiry. The store checks this before
accepting a policy change. This protects linked Evidence independently of the
specialist that created the Finding, but it does not by itself implement
expiration of other immutable Evidence or Traffic rows.

Pending schema 39 adds direct digest-lookup indexes for all seven declared
artifact-reference owners and lookup indexes for eleven previously unindexed
direct TrafficStore exchange references. This makes those reference checks
indexed lookups instead of full table scans as the stores grow. A
schema-38-to-39 fixture preserves existing Evidence and verifies indexed
digest query plans; a fresh-schema TrafficStore fixture verifies the direct
exchange-link query plans, derived from every direct reference column in the
installed schema. The 2026-10-16 TrafficStore and store modules passed 63 tests
after the additional indexes. Generic Evidence JSON-reference scans remain
unindexed and can still defer Evidence retirement on a large database. The collector now
keeps at most one configured scan window per hash
bucket in memory, but still enumerates the whole bucket to choose that window;
large buckets remain a scan-time scaling limit. A configurable
`retention.orphan_scan_timeout_seconds` (30 seconds by default) now aborts
an incomplete scan without publishing candidates or advancing its cursor.
Starting a new dry run first invalidates the previous review, so a timed-out
scan cannot leave stale deletion authority behind. This bounds maintenance
work and fails closed, but does not guarantee progress through a pathological
bucket; a durable inventory or different directory index is still needed.

Pending schema 40 extends the permanent finding hold to Evidence referenced
by linked validations, including contradictory and check-only references in
the primary, location, and duplicate validations. It backfills existing
links, pins new links and late checks through SQLite triggers, and rejects
later policy events that would release them. This preserves report proof
without treating every rejected or unrelated validation as critical durable.
The backfill parses only finding-linked validations: malformed unlinked history
does not block an upgrade, but malformed linked JSON or non-string references
roll the migration back without advancing the schema version.

A separate `PROFILE_PLAN`/`PROFILE_RUN` action handles only anonymous browser
profiles whose sessions have been terminal for at least the configured grace
period (48 hours by default). It requires a known BugHunter process inventory
with no BugHunter-owned browser process, no active target plan/planner run,
and no unresolved disposable object in that target. Named identity profiles
are never selected by this action. A separate, operator-selected
`DISABLED_PROFILE_PLAN`/`DISABLED_PROFILE_RUN` pair can clean terminal profiles
for one explicitly named disabled identity only after both the identity and
session have aged past `retention.disabled_identity_profile_grace_hours`
(seven days by default) and the session has no newer use or verification. The run requires
the exact target/identity and reviewed task ID, intersects with a fresh plan,
and fails closed if the identity is re-enabled or a browser/process is active.
Active identities, including expired sessions still needed by a researcher,
are retained by default. For one explicitly selected active-identity session,
`NAMED_PROFILE_PLAN`/`NAMED_PROFILE_RUN` allows a reviewed cleanup only when
the session is terminal, at least
`retention.active_identity_profile_grace_hours` old (30 days by default),
has no newer use or verification, and is not bound to a valid AuthContext.
The run binds the exact target, identity, session, and one-use review; it
rechecks eligibility and serializes deletion with browser launch in the
BugHunter service process. Named profiles are never cleaned automatically.
The plans show candidate counts and estimated bytes; cleanup requires explicit
confirmation and retains session metadata and an audit trail. The CLI reaches
both named-profile paths through the private service socket; it does not open
the profile store independently.
If a BugHunter agent-cgroup PID has an unreadable process name, the inventory
is `UNKNOWN` and all profile cleanup paths fail closed.

The Operations API binds each confirmed cleanup to the latest completed
dry-run task ID in the same service process. Reviews expire after 15 minutes
and cannot be replayed after restart, another maintenance task, or a prior
cleanup. The worker rechecks eligibility and deletes only the intersection
with that reviewed plan, so newly eligible artifacts or profiles require a
new review. The Operations view displays at most 20 redacted candidate
identifiers plus total count and estimated bytes; the complete in-memory
review remains the deletion boundary, not the display preview. The
short-lived artifact CLI requires explicit `--confirmed` and a recent local
dry-run review; it does not accept arbitrary paths or delete newly eligible
items outside that review. The Operations UI additionally binds the review to
the same service process and one-use task ID.

## Backup and restore

`BackupManager` uses SQLite's online backup API, checks `integrity_check` and
`foreign_key_check`, copies referenced content-addressed artifacts, records a
manifest with hashes/counts/schema/version, and verifies before reporting
success. Backup creation now holds shared Evidence and report artifact locks
from snapshot through copy so reviewed artifact cleanup cannot unlink a
selected blob mid-generation. A lock-contract fixture and a real local
backup-copy fixture passed on 2026-10-17; full backup and matrix reruns remain
pending. Standalone backup creation also checks the configured state mount
before making backup directories; two local mount-present/mount-missing
fixtures passed. Read-only backup inspection and staged recovery remain
available without that create guard. Production uses standard GnuPG AES-256 symmetric encryption with a
SecretProvider key reference. Plaintext backup creation rejects **any** `SECRET`
Evidence row, including an unselected artifact, because its metadata remains
inside the SQLite snapshot. Verification also rejects such plaintext
generations. Misclassified metadata still requires an operator
audit; production backups remain encrypted. Browser profiles and Burp runtime
are excluded. The `ALL` policy includes all known direct artifact references
except retired Evidence payloads in selection version 3; a digest still
selected by any live Evidence, Traffic, JS, plan, or exposure owner is included.
`FINDING_LINKED` is the
smaller, explicit alternative. Backup generations have a dry-run and an
explicit, verified-retained-generation pruning command.
Selection is capped at 50,000 distinct artifact files before copying, and
creation, verification, listing, and pruning use the same 32 MiB manifest
limit. Exceeding either cap fails the backup rather than silently omitting
artifacts or publishing a generation its verifier cannot read. Operators must
switch to `FINDING_LINKED`, reduce safely retired data, or review capacity if
an `ALL` generation exceeds the cap.
Pruning verifies every completed generation before selecting old ones.
Malformed or corrupt generations stop the prune and remain for operator
review; they cannot silently displace a good backup in the retention count.
This conservative preflight can take time when generations contain many
artifacts, so it is an explicit maintenance action rather than a health probe.

`hackbot backup verify` checks the full ciphertext and plaintext hashes and
records the last successful verification time. A status display says
`LAST_VERIFIED`, not that the bytes have been continuously rechecked.
New backups use artifact-selection version 4. `FINDING_LINKED` still includes
Evidence referenced by the Finding's primary validation, later locations,
and duplicate validations, including check-only and contradictory Evidence.
The selected hashes also participate in the unencrypted-secret rejection.
Manifests without a selection version remain verifiable under the original
version-1 selector; version-2 and version-3 manifests retain their original
selection rules. Version-4 `ALL` selects only reachable artifacts, including
live owners of a shared digest after standalone Evidence or Traffic retirement.
Verification of an older backup proves its original contents, not that it
contains every validation-only artifact or reflects later payload retirement.
Create and verify a new version-4 generation before relying on the current
selection policy for recovery.
On 2026-10-16, the complete backup module passed 45 tests in 83 seconds after
the artifact-selection and manifest-limit changes. The nine-group matrix still
requires a rerun after the final Phase 30 changes.
On 2026-10-17, the current backup module passed all 59 tests in 4:56 under
shared VPS load, including the shared artifact-lock and standalone required-mount
regressions. This is full `test_backup.py` coverage, not completion of the
nine-group source-bound matrix.
`hackbot backup stage` verifies and decrypts to a private temporary directory;
it never replaces active state. Staging contains plaintext sensitive data and
must be secured and removed after an isolated restore test. See
`docs/OPERATIONS_RUNBOOK.md` for the operator-controlled replacement sequence.
`hackbot backup rehearse <id>` performs the isolated staged schema upgrade,
integrity and foreign-key checks, and critical-row-count comparison, then
removes the decrypted stage even if a check fails. It does not restore or
restart production. Unit fixtures upgrade schema-34 and schema-35-through-39
copies to the then-current schema 42 without losing their Evidence rows; a separate schema-41
fixture checks traffic-row preservation and late-link guard installation.
`hackbot backup audit-json-indexes <id>` separately verifies the schema-44
trigger-maintained Evidence and Traffic JSON counts against independently
decoded source values on a verified staged copy. The scan has explicit row,
distinct-ID, per-value size, and elapsed-time limits; hitting any limit is
incomplete, not a passing sample. It reports mismatch counts without IDs and
removes the decrypted stage. Focused fixtures cover matching counts, Unicode
escapes, derived-count drift, missing triggers, limits, CLI success, and stage
cleanup. The production schema-34 backup cannot satisfy this schema-44 audit;
a current-schema generation is required after controlled deployment.
If a process is killed before `finally` runs, an operator can review and
remove the exact stale decrypted stage with `backup restore-staging-plan` and
`backup restore-staging-cleanup <name> --confirmed`. This is separate from
unfinished backup-generation cleanup and never touches recent stages or
completed generations automatically.
Backup creation is serialized with verification and pruning under the backup
inventory lock. An interrupted creation can leave a private `.pending-*`
directory containing plaintext; `backup incomplete-plan` previews only stale
unfinished directories, and `backup incomplete-cleanup --confirmed` removes
them after a safety and symlink check. Recent in-progress directories and
completed generations are excluded.
Before creating a SQLite snapshot, backup creation checks free space on the
backup filesystem against the database size and the configured block-storage
reserve (2 GiB by default). After the consistent snapshot selects artifacts,
it streams their file sizes and checks capacity again, including encrypted
plaintext/ciphertext overlap and the later verification copy. An encrypted
verification and any restore staging also preflight the manifest's expected
materialized bytes plus a small working allowance before copying or decrypting.
GnuPG decryption uses its documented
[`--max-output`](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html)
limit for each entry's expected plaintext size, then checks its hash and size;
failed crypto operations remove partial output files.
A newly created generation is verified inside its private `.pending-*` staging
directory and published only after that verification succeeds. Unsafe
symlinked artifact bucket directories and hard-linked entries fail closed.
The preflight cannot reserve space against other processes; if space changes
later, backup creation still aborts and removes its incomplete staging copy.
The complete backup module passed 42 tests in 2:17 after the space and bounded
decryption changes, including a corrupted plaintext-size fixture. This does
not substitute for the complete test matrix.
The 14-module `store-migrations` segment then passed 304 tests in 8:49 after
historical-schema fixtures were changed to request migration explicitly. The
complete nine-group matrix remains pending.
Backup creation now records `BACKUP_STARTED` before the capacity preflight and
`BACKUP_FAILED` with only the exception class when creation aborts. It never
places an exception message or source content in that audit record. If even
the failure audit cannot be written, the original backup error remains the
operator-visible failure; a focused fixture verifies this case.

On 2026-10-15, the existing encrypted schema-34 production backup
`20261015T085423Z-1fc53af4` verified when the CLI inherited the root-owned
backup-key environment. A plain interactive shell without that key reported
the generation as unverified, which is an access/configuration limitation, not
proof of corruption. Its private staged copy migrated to schema 38 with
`integrity_check=ok`, zero foreign-key errors, and all 80 Evidence records
present. The staged plaintext was removed afterward; the active service and
schema-34 database were not changed. That backup has no Finding or Report
rows. A separate encrypted `FINDING_LINKED` fixture now stages a Target,
Finding, Evidence, ReportDraft, and PlannerRun, and checks hashes for
check-only and contradictory Evidence attached through a duplicate validation.
This is an isolated rehearsal, not a production restore.

A separate SQLite online snapshot of the active schema-34 database was
migrated in a temporary block-backed directory to schema 39 on 2026-10-15.
The rehearsal retained all 80 Evidence rows, passed `integrity_check`, had
zero foreign-key errors, and contained all seven digest-lookup indexes. The
temporary snapshot was removed; the live database remained at schema 34.
This checks migration compatibility, not encrypted-backup restore or active
service rollout.
The same isolated rehearsal was repeated for schema 40: all 80 Evidence rows
remained, `integrity_check` returned `ok`, foreign-key errors were zero, and
the new validation-hold table was present. The temporary copy was removed.
The fresh encrypted `ALL` backup `20261015T182453Z-501dba84` was independently
verified and rehearsed with the new command on 2026-10-15: schema 34 upgraded
to 40, integrity and foreign-key checks passed, all 80 Evidence rows remained,
and `restore-staging` was empty afterward. The live schema-34 database and
service were not changed.
The same encrypted generation was then rehearsed against source schema 41:
`from_schema=34`, `to_schema=41`, `integrity=OK`, all 80 Evidence rows retained,
`active_state_replaced=false`, and `restore-staging` empty afterward. This
remains an isolated rehearsal, not approval for a live restart or migration.
On 2026-10-16 that encrypted generation was rehearsed again against source
schema 42. It reported `from_schema=34`, `to_schema=42`, `integrity=OK`,
80 Evidence rows preserved, and `active_state_replaced=false`. The private
restore-staging directory was empty afterward. A read-only startup check still
reported live schema 34 versus the then-current expected 42, and the service PID was unchanged.
This does not replace the complete test matrix or authorize the live rollout.
The same encrypted generation also rehearsed successfully to schema 43:
`from_schema=34`, `to_schema=43`, `integrity=OK`, 80 Evidence rows preserved,
and `active_state_replaced=false`. The restore-staging directory was empty
afterward. A read-only startup check still reported live schema 34 versus
expected schema 43; the active service remained on the same PID. This proves
the isolated migration path for this snapshot, not a production rollout.
The generation also rehearsed to schema 44: `from_schema=34`, `to_schema=44`,
`integrity=OK`, 80 Evidence rows preserved, and `active_state_replaced=false`.
The private restore-staging directory was empty afterward. The read-only
startup check reported live schema 34 versus expected schema 44, and the
active service retained the same PID. This is an isolated migration proof,
not approval for a live restart.
On 2026-10-16 a fresh encrypted `ALL` generation
`20261016T183411Z-97fe1967` was created from the still-live schema-34
database and verified separately: 48 files, 111,092 encrypted bytes, and a
valid manifest. Its isolated rehearsal reached schema 44 with
`integrity=OK`, `active_state_replaced=false`, all 80 Evidence rows
preserved, and a matching independent JSON-reference audit across 268
values. The restore-staging directory was empty afterward. A second
read-only live check still reported `schema_actual=34`, `schema_expected=44`,
`integrity_ok=true`, and `foreign_keys_ok=true`. This is a fresh rollback
generation and migration rehearsal, not a complete-matrix pass or live rollout.

## Runtime and observability

Resource admission checks disk and available memory before new heavy planner,
plan, browser, bootstrap, learning, and research work. The intended default
thresholds are 80/90/95 percent disk for warning/high/critical plus an absolute
free-space reserve. The live configuration caps BugHunter at one browser,
two concurrent plan runs, a 1 GiB available-memory reserve, and a 10 GiB
free-disk reserve. Agent systemd limits are CPUWeight 50, MemoryHigh 1800M,
MemoryMax 2500M, and TasksMax 384; dedicated VNC is capped at 512M and 96
tasks. These are staged for the next controlled restart after unit verification.
The pending build also reports one-minute system load divided by the CPUs
available to the process. Optional paired `resources.high_load_per_cpu` and
`resources.critical_load_per_cpu` thresholds are recommended at 4.0 and 8.0
for this VPS, but are not yet in the live configuration. At high load, new
planner, browser, bootstrap, learning, and research work is deferred while a
new plan run can still proceed. At critical load, all new heavy work is
deferred. Cleanup, backups, reports, and operator reads are not admitted
through this gate. An unavailable load sample fails closed only when the
thresholds are configured. This is a load-shedding control, not a CPU quota;
it does not interrupt an already executing action or replace systemd limits.
The pending build also measures `/` independently of block-backed state, with
a configurable one-GiB free-space reserve and separate
`LOW_SYSTEM_DISK`/`HIGH_SYSTEM_DISK`/`CRITICAL_SYSTEM_DISK` warnings. High or
critical root-disk pressure blocks new heavy work without blocking cleanup or
operator reads; a missing root-disk measurement fails closed.
Resource admission no longer measures a parent disk if the BugHunter root is
missing. A configured `resources.required_mount` additionally checks that the
mount is present and that the storage root resolves beneath it; a failure
blocks new heavy work. Operations can show the resource failure only while its
local state database remains reachable. Startup now performs
that check before opening SQLite and rejects an Evidence artifact root that
resolves outside the required mount, so a missing volume cannot silently
create a fresh state database on the VPS root disk. Set `required_mount` to the
actual block mount as part of the controlled production rollout. The live
schema-34 service has not yet loaded this new setting or code.
On October 15 the agent systemd unit was given a separate
`RequiresMountsFor=/mnt/volume_sfo2_1788290659423` drop-in. `daemon-reload`
and `systemd-analyze verify` succeeded, and the agent stayed active without a
restart. The mount dependency protects subsequent starts; the in-process
guard still needs the pending build and configured `required_mount` to protect
new heavy work after an unexpected live unmount.
The configured `max_artifact_bytes` limit is enforced for new Evidence and
Report blob writes before local hashing or filesystem creation. It does not
yet bound aggregate cache size or the memory used to receive bytes upstream.
Critical disk blocks new heavy work, not operator reads,
evidence preservation, or cleanup. Runtime recovery rebuilds safe planner
metadata but pauses recovered runs for explicit operator resume; ambiguous
actions are not replayed on startup. Existing notification and object ledgers
remain the recovery authorities for their own work.
Notification startup reconciliation now processes at most 256 in-flight
deliveries per SQLite transaction using a delivery-ID cursor, marks each
`NEEDS_REVIEW`, and records an
attempt without resending it. Pending deliveries remain eligible for normal
dispatch after restart; `SENDING` and review counts are visible in health and
Operations so interrupted delivery cannot look healthy. Local restart,
idempotency, batching, and degraded-status fixtures passed on 2026-10-16.

The process inventory reads only the exact BugHunter agent, Burp, and VNC
systemd cgroups and their bounded child cgroups. Missing, unsafe, or oversized
child inventories report unknown ownership and block profile cleanup. It never
reads command lines or signals processes. A Chrome process in the agent cgroup
tree with no driver-owned browser session is surfaced as a suspected orphan for
operator review; unrelated Chrome processes are excluded. Agent-cgroup
Xvfb/Xorg, x11vnc, websockify, and fluxbox processes are tracked separately
from the deliberately persistent VNC-service display. An agent-owned display
process without an active browser session blocks profile cleanup and raises
`SUSPECTED_DISPLAY_ORPHAN`; a VNC-service display with an unavailable VNC
endpoint also raises that review warning. The local cgroup fixture passed seven
tests on 2026-10-17, including Linux's 15-character `/proc/<pid>/comm`
truncation of `chrome-headless-sh` and `chromium-browser`. The exact truncated
forms are recognized only within the agent cgroup. The focused Operations
fixture passed, and the live inventory reported
four expected VNC display processes with no agent display orphans. This is
read-only identification, not an automatic process-kill policy. Burp's global
status aggregates active listener bindings and recent bridge heartbeat
instead of implying no capture merely because no target was
selected. Neither status starts or stops a process.
This process-inventory source change invalidates earlier source-bound
complete-matrix checkpoints; the final nine-group run is still required.
The new `burp storage` CLI and Operations `burp_storage` component scan at
most 4,096 runtime entries or 0.5 seconds, do not read contents or follow
symlinks, and report `PARTIAL` or `UNAVAILABLE` rather than treating an
incomplete logical-byte estimate as exact usage. They distinguish persistent
`data/`, temporary `tmp/`, and other files. This is monitor-only; the
reviewed launcher-temp collector remains the sole Burp cleanup path.

The private `/v1/operations` endpoint and authenticated dashboard Operations
view report schema, storage, run counts, Burp, notifications, objects, backups,
and warnings. They are under development until the live service and gateway
are deployed together. Recon status now uses a read-only transaction with a
three-second connection timeout and a 30-second in-process cache. A failed
probe degrades health and raises `RECON_DISCONNECTED` in Operations without
bringing down the local control plane. `/v1/health` remains a responsive
liveness/degradation view when the local store fails; `/v1/ready` checks the
SQLite schema and startup-prepared artifact root and returns 503 only when
essential local state is unavailable. Optional recon failure reports
`DEGRADED` without withdrawing the control plane. Operations now reports
separate state, artifact, recon, Burp, browser, local research, external
research, and notifier component states. Burp and notifier status exceptions
produce sanitized degraded states instead of a 500. External research is
`UNVERIFIED` when configured but no attempted external search is recorded,
because Operations does not send a provider request. The newest completed
external search among the last 64 terminal local research records determines
observed external status: a recorded provider exception is `DEGRADED` until a
later completed external attempt succeeds within that window. This also
applies when local sources produced a partial brief. Local provider failures
are recorded separately and remain visible until a later completed local
attempt succeeds within the window. If observations age out, status becomes
`UNVERIFIED`, not `OK`. A request that merely allowed external research but
never called it is not a health observation. Local fixtures cover provider
exceptions, persisted fixed error codes, degraded Operations state, and later
recovery without network traffic; current reachability and live deployment
remain unverified. A persisted `RESEARCH_FAILED` or `INTERRUPTED` terminal
request also degrades the aggregate research component until a later terminal
request succeeds; it does not trigger automatic retry or hide exception text
in Operations.
Historical requests with the ambiguous `PROVIDER_UNAVAILABLE` code degrade
aggregate research health, while both provider-specific states remain
`UNVERIFIED` rather than assigning blame from a search count. Four focused
Operations provider-health tests passed on 2026-10-16. This remains local
ledger evidence, not a live provider probe.

## Production security audit

The October 15 listener inventory showed BugHunter's Unix control socket at
mode 0700, the active SQLite file at 0600, and the sampled Evidence, backup,
and browser-profile directories at 0700. Burp proxy listeners on ports
38080-38083, the VNC/noVNC listeners on 5900/6080/6901 where present, and
Chromium CDP on 9222 were loopback-bound. Caddy owns public 80/443; dashboard
authentication and CSRF still require an end-to-end deployment regression.
One unauthenticated GET to `/hackbot/operations` through local Caddy returned
302 to `/login`, and all 14 gateway tests passed under the BugHunter virtual
environment. These checks do not prove every deployed
state-changing path or authenticated browser interaction.
An October 15 read-only recheck found the control socket and runtime directory
at 0700, SQLite at 0600, and sampled Evidence, backup, and browser-profile
directories at 0700. The private config, backup-key environment file, recon
environment file, and Burp bridge token were all root-owned mode 0600. The
observed Burp 38080-38083 and noVNC 6080/6901 TCP listeners were bound to
loopback; no raw VNC TCP listener was present in that sample. Unrelated public
listeners were not changed. This does not establish that every authenticated
gateway operation has passed a deployed CSRF/browser regression.
The VPS also has unrelated public and private listeners, which this phase
must not reconfigure as a side effect.
On 2026-10-16, a fresh `ss -ltnp`/`ss -lxnp` and `stat` check again found the
BugHunter control socket and runtime directory at mode 0700, Burp ports
38080-38083 bound to loopback, and BugHunter noVNC on loopback port 6901.
This is listener-boundary evidence only; authenticated Operations rendering,
POST CSRF, and the staged unit's post-restart filesystem restrictions still
need deployment verification.
The October 16 local Caddy recheck redirected an unauthenticated
`/hackbot/operations` request to login. The three-module service/gateway
segment passed 91 tests in 11:07; a focused secret-bearing console-notifier
fixture passed after its logging was narrowed to a validated event ID only.
The control socket and runtime directory remained mode 0700, the live SQLite
file and private config/key files mode 0600, and sampled artifact, profile,
and backup directories mode 0700. This is not a deployed authenticated
browser/CSRF regression or a complete secret-logging audit.
The recon dashboard gateway's 14 synthetic Unix-socket tests then passed in
17.6 seconds without production database access. They cover authentication,
CSRF on maintenance writes, stripping dashboard credentials before private
proxying, and inert rendering of target-controlled report text. They do not
prove the deployed authenticated browser path or authorize a service restart.

The agent and VNC units still run as root. Burp uses the dedicated
`bughunter-burp` user. All three units have `NoNewPrivileges=yes`; the agent
has staged CPU/memory/task limits. The repository agent unit now stages
`PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, a block-backed
`ReadWritePaths`, and an empty capability set. This source-unit change is not
yet active in the live service. A transient systemd fixture showed that
`ProtectSystem=strict` alone did **not** protect this VPS's separately mounted
`/root`; adding `ProtectHome=read-only` blocked a source-tree write while
allowing a temporary block-storage write. Under those combined directives,
the local Chromium fixture passed, 40 service tests passed, and a runtime
Unix socket was created. `systemd-analyze verify` accepted the staged unit.
A repository unit test now asserts the `/root` protection and block-volume
write exception; the manifest assigns all 56 current test modules. The loaded
unit now reports `ProtectSystem=strict`, `ProtectHome=read-only`, and
`PrivateTmp=yes`, but the still-running agent (PID 407039) shares PID 1's
mount namespace. Those restrictions have not taken effect in that process;
they require the controlled schema-46 rollout and service restart.
The live database is schema 34 while this source expects schema 46. All
ordinary store initialization now permits first-time setup but refuses to
migrate an existing database, including CLI and registry paths. Only the
isolated backup-upgrade rehearsal explicitly opts into migration. A read-only
`hackbot storage startup-check` reports
`MIGRATION_REQUIRED` for the live store. The repository systemd unit uses it
as `ExecCondition`, so a future restart is skipped cleanly rather than
repeatedly launching Gunicorn against the old schema. `systemctl daemon-reload`
loaded that condition without restarting the running service; its PID was
unchanged. This preserves data but means the dashboard will remain unavailable
after a reboot until the controlled, backed-up migration is completed. Do not
remove the gate merely to restore availability.
The VPS unit also has `ConditionPathExists` for its known block-backed SQLite
file. A missing production database now skips startup instead of silently
creating an empty state. Local first-run fixtures may still initialize a fresh
store through the runtime; production recovery from a missing file requires an
operator-verified restore.
Moving agent/VNC to an unprivileged user is deferred until browser, Burp,
block-storage, and private-socket fixture tests prove it will not break
recovery. On 2026-10-16 the system journal occupied about 2.2 GiB. A
host-wide drop-in now caps persistent journal storage at 4 GiB and runtime
storage at 512 MiB while preserving 10 GiB free on the root filesystem.
No time-based retention is imposed; the cap can eventually evict older recon
and other service logs. The repository agent unit separately stages a
per-service `LogRateLimitIntervalSec=30s` and `LogRateLimitBurst=300` to bound
bursts after the controlled agent restart. Rate limiting can discard excess
messages and does not replace the shared journal size cap.
The installed drop-in matched the repository file and appeared in
`systemd-analyze cat-config systemd/journald.conf`. After restarting only
`systemd-journald.service`, journald, BugHunter agent, Burp, and VNC were all
active, and `journalctl --disk-usage` remained at 2.2 GiB. This proves the
limit was loaded without immediate pruning; it does not prove future rotation
at the 4 GiB threshold. The journal config fixture passed 2 tests.
The persistent VNC display still writes four mode-0600 child logs to the
block-backed runtime directory. A host logrotate rule now checks them daily,
rotating weekly or above 10 MiB and retaining four compressed rotations.
It is not a hard byte cap between daily checks. The timer is enabled and
active. The revised launcher and VNC unit send new child output to journald
with a 300-message/30-second burst limit. Before the controlled VNC-only
restart, there was no connected port-6901 client, agent-owned browser process,
or active browser-session row. The restart kept BugHunter, Burp, and the
separate human-login browser active. The new VNC service remained active,
port 6901 was loopback-bound, local noVNC returned HTTP 200, and journald
received child output. The old file logs remain for a separate retention
review; they are no longer the launcher's log destination.
At 05:54 UTC on 2026-10-17, the installed journald and VNC logrotate files
again matched their repository copies. The effective journal configuration
reported `SystemMaxUse=4G`, `SystemKeepFree=10G`, and `RuntimeMaxUse=512M`;
`logrotate.timer` was active, journal usage was 2.2 GiB, and the four VNC
logs were each 12 KiB or smaller. This verifies installed controls, not an
actual rotation at the thresholds.

`hackbot storage check` opens the live SQLite file read-only and reports bounded
`integrity_check`, foreign-key status, schema and core-table presence, journal
mode, WAL bytes, and free pages without displaying database contents. The live
database currently uses rollback-journal mode and schema 34; the pending build
expects schema 46. Do not switch journal mode, run VACUUM, or perform a live
migration merely to improve a health metric. Back up first, then use an
isolated migration/restore rehearsal and a controlled service deployment.

## Verification strategy and known gaps

`scripts/verify_all.py` assigns every `tests/test_*.py` module to exactly one
of nine required groups. It runs each group in a separate process, prints
durations and a combined result, and warns about no-output intervals without
terminating a CPU-active browser test. The warning now defaults to 180 seconds
and reports pytest-process CPU ticks since the last output; child browser CPU
is not included, so the indicator is diagnostic rather than a stall verdict.
On runner interruption, including `SIGTERM`, pytest is launched in its own
process group and that group is terminated before the runner exits; a focused
local regression test passed on 2026-10-16. This prevents an interrupted
verification command from leaving its direct pytest child running, but it is
not a general browser-orphan supervisor.
`--manifest-only` proves module assignment, not test success. A complete run
without `--group` is the acceptance command;
single-group results are only partial evidence. No Phase 30 acceptance test may
contact bounty targets or write to production recon PostgreSQL.
The runner now accepts `--resume-file` for an operator-owned checkpoint outside
the source tree. It records only passing modules and fully passing groups,
atomically and mode 0600,
under a fingerprint of source, tests, deployment fixtures, Python, and installed
package versions. A different fingerprint or manifest fails closed rather
than reusing older results. With a resume file, each module runs in its own
pytest process, so an interrupted group can resume from its next unfinished
module. A group is credited only after all assigned modules pass; the final
invocation without `--group` still produces one combined matrix result.
The runner also accepts `--module` with the same resume file for an individual
assigned module, in any order. It rejects group records that lack any assigned
module pass, and module mode cannot claim full-matrix completion. The final
unfiltered invocation remains mandatory.
This preserves progress under VPS load without weakening the requirement to
execute all nine groups on the final source or verify the deployed service.
The module-checkpoint fixtures passed 13 focused tests on 2026-10-17; no
prior-source checkpoint is eligible for the current build.
The first real checkpointed `unit-fast` run then passed 177 tests across 19
modules in 4:04 (246.7 seconds wall time including runner overhead). Its
mode-0600 checkpoint contains only that group, and a second invocation reused
it after the same-source fingerprint check. `complete=false` remains correct:
the other eight required groups have not passed on this checkpoint.
The October 17 manifest-only check assigned all 59 current test modules to
the nine required groups with no omissions. The first full run found a
read-only `storage status` regression for an uninitialized root; the CLI now
reports `BLOCKED/STORAGE_UNAVAILABLE` without creating state or measuring the
parent filesystem.

The 2026-10-15 baseline run assigned all 54 modules present at that time and measured group times
of 1:56 unit, 5:49 store/migrations, 37:26 API, 26:26 authorization, 8:19
surface, 5:41 workflow, 3:19 execution, 5:01 browser, and 6:47
service/gateway. Eight groups passed; authorization stopped after 73 passes
on one suite-order-sensitive CSRF fixture. That test passed in isolation.
Inspection found an imported `unittest.TestCase` fixture collected a second
time in the mutation module (62 collected instead of 33). The import was
changed to module-qualified access; the corrected run passed 59 cases before
an unconverted fixture alias was identified, and its remaining four distinct
cases passed after correction. Those earlier partial runs were not a green
complete matrix.

After adding the schema 38 finding-hold fixture, the migration/Evidence
compatibility subset passed 187 tests in 2:54. This is a focused result, not
the required complete matrix. The Phase 29 notifier/report module passed its
28 tests in 3:09 after the finding-hold change.

After the schema-39 index migration and bounded-memory bucket scan changes,
the 14-module store/migrations segment passed 258 tests in 3:31 on
2026-10-15. The smaller store/backup/retention subset passed 69 tests in
39 seconds. The manifest assigned all 55 modules without omissions. These
are partial results; rerun the complete matrix after the remaining Phase 30
changes.

The stricter unencrypted-secret gate and conservative pruning passed all 26
backup tests, including an
unselected `SECRET` Evidence row with fixture metadata in both creation and
verification paths, malformed newest metadata, and a corrupt older generation.
This is a focused
security result, not full backup or live deployment acceptance.

With the schema-40 validation hold and historical fixture updates, the
14-module store/migrations group passed 265 tests in 4:33. The focused
store/hold suite and the affected validator legacy-upgrade case also passed.
The source remains undeployed and the complete matrix must be rerun after all
remaining changes.

The schema-40 historical-link rollback fixture rejects null, missing,
malformed, non-array, and non-string references without advancing the schema
version or discarding pre-existing Evidence. A malformed unlinked validation
does not block the upgrade. The 14-module store/migrations segment passed 269
tests in 3:03 on 2026-10-15; this is still an isolated test result, not live
migration approval.
The Phase 29 notification/report module then passed 29 tests, including a
pending-confirmed-alert restart fixture that sends once and remains deduplicated.

The subsequent complete matrix finished at 2026-10-15 15:55 UTC with
`complete=true` and `passed=true`: 55 modules in nine groups, 809 passed,
one browser-fixture skip, and no failed group. The group results were 144
unit-fast, 240 store/migrations, 85 API, 63 authorization, 56 surface,
54 workflow, 47 execution, 36 browser plus one skip, and 84 service/gateway.
This is a pass for the code at that point, not proof of unimplemented
retention or live deployment. Rerun the complete matrix after later code
changes before declaring Phase 30 complete.

The subsequent named-profile review/serialization work passed 93 focused
service, CLI, browser, maintenance, and profile-retention tests. Its config
boundary passed 38 focused config/retention/maintenance tests. These overlap
and are not a replacement for a fresh complete matrix.
The affected segmented rerun then passed unit-fast (151), store/migrations
(273), service/gateway (87), and browser (36 passed, one skip) with 55 modules
still assigned across all nine groups. The five other segments were not rerun
after this change, so this is not a complete-matrix pass.
After the backup-upgrade rehearsal command and schema-copy fixtures were added,
the current manifest assigned 56 modules. `unit-fast` passed 152 tests and
`store-migrations` passed 275 tests on 2026-10-15. The focused backup module
passed 28 tests. The remaining seven groups have not been rerun after this
change, so the full Phase 30 acceptance matrix remains pending.
After adding operator-reviewed stale decrypted restore-stage cleanup, the
focused backup module passed 31 tests and the 14-module `store-migrations`
segment passed 278 tests on 2026-10-15. This newer segment pass does not
replace the still-pending complete matrix or the live rollout checks.

With schema 41 and the reviewed standalone-Evidence retirement path, focused
`test_store` plus `test_retention` passed 47 tests, `test_backup` passed 33,
and the expanded `test_retention` module passed 24 on 2026-10-15. The
14-module store/migrations segment passed 287 tests and unit-fast passed 152;
the encrypted schema-34-to-41 rehearsal preserved all 80 Evidence rows. These
are overlapping partial results. The complete matrix and live rollout remain
pending.
After the direct late-link guards were added, the 14-module store/migrations
segment passed 289 tests on 2026-10-15. It took 26:13 under severe concurrent
VPS load (load average about 57 at completion, swap nearly full); the slowest
backup fixture took 7:33. This is an observed resource-pressure limitation,
not a failed test or evidence that the complete matrix has passed.
After adding named-JSON late-link guards and a missing-trigger schema gate,
the focused retention/backup modules passed 57 tests. The full store/migrations
segment and complete matrix have not been rerun since that change.
After requiring all reviewed direct Evidence references and their insert/update
guards to match schema 41, the focused retention module passed 26 tests. This
does not replace the store/migrations or complete-matrix rerun.
The next `api-specialists` segment passed 59 tests before one local
disposable-delete fixture reached `UNKNOWN` rather than `READY`; it stopped
after 56:10 under severe VPS contention. A focused backup run similarly had
one local authorization fixture fail with `EXECUTION_FAILED`, then passed its
33 tests after a fixture-specific timeout increase. The 13-test Validator
module still had three loopback `TIMEOUT` failures with a one-second read
deadline; its composed fixture now uses the executor's normal 3/10/30-second
limits. The API disposable-delete fixture uses those same bounds.
These timeout adjustments and the failing cases require a later low-contention
rerun. Neither the API segment nor the complete matrix is currently passing
evidence for this revision.
The previously failing API disposable-delete case passed on its targeted rerun
with the standard fixture timeout, but took 714 seconds under the same VPS
load. This is one passing case, not a passing API group or complete matrix.
The opt-in normalized CPU-load admission gate passed 22 config/resource tests
and one focused Operations API test. At inspection the two-CPU VPS had a
one-minute load above 180 and its 4 GiB swap was full. The thresholds have
not been enabled in the live schema-34 service; staged behavior and unit tests
do not substitute for the controlled rollout or complete matrix.

On 2026-10-15, the staged BugHunter-only journal burst limit passed its
systemd unit assertion and `systemd-analyze verify`; neither directive is
active in the live unit. The current 56-module manifest still has no omissions.
The `unit-fast` segment passed 155 tests across 17 modules in 1:04, and the
`store-migrations` segment passed 293 tests across 14 modules in 4:21. These
are separate passing segments, not a fresh complete-matrix result. Research
briefs cannot be deleted on expiry alone: request history and hypothesis or
planner links retain their IDs. Any cache retirement needs an explicit
metadata-preserving contract and reference-aware eligibility checks.
The API specialist segment was stopped after 23 passes in 8:14 when concurrent
VPS load again made local loopback fixtures take 21-143 seconds each; the
interrupted group is not a pass or an application failure. The test runner's
shorter no-output warning and CPU-progress probe passed five focused tests.
After making existing-schema migration opt-in for every ordinary store caller,
the store, identity-registry, traffic, and CLI subset passed 73 tests in 2:48.
Six focused migration/backup/planner tests passed in 0:25, and the 56-module
test manifest had no missing or duplicate assignments. The live service was
not restarted; its database remained schema 34. The complete backup module
then passed 38 tests in 3:10 under concurrent VPS load. This is not a fresh
complete-matrix result.

The backup module subsequently passed 42 tests, and the 14-module
`store-migrations` segment passed 304 tests after the opt-in migration and
encrypted-verification changes. The research module passed 17 tests after
provider-specific failure recording was added, and three focused
provider/Operations tests passed. These are partial results; the complete
matrix and live rollout remain pending.

The DOM XSS and postMessage Babel child parsers now share a bounded
20-second deadline. An expiry returns `PARSE_FAILED/PARSER_TIMEOUT` instead
of silently treating the asset as analyzed; the DOM store retries a failed
analysis on a later explicit call. Focused parser tests passed, and
the current `unit-fast` segment passed 159 tests across 17 modules in 2:07.
The API segment's earlier ambiguous local object creation reused a fixture
with one-second loopback read timeout; its authorization consumer now uses
the executor's normal 3/10/30-second fixture limits. The previously failing
GraphQL batch case passed in isolation (2:36) after that change. The complete
API segment and nine-group matrix still require fresh passing runs.
The DOM store module then passed all 5 tests, including a timeout-to-success
retry that reused the versioned analysis row. Under severe concurrent VPS
pressure, the API segment was operator-interrupted after 23 passing tests in
16:15; its slowest local case took 5:47. The interrupted segment is not a
passing API result and is not evidence of an application failure. A lower-load
rerun and the complete matrix remain required before deployment.

The staged traffic-retirement work passed 98 local traffic, retention, and
backup tests on 2026-10-16. Fixtures cover reviewed logical retirement,
metadata preservation, shared-digest and late-reference holds, separate GC,
and old/new `ALL` backup selection. The first combined run found a mock cursor
missing `fetchall`; after the fixture was corrected, the full 98-test subset
passed in 4:19. This subset does not replace the nine-group matrix or a live
schema-44 rollout. At that stage the reference scan was deadline-bounded
rather than indexed, so production-scale eligibility could fail closed under load.
A subsequent focused fixture also created and verified an encrypted `ALL`
backup after the reviewed GC removed a retired-only traffic blob.

The pre-index traffic and Evidence reference scans validated each JSON column and
apply an exact-ID-or-Unicode-escape prefilter before expanding JSON trees.
Regression fixtures confirm that Unicode-escaped IDs still hold their owners
and malformed JSON still fails closed. The 56-test traffic/retention subset
and the 79-test backup/store subset passed on 2026-10-16 after these changes.
SQLite's query plan evaluates the prefilter before the JSON virtual-table
filter; no candidate-row materialization is used. This reduces avoidable
JSON-tree work, but at that stage it still scanned JSON columns. Schemas 43
and 44 add indexed reachability for exact TrafficStore and Evidence IDs.

After schema-42 exchange markers and late-link guards were added, the local
traffic/retention/backup subset passed 101 tests in 3:55. A schema-41-to-42
fixture preserved existing traffic and installed the guards; a new unguarded
reference table blocked initialization, GC, and backup selection. Version-4
`ALL` backup selection now pages through retired digest owners and applies its
50,000-file limit only to reachable artifacts. The complete 14-module
`store-migrations` segment passed 324 tests in 14:49 under heavy host load.
The `unit-fast` segment then passed 160 tests across 17 modules in 3:13.
The encrypted schema-34-to-42 rehearsal also passed without replacing live
state. The service/gateway group later passed 91 tests across three modules
in 11:07. These results do not replace the remaining six groups or controlled
live rollout.
The `surface-specialists` group passed 56 tests across four modules in 17:04
on 2026-10-16. Its slowest exposure-runtime fixtures took 56-73 seconds each
under concurrent VPS load. The `api-specialists` group then passed 85 tests
across three modules in 1:25:51. Its five slowest API-runtime cases took
183-241 seconds each. The `execution-specialists` group then passed 47 tests
across four modules in 5:24 on 2026-10-16. The `authorization-specialists`
group passed 63 tests across two modules in 53:22; its slowest mutation cases
took 111-127 seconds each under host load. After the Burp-index retention and
late-retry edits, the complete traffic/Burp modules passed 49 tests in 1:50.
The first `workflow-specialists` run stopped when a bootstrap fixture received
HTTP 503 from host-dependent resource admission. The isolated case passed; the
fixture now supplies healthy disk, memory, and load probes while still using
the real admission logic (pressure behavior is tested separately). All 23
bootstrap tests passed in 7:43, and the complete `workflow-specialists` group
passed 56 tests across four modules in 11:52 on 2026-10-16. The `browser`
group passed 36 tests with one optional Chromium integration fixture skipped
because `HACKBOT_TEST_CHROMIUM` was unset; that fixture passed separately with
the installed local Playwright Chromium binary (one test in 10.50 seconds).
After bounded child-cgroup process inventory was added, process/profile/resource
fixtures passed 30 tests and the `unit-fast` group passed 163 tests across 17
modules on 2026-10-16. The live read-only process inventory remained `OK`.
Earlier groups predate the latest Burp-index edits, so a final complete-matrix
pass is still required; these results are not a complete-matrix result.
The current manifest assigns all 56 test modules to one of nine groups. After
schema 43, a focused store/traffic/backup/retention run passed 118 tests and
stopped on a malformed-JSON fixture that the new write guard correctly
rejected. That fixture now tests both write rejection and read-side failure
on simulated legacy corruption; its isolated test passed. The full
`store-migrations` group then passed 293 tests and stopped when an ObjectFactory
fixture returned `NEEDS_MANUAL_REVIEW` instead of `READY`. Its one-second
loopback timeout may have contributed under host load; the original result
reason was not captured. The fixture now uses a bounded longer timeout for
that case, includes the reason in failures, and passed in isolation. The group
result remains failed until a clean rerun. Neither partial run proves complete
Phase 30 verification.
After the shared ObjectFactory fixture timeout was raised, its full module
passed 16 tests in 10:04. The two modules not reached by the interrupted
store-group run, Phase 12 and profile retention, passed 22 tests in 3:22.
All 14 store-group modules have passing coverage across these separate runs,
but the authoritative combined group remains unproven until it passes in one
run. The nine-group complete matrix has not yet passed against the current source.
The schema-43 `unit-fast` group passed all 163 tests across 17 modules in
2:50. This is one green segment, not a complete-matrix result.
After schema 44, the Evidence-retention module passed 31 tests; the combined
TrafficStore and backup modules passed 81 tests in 11:14. Focused schema-43
backup compatibility and missing-trigger checks also passed. These are
partial results; the current schema-44 complete matrix remains pending.
The schema-44 `store-migrations` group then passed all 335 tests across 14
modules in 36:04 on 2026-10-16. Its slowest fixture took 118 seconds under
shared VPS load. This is a green required segment, not a complete-matrix pass.
The schema-44 `unit-fast` group passed all 163 tests across 17 modules in
2:38. The staged JSON-index audit added six focused retention tests and two
backup/CLI tests, all passing in isolation. The full affected retention and
backup modules then passed 85 tests in 12:19 under shared host load. A final
JSON-audit size/depth guard was applied during that run; eight focused
audit/backup cases then passed on final source. The module result does not
replace the final-source
`store-migrations` group. The remaining seven groups and the authoritative
complete-matrix run are still pending.
The schema-44 `service-gateway` group then stopped with 84 passing tests and
one Burp loopback timeout after 65:52 under a two-CPU load near 11. The bridge
had ingested the local fixture request before the three-second client timeout,
then attempted to write to the closed connection. The loopback-only fixture
now uses bounded 30-second app/bridge and 45-second outer-client deadlines;
the bridge ignores response-write disconnects instead of sending a second
error response. The failed fixture and disconnect regression passed together,
and the full Burp module passed 21 tests in 3:28. The combined service group
remains failed until rerun, and the nine-group matrix remains unproven.
The operational Burp Community service was found failed on 2026-10-16 after
three starts at the old 90-second wizard deadline. The launcher was extended
to a bounded 180-second wizard wait with sanitized failure classification and
installed without restarting BugHunter. A controlled start then reached the
expected wizard, temporary-project ready message, and four loopback listeners
on ports 38080-38083; `hackbot burp check` returned `BURP_AVAILABLE`.
`bughunter-agent.service` retained its original PID. This verifies local
proxy recovery, not end-to-end capture ingestion or a target request.
On 2026-10-16 a fresh encrypted schema-34 backup
`20261016T124641Z-e48d763f` was created and verified. The isolated
schema-34-to-44 rehearsal preserved 80 Evidence rows and all tracked table
counts, passed SQLite integrity checks, and independently audited 268 JSON
values against the new reference indexes with no mismatches. Active state was
not replaced. Future rehearsals now require that bounded JSON audit; a mismatch
or incomplete audit fails closed and removes the decrypted stage. This is a
pre-rollout backup rehearsal, not the required post-rollout schema-44 backup
audit or permission to restart the live agent.
The complete Burp module then had 22 passes and one timeout in a separate
three-second loopback capture fixture under shared host load. That fixture now
uses a bounded 30-second client wait and passed in isolation. The full Burp
module then passed all 23 tests in 2:36. The combined service/gateway segment
still needs a clean final-source run.
The October 16 listener audit found Burp's four proxy ports and noVNC bound to
loopback, with the BugHunter Unix control socket at mode 0700. Root-owned
archived UI smoke screenshots and full-suite logs were tightened to private
directories/files (0700/0600); the live Burp runtime was left untouched.
This is a targeted permission correction, not the completed service-wide
security audit.
After the rehearsal audit change, the complete backup module passed all 51
tests in 3:55, including a finding/report/planner fixture with positive
Evidence-ID reference counts. The current test manifest still covers all 56
modules in nine required groups, and `systemd-analyze verify` accepted the
staged BugHunter unit. Neither result activates the staged unit or proves the
combined final-source matrix.
The reviewed Burp launcher-temp collector passed nine focused launcher and
retention fixtures, and the full Burp module passed 30 tests in 4:12 on final
source. A live dry run identified two old `community-*` directories
with 308,556 estimated bytes and excluded the current project; a confirmed
cleanup attempt refused while `bughunter-burp.service` was active, and all
three directories remained. The lock file is private and owned by the
dedicated Burp user. No production Burp data was removed. The locked launcher
file was installed and matched repository source before the service restart.
The lock-aware launcher was activated by a controlled Burp-only restart on
2026-10-16 after a read-only check found no active browser sessions, active
capture bindings, bridge targets, or connected proxy clients. The agent PID
was not changed. All four Burp listeners returned on loopback, `burp check`
reported `BURP_AVAILABLE`, and a nonblocking exclusive lock attempt failed
while the service held the shared lock. A subsequent dry run still identified
only the same two abandoned directories; no Burp data was deleted. This
verifies live launcher lock coordination, not end-to-end capture ingestion or
generic Burp cache retention.
The same read-only storage audit found BugHunter's state, artifacts, backups,
browser profiles, and Burp runtime on the block volume. Burp's persistent
`burpbrowser` directory accounts for about 668 MiB of its 672 MiB runtime;
it was not classified as disposable launcher cache or deleted. A historical
root-owned SQLite snapshot inside the private state directory was mode 0644
and was tightened to 0600. Regular setup screenshots directly under the
private Burp runtime directory were also tightened from 0644 to 0600. A
follow-up scan found no world-readable regular files in the BugHunter state,
artifact, backup, or browser-profile trees. The Burp proxy, BugHunter noVNC,
human noVNC, and human CDP TCP listeners sampled in this audit were loopback
bound; the control socket remained mode 0700. An unauthenticated local-Caddy
GET of `/hackbot/operations` redirected to login. This does not prove the
authenticated Operations POST/CSRF flow or end-to-end capture ingestion.
The bounded Burp runtime monitor completed a read-only live inventory of 585
entries: 703,210,966 logical file bytes in total, including 699,375,212
under persistent `data/` and 658,044 under `tmp/`. The scan followed no
symlinks and reported no paths or file contents. The revised `unit-fast`
segment passed 167 tests across 18 modules in 5:03; two focused Operations
service tests passed in 15.84 seconds. The test manifest now assigns all 57
modules. An early `api-specialists` run was intentionally interrupted while
CPU-active after 21 minutes so host resources could be used for remaining
Phase 30 work; it is neither a pass nor evidence of a test hang. The complete
final-source matrix remains pending.

The `execution-specialists` segment passed all 47 tests across four modules on
2026-10-16 in 35:11 under heavy shared-host load. A loopback executor fixture
had used a two-second overall deadline for ordinary requests and could record
`TIMEOUT` after receiving HTTP 200; ordinary fixture requests now use a bounded
60-second deadline, while the intentional slow-response test explicitly keeps
its short timeout. The rate-concurrency fixture now holds the first reservation
at the pre-send hook instead of relying on a half-second scheduling window.
Focused regressions passed before the complete segment. Its five slowest
validator cases took 151-306 seconds each, so this pass proves behavior but
does not resolve the overall test-runtime concern or replace the other eight
segments of the final-source matrix.

The `service-gateway` segment passed all 105 tests across the service,
Phase 29, and Burp modules on 2026-10-16 in 1:08:39 under the same shared-host
load. Its slowest report/notification cases took 149-537 seconds. Live stack
samples during the longest cases showed the test process advancing through
local plan-run, Evidence, and report-store operations; this was not a silent
process exit or a proven deadlock. The result verifies the combined local
fixtures, but not the deployed authenticated Operations UI, live capture
ingestion, or the seven other final-source test segments.

After adding the notification restart fixtures, the updated `unit-fast`
segment passed all 170 tests across 19 modules on 2026-10-16 in 4:04.
The manifest assigns all 58 discovered test modules without omission or
duplication. This is one segment, not a complete final-source matrix pass.
After the delivery-ID recovery cursor change, `unit-fast` passed again on
the current source: 170 tests in 3:13 on 2026-10-16.

The `api-specialists` segment was stopped after 35:50 on 2026-10-16 because
individual CPU-active local GraphQL fixtures were taking several minutes; it
is **incomplete**, not a pass or a hang. Stack samples showed repeated
authorization-profile work in API inventory and candidate generation. A
small Phase 30 runtime change reuses one target-bound authorization snapshot
within each `generate()` call. Its call-count/target-binding fixture passed,
and a representative GraphQL approval case passed in 5:35 under the same
load. This removes duplicate profiling but does not yet prove that the full
API segment is operationally fast enough; it must be rerun to completion.

The two-module API inventory/GraphQL parser regression initially had one
failure among 41 passes: the five-second Node AST deadline expired while
paging a bounded 1,025-route fixture. The parser now has a 20-second wall
deadline, still reports paged extraction failure rather than successful
coverage, and retains its existing byte/page caps. The failed fixture and an
explicit timeout-contract test passed in isolation; the complete two-module
rerun then passed 42 tests in 10:14. The API runtime module and authoritative
three-module segment still need a final pass.

The schema-45 ResearchBrief cache path passed focused retention, planner-link,
configuration, CLI, historical upgrade, and backup-guard tests. A combined
research/store/retention run passed 57 tests; a later affected research,
retention, CLI, and config run passed 51. An affected backup/retention
run passed all 64 tests in 8:01, and the complete ResearchBrief-retention
module passed 12 tests after adding derived-index drift coverage. These
overlapping runs are not a complete final-source matrix. On
2026-10-16, encrypted backup `20261016T183411Z-97fe1967` was verified and
rehearsed from schema 34 to 45 in an isolated restore stage. SQLite integrity
and foreign keys passed; 80 Evidence rows and all other tracked table counts
were preserved; the independent JSON-reference audit matched 268 values.
The active database was not replaced, restore staging was empty afterward,
and a read-only live check still reported schema 34 with integrity and foreign
keys passing. The controlled rollout and full test matrix remain pending.

A second isolated rehearsal of the same verified encrypted generation against
the current schema-46 source passed: SQLite integrity and foreign keys were
clean, all 80 Evidence rows and other tracked counts were preserved, and the
independent JSON-reference audit matched all 268 scanned values. The decrypted
restore stage was removed, the live database remained schema 34, and the
BugHunter service remained active. This proves the migration on that snapshot,
not a production rollout or complete recovery of every artifact class.

The controlled HTTP executor now applies the configured JS/source-map expiry
to its separate asset Evidence, matching DOM-created Evidence. A local
13-test executor module run passed, followed by three focused capture,
DOM-handoff, and service-wiring checks. These tests use loopback fixtures only;
they do not establish safe retirement of DOM-linked bytes or replace the
complete final-source matrix.

A current-source `unit-fast` matrix segment passed 179 tests across 19 modules
in 3:06. The following `store-migrations` segment was stopped at 60% while
still CPU-active under sustained VPS load; it has no passing-group checkpoint.
The same source then gained DOM JS/map expiry metadata, so the prior unit
checkpoint is historical and cannot satisfy the final-source matrix. Focused
DOM-store/config/service tests for that change passed 22 tests. No production database
or service was changed by these tests.

A current-source `surface-specialists` rerun on 2026-10-16 was intentionally
stopped after observing sustained host load around 14 on 2 CPUs with full swap.
The pytest child remained CPU-active and emitted completed-case dots; the
interruption is not a failure or a pass. No surface segment result from that
run counts toward the required final-source matrix. The previous
`store-migrations` rerun was likewise interrupted after prolonged CPU-active
execution and remains incomplete.

The schema-46 DOM retention follow-up now checks decoded JSON object keys as
well as values, including Unicode-escaped owner IDs, before and after logical
retirement. Focused key-reference tests passed (2 tests); focused GC and backup
tests passed (4 tests), as did a separate schema-45-to-46 guard-migration test.
The combined retention/backup run passed 107 tests but began before the final
key/cache edits, so it is supporting coverage rather than a final-source
segment. A later current-source CLI/DOM-store/executor run passed 35 tests.
The authoritative manifest assigns all 59 test modules to nine groups, and a
current-source `unit-fast` segment passed 180 tests across 19 modules in 3:03.
Its matrix result was explicitly incomplete; the other eight groups and the
final combined result remain pending.

Known remaining work before Phase 31: lifecycle-aware linked Evidence beyond
the current standalone, TrafficStore, and DOM owner contracts; a controlled
schema-46 production rollout of the staged retention policies; verified retention/recovery policy
for persistent Burp data and generic cache (now monitored but not pruned);
a durable artifact inventory or equivalent bounded-time directory
listing for very large hash buckets (the current scan still enumerates a whole
bucket despite bounded memory); running the new independent JSON-index audit
on a post-rollout schema-44 production backup; additional crash,
notification, and process-recovery fixtures; deployment and visual checks for
the CSRF-protected Operations controls; end-to-end optional-provider health
evidence; safe systemd CPU/memory policy under recon load;
the remaining security and permission audit; activation of staged systemd
hardening; and live deployment smoke tests.
These gaps are not waived by the existing backup or orphan collector.

The 2026-10-16 read-only boundary recheck found the BugHunter control plane
only on `/run/bughunter-agent/control.sock` (mode 0700, root-owned), with no
BugHunter TCP control listener. Burp's four proxy listeners and BugHunter
noVNC were loopback-bound; the dedicated VNC relay used a private Unix socket.
Unauthenticated local dashboard requests redirected `/hackbot/operations` to
login and returned 401 for the Operations API and maintenance POST. The live
SQLite file and selected state, Evidence, backup, and browser-profile trees
were owner-only; one mode-0644 Burp preference file was behind the mode-0700
Burp runtime directory. CORS headers were absent on the sampled unauthenticated
response. This is not an authenticated CSRF or visual Operations regression.
The agent process started on October 14, before the currently staged unit
changes; its active sandbox and resource limits remain unverified until the
controlled rollout. The live store still reports schema 34; the current
source expects 46. The last read-only integrity and foreign-key checks passed
before schema 45 was staged. Host load was
roughly 9 on two CPUs with all 4 GiB swap occupied, so no new heavy test
segment or service restart was initiated during this recheck.

On 2026-10-17, a read-only `systemctl show` recheck confirmed that the active
agent unit has `CPUWeight=50`, `MemoryMax=2621440000`, `PrivateTmp=yes`,
`ProtectHome=read-only`, `ProtectSystem=strict`, and `NoNewPrivileges=yes`.
The active Burp unit has `MemoryMax=1677721600`, `PrivateTmp=yes`, and
`NoNewPrivileges=yes`; the VNC unit has `CPUWeight=50`, `MemoryMax=536870912`,
and `NoNewPrivileges=yes`. These are current unit properties, not proof that
the staged schema-46 application code or every proposed hardening directive is
deployed. A read-only check of the running agent PID 407039 found
`NoNewPrivs: 1` and cgroup `memory.max=2621440000`, `cpu.weight=50`, and
`pids.max=384`. Its mount namespace matched PID 1, so the currently running
process does not demonstrate the unit's staged mount isolation; it still runs
as root with an effective capability set. A controlled restart after the
schema migration checks is required to verify those directives in-process.
The isolated dashboard gateway fixture suite passed 14 tests in
12.07 seconds with production-repository bytecode/cache writes disabled. It
covers Operations authentication, CSRF-protected POST actions, route allowlists,
and credential non-forwarding. Authenticated live-session and visual checks
remain pending.

On 2026-10-17, the 59-module manifest still assigned every test module exactly
once across nine groups. A `store-migrations` run passed 378 tests in 53:27,
but a subsequent test-only schema-46 assertion correction changed the source
fingerprint, so that pass is supporting evidence rather than final-matrix
credit. The corrected postMessage migration test passed in isolation. A
`surface-specialists` run then stopped after 17 passes and one local fixture
failure: a composed owned-object setup timed out under the fixture's 30-second
overall executor limit. The failure reproduced alone; the same two-request
loopback setup completed in 104 seconds with the supported 120-second limit.
After raising only the composed authorization test fixture to that limit, the
failing exposure test passed in isolation. Production executor limits were not
changed. The current-source `unit-fast` group passed 180 tests in 4:13 and is
saved in the source-bound checkpoint at
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-current-20261017T0010Z.json`.
The complete matrix, clean surface rerun, and controlled live schema-46
rollout remain pending.

On 2026-10-17, the orphan-artifact collector gained a configurable 30-second
cooperative scan deadline. Deadline expiry fails closed before publishing a
cleanup plan; a new dry run invalidates the old review, and an Operations
approved plan must match the persisted current review exactly. Local config
and retention modules passed 71 tests, including deadline, stale-review,
shared-reference, and schema-drift fixtures. The source-bound `unit-fast`
segment then passed 181 tests across 19 modules in 3:43; the checkpoint is
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-bounded-scan-20261017T0050Z.json`.
The other eight required segments, final combined result, durable large-bucket
inventory, and controlled production rollout remain pending. The deadline is
not proof of guaranteed scan completion on a very large bucket.
An initial `service-gateway` attempt found a test fixture dependent on the
VPS's transient free memory: two otherwise local service tests received
`LOW_MEMORY` admission under host pressure. The shared service fixture now
sets a zero minimum-memory reserve; the dedicated resource-budget test still
proves low-memory denial in production code. Three focused service/resource
tests passed. A full `service-gateway` rerun was stopped while CPU-active
after prolonged host load around 20 on two CPUs; it has no passing-group
checkpoint. The fixture edit changed the source fingerprint after the
181-test `unit-fast` pass, so that earlier checkpoint is supporting evidence
only. The final-source complete nine-group matrix remains unproven.

The module-checkpoint runner passed 13 focused tests and a real `unit-fast`
group of 184 tests across all 19 assigned modules on 2026-10-17. The group
took 412.8 seconds under shared VPS load. Its source-bound checkpoint is
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-module-checkpoint-20261017T0131Z.json`;
a second invocation reused the group without rerunning tests. The result is
`complete=false`: the eight remaining groups and the final combined matrix
are still required. No production service or database was changed by this run.

The next `authorization-specialists` module was interrupted before any module
pass because unrelated host load climbed above 180 on two CPUs. Its pytest
process was CPU-active, not proven stuck, and the prior `unit-fast` checkpoint
remained intact. The subsequent test-fixture edit changed its source fingerprint,
so that checkpoint is historical evidence only. The shared loopback
`ExecutorFixture` now copies a cached
empty schema into each private test database instead of applying all current
migrations for every nested authorization/object fixture. Four focused tests
passed across fixture isolation, authorization setup, disposable-object
lifecycle, and the schema-31-to-current mutation upgrade. The last two took
917.88 seconds together under contention, so this optimization does not yet
prove the authorization group is fast enough; all affected modules and the
source-bound complete matrix require a fresh run.

On 2026-10-17, a fresh schema-46 source-bound checkpoint at
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-20261017T0230Z.json`
passed all 19 `unit-fast` modules in 195.1 seconds and `test_api_graphql.py`
in 23.2 seconds. The manifest still assigns all 59 modules exactly once.
`test_api_runtime.py` was deliberately interrupted, not failed or credited:
its 45-case local fixture module completed only one case after roughly seven
minutes under low CPU priority on the shared two-CPU VPS. Profiling that
first case at normal priority showed about 900 SQLite connection closes and
5,359 SQL executes, with 126.5 seconds in SQLite execute and 35.8 seconds in
connection close during a 207-second profiled run. A disposable tmpfs control
still took 187 seconds, so relocating test temporary files alone is not a
validated speed fix. The interrupted child was reaped; 20 module checkpoints
were valid at that point for the identical source fingerprint, but the
complete nine-group matrix remains unproven. A separate long-running high-CPU
process was observed
outside BugHunter cgroups and was not changed.

The same day's read-only security recheck found the active control-socket
directory/socket mode 0700, live SQLite mode 0600, and artifact/backup roots
mode 0700. Burp's four `38080`-`38083` listeners, BugHunter noVNC `6901`, and
the separate human-browser `6080`/`9222` listeners were loopback-bound.
`systemd-analyze verify` passed for the staged agent and VNC units. These
checks do not prove authenticated Operations behavior or that the running
agent has inherited newly staged mount isolation.

The source-bound `store-migrations` group completed on 2026-10-17 with all
15 modules passing in 3,065.0 seconds. It includes 33 store, 59 backup, 58
retention, 14 maintenance, 8 finding-evidence-hold, 18 auth, 15 identity,
32 traffic, 75 planner-store, 9 DOM-store, 17 recon-adapter, 16 object-factory,
8 Phase 12, 14 profile-retention, and 12 research-retention cases. The
checkpoint above now holds 35 of 59 module passes and two complete groups
(`unit-fast` and `store-migrations`) for fingerprint
`17a6c084aafdeebdc73dd570e46d4db5c92013c1341f29f9db7e4167b3d96ca9`.
The group result was explicitly `complete=false`; the other seven groups,
final combined result, and controlled production rollout remain pending.
The profile of the first API-runtime case points to repeated SQLite-backed
fixture operations and connection churn, not a stalled test. No production
connection-lifetime change was made on the strength of that fixture profile.

The `service-gateway` group passed on 2026-10-17 against the same source
fingerprint: 48 service, 30 Phase 29, and 30 Burp tests. Its three modules
took 3,730.5 seconds under low CPU/IO priority on the shared VPS. The
Phase 29 module alone took 3,082.9 seconds; its GraphQL report fixture took
507.9 seconds while CPU-active. The checkpoint now has 38/59 passing modules
and three complete groups (`unit-fast`, `store-migrations`, and
`service-gateway`). The group result was `complete=false`; six groups and the
final combined matrix remain unverified. No production service, recon data,
or live bounty target was changed by these fixture tests.

A subsequent `authorization-specialists` attempt was interrupted without a
module checkpoint after the first local fixture cases proved very slow under
host load above 8 on two CPUs. The pytest child was CPU-active, not hung,
and the runner exited 130 after a controlled signal; its child process was
reaped. Available memory had fallen below 1 GiB with swap full, so the
Chromium-bearing `browser` segment was deferred rather than launched under
memory pressure. Neither attempt is credited as a passing group. The next
verification window should favor lower host contention. The 38-module
checkpoint is historical after the cgroup memory-admission source change and
must not be reused for final acceptance.

## Current acceptance ledger (2026-10-18 02:30 UTC)

This ledger tracks the 27 required completion checks in the Phase 30 brief.
`Fixture pass` means the operation was exercised on isolated local state, not
against production target objects. The live schema-46 rollout and the
source-bound matrix are complete. The final checkpoint is
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-preserve-runtime-20261018T0130Z.json`
on fingerprint `ae47ef41abbc523fe8677be7a70558545419db24510703c2454ceb7937380e15`.
The combined result reports `complete=true`, `passed=true`, 59/59 modules,
nine/nine groups, and zero failed modules. Historical partial checkpoints
below are not current acceptance evidence.

| Gate | Current evidence | Disposition |
| --- | --- | --- |
| 1. Complete test matrix | Current fingerprint `ae47ef41abbc523fe8677be7a70558545419db24510703c2454ceb7937380e15`: 59/59 modules in all nine groups, `complete=true`, `passed=true`, zero failures; local Chromium integration ran and passed | Verified |
| 2. No omitted module | Current-source `--manifest-only`: all 59 assigned exactly once | Verified |
| 3. Retention dry-run | Current-source `test_retention.py`: 59 passed. Post-rollout live `hackbot retention plan` scanned 47 artifact records, found zero candidates, and made no deletion | Verified |
| 4. Actual retention | Current-source retention module exercises confirmed fixture cleanup; no live cleanup | Fixture pass |
| 5. Finding Evidence survives | Current-source retention and `test_finding_evidence_hold.py` (8 passed) cover protected references | Fixture pass |
| 6. Artifact references safe | Current-source retention, traffic, DOM, and finding-hold modules passed; shared-digest and late-reference fixtures preserve reachable bytes | Fixture pass |
| 7. Backup create/verify | Current-source `test_backup.py`: 59 passed. Encrypted schema-34 pre-rollout generation `20261018T011827Z-6d775eae` and schema-46 post-rollout generation `20261018T012516Z-d9e8edd3` independently verified, 48 files each; post-rollout generation reverified after the matrix | Live verified |
| 8. Isolated restore | Both October 18 encrypted generations rehearsed privately to schema 46; the post-matrix schema-46 rehearsal again returned `active_state_replaced=false`, integrity OK, 80 Evidence rows, and matching audit of 268 JSON-reference values | Verified |
| 9. Corrupt backup rejection | Focused corrupt-backup fixture passed | Fixture pass |
| 10. Crash reconciliation | Current-source service, planner, browser, and object-state recovery fixtures passed in the complete matrix | Fixture pass |
| 11. Ambiguous action not replayed | Current-source service and notification recovery fixtures passed; ambiguous target/notification actions remain visible for review rather than automatic replay | Fixture pass |
| 12. Notification idempotency | Phase 29 and notification-recovery modules passed | Fixture pass |
| 13. Resource caps | Current-source `test_resources.py`: 14 passed, including cgroup-v2 headroom and fail-closed metrics; `unit-fast` group complete | Fixture pass |
| 14. Low-disk behavior | Resource and backup fixtures passed | Fixture pass |
| 15. Burp failure fail-closed | Focused mocked browser/proxy fixtures passed (2 selected tests) | Fixture pass |
| 16. Optional provider degradation | Current-source Operations, recon, research, notifier, and Burp failure fixtures passed in the complete matrix; live Operations exposes separate component states | Fixture and live pass |
| 17. Listener exposure | Post-rollout `ss` shows Burp 38080-38083 and noVNC 6901 on loopback only | Live read-only pass |
| 18. Control socket permissions | Post-rollout `/run/bughunter-agent` and socket both 0700; preserved directory inode across an agent restart | Live pass |
| 19. File permissions | Post-rollout database and private environment/config files are 0600; state, artifact, browser-profile, backup roots, runtime directory, and control socket are 0700. No group/world-readable files were found under the four sensitive storage roots. Burp-generated preferences have broader file modes only beneath its 0700 runtime root | Live pass |
| 20. Secret/redaction audit | Current-source `test_logging.py` passed 10 tests in the full matrix. Static review found no raw secret/error-body logging. A post-matrix scan of BugHunter and Burp journals, private Operations JSON, and seven backup manifests found zero exact matches for the configured backup, recon, and Burp bridge secret values; current backup is encrypted and verified | Fixture and live spot-check pass |
| 21. Dashboard auth/CSRF | Live unauthenticated panel redirects to login; authenticated panel and Operations API return 200; CSRF-less maintenance POST returns 403 without dispatch | Live pass |
| 22. Operations page | Live private Operations endpoint and authenticated dashboard proxy respond. Resource load and inaccessible Burp storage are visible as degraded warnings, not silently hidden | Live pass with known telemetry limitation |
| 23. Migration/integrity | Controlled schema-34-to-46 migration passed integrity/foreign-key checks, preserved 80 Evidence rows, and post-rollout encrypted backup audit matched all 268 JSON-reference values | Live pass |
| 24. Matrix manifest coverage | Current-source 59-module manifest assigned exactly once | Verified |
| 25. No bounty-target traffic | Acceptance used local fixtures, the private control socket, and local dashboard checks; no target package hunt or bounty-target request was initiated | Verified for Phase 30 acceptance |
| 26. No production recon writes | BugHunter recon adapter uses `BEGIN READ ONLY`; Phase 30 acceptance made no recon mutation call or schema change. A dashboard-only restart refreshed its existing socket mount and is distinct from BugHunter's read-only recon integration | Verified for BugHunter Phase 30 |
| 27. `git diff --check` | Passed after the final ledger and runbook edits; separate no-index whitespace checks emitted no warnings for the two new docs | Verified |

## Historical verification log

The dated entries below describe earlier partial builds, rollout actions,
and prior observations. They are retained for troubleshooting, not as the current
acceptance state or instructions to repeat a completed migration.

The block volume remained mounted during this read-only check. At 05:05 UTC,
host load was above 6 on two CPUs with swap full.
The authorization test attempt was stopped cleanly under this contention;
no unfinished module was credited. At that time the later matrix, backup,
and controlled rollout gates had not yet been satisfied.

Focused current-source checks at 05:05 UTC: `test_resources.py` passed 14 tests;
`test_test_matrix.py` and `test_config.py` passed 28 tests. These do not replace
the required nine-group matrix. Host-side cgroup memory is unlimited for this
shell, so the finite-limit behavior is verified by deterministic fixtures;
production service admission will need a post-rollout observation.

The prior-source low-priority `unit-fast` segment completed at 05:12 UTC:
all 19 modules passed in 274.7 seconds. At 05:27 UTC, the checkpoint had 20
passing modules after the API GraphQL fixture passed. The API runtime fixture
remained CPU-active and below 100 MiB RSS but was interrupted after host
available memory fell to about 260 MiB with swap exhausted. The runner exited
130, its child was reaped, and no API runtime module pass was credited.
The active BugHunter agent cgroup was approximately 36 MiB against its
2.5 GiB limit, but host available memory was under 0.5 GiB with swap full.
This is why browser and store-heavy groups remain deferred until host
contention improves.

Subsequent current-source acceptance slices passed: three selected backup
tests (including corrupt rejection, encrypted restore, and full fixture
restore), two retention/finding-hold tests, two Burp fail-closed tests, and
four Operations degradation tests. A synthetic recon-dashboard gateway
auth/CSRF test passed with bytecode and pytest cache writes disabled. These
focused runs are supporting evidence, not completed matrix modules. At
05:34 UTC, unrelated host workloads drove one-minute load above 160; no
Phase 30 test process remained. Broader fixture execution was paused while
that load decayed. The 20/59 checkpoint is now historical after the test
runner changed. The current-source matrix runner itself passed 15 focused
tests, including out-of-order module checkpointing and rejection of a group
record missing its module passes. At 05:49 UTC the new checkpoint contained
13/59 passing modules across unit-fast, all source/manifest matched, and no
group had yet been credited. Two further short modules passed by 05:54 UTC,
raising the current checkpoint to 15/59. Available RAM fell below 200 MiB
with swap full, so longer modules were deferred.

At 06:17 UTC, the remaining four `unit-fast` modules passed: policy (13 tests),
skills (14), postMessage static (16), and exposure static (9). All 19 modules
in that group now have current-source passes. The API GraphQL module passed 18
tests at 06:18 UTC, raising the checkpoint to 20/59. The next API runtime
module remained CPU-active near 100 MiB RSS but completed only one visible
test over several minutes during severe host contention. It was interrupted
with exit 130, its child was reaped, and no API runtime pass was credited.
The source-bound checkpoint still contains one complete group and no failed
module result. Resume the remaining modules when host contention permits.

By 06:39 UTC, six additional current-source `store-migrations` modules passed:
backup (59 tests), retention (58), maintenance (14), finding-Evidence hold (8),
profile retention (14), and ResearchBrief retention (12). The checkpoint is
26/59 modules with no failed module record; `store-migrations` is not yet a
complete group. These fixture passes do not substitute for a fresh verified
production backup or the controlled schema-46 rollout.

By 07:34 UTC, seven more current-source `store-migrations` modules passed:
Phase 12 (8 tests), DOM XSS store (9), identity registry (15), recon adapter
(17), auth (18), core store (33), and planner store (75). The checkpoint is
33/59 modules with `unit-fast` as its only complete group. The full
`test_object_factory.py` module failed after 12 passes: its recovery fixture
received `NEEDS_MANUAL_REVIEW` rather than `READY` for a new disposable object.
That exact test passed when rerun alone under the same source, so the cause is
not yet established; host contention or test-order sensitivity are possible.
No ObjectFactory module pass was credited. The store/migrations group still
requires clean full-module passes for ObjectFactory and TrafficStore. The API
runtime module also remains uncredited after its earlier clean interruption.

By 08:13 UTC, `test_traffic.py` passed all 32 tests and `test_api_specialist.py`
passed all 24 tests on the same source fingerprint. The checkpoint is 35/59;
TrafficStore is no longer outstanding, so ObjectFactory alone prevents the
`store-migrations` group from completing. The previously failing ObjectFactory
recovery test also passed when run immediately after its collected predecessor
(2 tests passed). This narrows but does not resolve whether the full-module
failure was load-sensitive or caused by an earlier test. The full ObjectFactory
module remains uncredited, as does the interrupted API runtime module.

By 08:47 UTC, a second low-priority full `test_api_runtime.py` attempt was
interrupted cleanly after its first test passed but the next test remained
CPU-active for several minutes under load above 12 on two CPUs. The child was
reaped and no module credit was recorded. A separate low-priority
`test_behaviour.py` run passed seven tests, then failed
`test_response_object_hints_are_hashed_and_not_ownership_facts`: the learned
profile contained zero response-metadata object hints instead of one. That
test took 306 seconds; the learner has a 90-second duration budget, so host
contention is a plausible explanation, not a confirmed diagnosis. The
behaviour module remained uncredited at that point. No live rollout has begun.

By 09:18 UTC, the full `test_behaviour.py` module passed all 13 tests on the
same source fingerprint, after the single response-hint fixture completed
successfully in isolation with one observed traffic record. The full
`test_object_factory.py` module then passed all 16 tests, including the
previously failing recovery fixture. These runs raise the checkpoint to
37/59 modules and complete the 15-module `store-migrations` group alongside
`unit-fast`. The earlier failures were not reproduced at the lower observed
host load; this is evidence of load sensitivity, not a guarantee that future
runs cannot fail under contention. API runtime and seven matrix groups remain
incomplete.

At 09:27 UTC, `test_planner_multisurface.py` remained CPU-active during its
first case while unrelated host contention pushed one-minute load above 24
on two CPUs. The low-priority runner was interrupted with exit 130 and its
pytest child was reaped. No module pass was credited, and the 37/59
checkpoint remains valid for the unchanged source. Retry this module under
lower contention; do not interpret the interruption as a test failure.

At 09:28 UTC, a read-only live recheck found the block volume mounted with
56 GiB free, root with 76 GiB free, and BugHunter, Burp, and VNC services
active. SQLite integrity and foreign-key checks passed; live schema remains
34 while the staged build expects 46. Burp listeners 38080-38083 and noVNC
6901 were loopback-bound; the control socket and directory were mode 0700,
the database was 0600, and the checked state/artifact/profile/backup trees
contained no group/world-readable files. Burp runtime contained 475 files
with broader file modes, but its root directory was mode 0700; these were
not deleted or chmodded. `systemd-analyze verify` passed for the staged agent
unit, but its active process predates the rollout. Latest backup metadata
reported encrypted generation `20261016T183411Z-97fe1967` as `RECORDED` and
`LAST_VERIFIED`; interactive `backup list` without the service backup key
returned `unknown`/`unverified`, an expected access limitation rather than
proof of corruption. A fresh verified pre-migration backup remains required.

At 09:32 UTC, `test_typed_mutations.py` passed four tests and
`test_domxss_browser.py` passed three tests on the same source fingerprint.
The checkpoint is 39/59 modules, still with two complete groups. Other
fixture-heavy modules were deferred while one-minute load remained above 13
on two CPUs with swap full; the source tree and live services were unchanged.

A read-only `hackbot storage check` at 05:50 UTC reported a 1,753,088-byte
live database, SQLite journal mode `DELETE`, `integrity_ok=true`,
`foreign_keys_ok=true`, and `SCHEMA_MISMATCH` for actual 34 versus expected 46.
Its exit code 2 is expected before the controlled migration; this check did
not write to the database. The current-source checkpoint was re-read after
the module selections and matched its manifest and source fingerprint.

At 12:18 UTC on 2026-10-17, the source-bound matrix is still incomplete. A
planner multisurface fixture exhausted its default five-minute run budget
under heavy host contention; two test-only planner limits were raised to 1800
seconds, leaving production limits unchanged. The ensuing checkpoint reached
31/59 modules before `test_object_factory.py` intermittently returned
`NEEDS_MANUAL_REVIEW` during local create/read-back tests. The failed cases
passed in isolated replay, and a successful direct replay took 86 seconds
end to end while the fixture allowed only 20 seconds per executor action.
The ObjectFactory test fixture now allows 120 seconds overall and 15 seconds
for connect/read; production executor settings are unchanged. All 16 tests in
that module passed in 22:57 after this adjustment. The latest checkpoint is
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-fixture-stability-20261017T1200Z.json`,
fingerprint `c8463863261892f8ac6c97093837df3c4e9f6d3001301504da92d353f2ff1fa0`,
with only 1/59 modules credited on the current source. No nine-group result,
fresh pre-rollout backup, or live schema-46 rollout has been completed. The
running production service remains on schema 34.

By 13:21 UTC on 2026-10-17, the next source-bound pass had reached 34/59
modules with `unit-fast` and `store-migrations` complete. The
`service-gateway` group then passed all 48 `test_service.py` cases, but a
local fixture request timed out in `test_phase29.py` after 21 passing cases.
Its isolated failing case passed. The composed Validator fixture's overall
executor budget was widened from 30 to the existing configuration maximum
of 120 seconds; production executor settings were not changed. Under two-CPU
host load above 13, another full Phase 29 attempt timed out after nine cases
at nice level 5. A direct diagnostic at normal priority showed four local
authorization actions reaching the fixture server and completing in 62.5,
19.9, 18.3, and 19.4 seconds. CPU starvation is therefore a material
test-environment cause, not proof of a report-rendering regression. A later
normal-priority run received an external `SIGTERM` after 21 cases; its pytest
child was reaped. The current full Phase 29 module is running in the
dedicated `bughunter-phase30-verify` tmux session against checkpoint
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-normal-priority-20261017T1535Z.json`.
It has not yet produced a passing module result. The live schema-34 service
was not restarted or migrated, and these fixture runs sent no bounty-target
requests or production recon writes.

At 17:07 UTC, the same Phase 29 tmux run remained live and CPU-active; its
module had not finished, so no current-source matrix credit was added. A
read-only review of `BackupManager` confirmed use of SQLite's backup API,
snapshot integrity and reference checks, and private staging under the backup
root. A read-only review of the 13 direct `logger`/`logging` call sites in
`src/hackbot` found event names and identifiers rather than credential or
evidence bodies. This is a partial source audit, not completion of the
cross-module secret/redaction or backup acceptance gates.

At 17:10 UTC, read-only listener and permission checks still showed Burp
38080-38083 and noVNC 6901 bound to loopback, `/run/bughunter-agent` and its
`control.sock` at mode 0700, and the block volume mounted at
`/mnt/volume_sfo2_1788290659423`. The SQLite file was mode 0600. A bounded
permission scan found no group- or world-readable files under the BugHunter
state, artifact, backup, and browser-profile trees. These are current live
pre-rollout observations for gates 17-19; recheck after any service rollout.

At 18:22 UTC, the source-bound `test_phase29.py` module passed all 30 cases
in 6704.13 seconds. Its slowest GraphQL report fixture took 1227.85 seconds
under the host's sustained two-CPU load. The checkpoint at
`/root/codex_artifacts/bughunter-agent/test-matrix/phase30-schema46-normal-priority-20261017T1535Z.json`
records that one passing module for fingerprint `8c54ac1241ece0f923c646506de2bbdc9859db89b190fd4f8441347c5eca4561`.
The detached `bughunter-phase30-matrix` tmux session is now running the full
59-module matrix against the same checkpoint and source. No production
migration, service restart, bounty-target request, or recon write accompanied
the local fixture run.

At 18:30 UTC, the full-matrix runner completed all 19 `unit-fast` modules
with exit code 0, bringing the current-source checkpoint to 20/59 modules
including Phase 29. It then entered `store-migrations`. This remains a partial
matrix result, not Phase 30 acceptance or permission to migrate production.

At 22:17 UTC, the source-bound checkpoint records 35/59 passing modules.
`store-migrations/test_research_retention.py` failed one of seven cases:
`test_planner_context_event_holds_brief_and_rejects_late_link` expected a
second research brief to be eligible for retirement, but the fixture's
`_brief()` returned `None`. The research coordinator and manual provider both
honor a 20-second request deadline, so host contention may have exhausted the
fixture budget; this has not yet been confirmed by isolated replay. The
matrix runner is still live in `bughunter-phase30-matrix` and has proceeded
through `api-specialists/test_api_graphql.py` (18 passed) into
`api-specialists/test_api_runtime.py`. The failed module must be rerun and the
full source-bound matrix must pass before any rollout. The live service remains
on schema 34; no production migration or restart has occurred.

At 22:22 UTC, a read-only live recheck found `bughunter-agent.service`,
`bughunter-burp.service`, and `bughunter-vnc.service` active. Burp listeners
38080-38083 and noVNC 6901 were bound to loopback; VNC itself used a Unix
socket under the BugHunter-owned service cgroup. The control socket and its
parent directory were mode 0700. `/root/codex_artifacts` still resolved to
the block volume, with about 51 GiB available; root had about 76 GiB
available. RAM availability was about 2 GiB with the 4 GiB swap nearly full.
The live agent still ran as root, with least-privilege migration deferred as
documented. These observations are pre-rollout only and must be rechecked
after the schema-46 deployment.

At 22:29 UTC, `api-specialists/test_api_runtime.py` stopped after 10 passes
and one setup failure in 8973.79 seconds. The failing case,
`test_nested_field_proof_rejects_independent_foreign_object`, received
`EXECUTION_FAILED` while creating its controlled actor-owned object; it did
not reach its authorization assertion. The shared authorization fixture uses
30-second read and 120-second overall executor limits. This result is not a
product authorization failure, but its exact executor error has not yet been
captured. An isolated replay is required after the current matrix releases
its checkpoint lock. The runner remained live and advanced to the
`authorization-specialists` group. At the same time, the VPS briefly showed
one-minute load above 230 on two CPUs, with nearly full swap; a later
read-only check showed load falling but still high. Do not alter recon or
other unrelated processes to clear this test failure.

At 23:01 UTC, the failed matrix was deliberately interrupted and its pytest
child reaped after a measured schema-46 connection regression was found. The
old schema-34 production database had 44 triggers and about 76 KB of schema
SQL; the original schema-46 fixture had 770 triggers and about 2.37 MB of
schema SQL. Fresh read-only connection/query CPU time was about 0.003 seconds
against schema 34 versus 0.12-0.16 seconds against the original schema 46.
A five-second syscall sample showed thousands of SQLite reads but only about
0.007 seconds in syscalls, consistent with schema parsing/statement CPU cost.
The schema-derived DOM guards and Evidence/Traffic JSON reference indexes now
use compact per-row JSON documents while preserving every inventoried source
column, duplicate counts, invalid-JSON rejection, and late-link checks. The
resulting schema-46 fixture has about 1.09 MB of schema SQL; fresh connection
CPU time remained 0.055-0.08 seconds, so the store now keeps one idle SQLite
connection per thread, using fresh connections for nested work and discarding
cached connections on error, migration, schema mismatch, process change, or
database-file replacement. A 100-operation cached fixture took about 0.058
CPU seconds.

On fingerprint `f92bf49b613a7573bba16e696794f145789817d661aa47860b85c7c095e4b783`,
focused modules passed: store 36/36 in 69.81 seconds, retention 59/59 in
86.28 seconds, backup 59/59 in 122.47 seconds, traffic 32/32 in 77.91
seconds, research retention 12/12 in 19.44 seconds, and API runtime 45/45 in
606.16 seconds. The two cases that failed on the old source passed on this
source. These focused results do not replace the mandatory complete 59-module
matrix or the controlled production migration and post-rollout checks.

At 2026-10-17 23:00 UTC, a separate SQLite concurrency probe found that an
unfinished SELECT cursor retained by the idle cache blocked a second writer
(`OperationalError: database is locked`). The first compact-cache matrix was
stopped intentionally; its partial checkpoint is not acceptance evidence.
Store connections now track and close all cursors before becoming idle, while
preserving nested-connection isolation and error rollback. A two-row,
partially consumed SELECT regression test verifies a separate SQLite writer
can commit after the store context exits. Current-source store and retention
suites passed 96/96 tests in 156.08 seconds. A fresh source-bound matrix is
running from `phase30-schema46-cursor-safe-20261018T0000Z.json` at fingerprint
`e2d1b93588a11733d8ab16486da1715e3fbd218fe98a72695c36bf21a66d452e`.
No production service or schema change accompanied this correction.

At 23:14 UTC, the final-source matrix completed the 19-module `unit-fast`
group and entered `store-migrations`. An encrypted production backup,
`20261017T231359Z-fa2a711b`, was created from the live schema-34 SQLite
database and independently verified (48 files, `verified=true`). The backup
was then restored and migrated in an isolated private stage to schema 46:
`integrity=OK`, JSON reference audit matched after scanning 268 values, and
all 80 Evidence rows were preserved. The rehearsal reported
`active_state_replaced=false`. This is the required pre-rollout recovery
point, not a production migration. A post-rollout backup and live checks still
remain after the complete matrix passes.

A fresh pre-rollout audit found `bughunter-agent.service` active with zero
restarts, the control socket and its runtime directory at mode 0700, the
schema-34 SQLite database at mode 0600, and Burp/VNC listeners on loopback.
`hackbot storage check` reported `integrity_ok=true` and
`foreign_keys_ok=true`; its `SCHEMA_MISMATCH` exit 2 is expected because the
live store is 34 and current source expects 46. The backup key, recon
environment, bridge token, and application config files are mode 0600.
Across state, artifacts, backups, browser profiles, and target-package trees,
no regular file was group/world-readable. A static review of the current
structured logger calls and CLI error paths found only bounded IDs/counts or
generic error labels, not raw requests, response bodies, or exception text.
This does not replace post-rollout runtime redaction and permissions checks.

The next source-bound matrix reached 26 passing modules before
`store-migrations/test_traffic.py` exposed a same-context DDL regression:
strong cursor tracking kept a finished temporary SELECT alive, so SQLite
rejected `DROP TABLE foreign_exchange_ref` with `database table is locked`.
The runner was stopped and its child reaped; none of that checkpoint counts
toward final acceptance. Cursor tracking now uses weak references: abandoned
temporary cursors can finalize normally, while still-referenced unfinished
cursors are explicitly closed before an idle connection is reused. The
external-writer regression, new same-context DDL regression, and original
Burp-index case passed together. The affected store, traffic, and retention
suites then passed 129/129 tests in 302.77 seconds. Current source fingerprint
is `cb98417cbfbc2751eb35358c5a5e9b8fb4c50bf5e642fea46e7c91e68b721774`.
The verified encrypted pre-rollout backup remains usable; no production
schema or service change occurred.

The fresh matrix checkpoint `phase30-schema46-weak-cursors-20261017T2333Z.json`
is bound to that current fingerprint. Under the same source, encrypted backup
`20261017T231359Z-fa2a711b` independently verified again, and its isolated
schema-34-to-46 rehearsal again reported `integrity=OK`, matching JSON
reference audit, all 80 Evidence rows preserved, and
`active_state_replaced=false`. The production service has not been restarted.

The current source-bound matrix then completed `unit-fast` (19 modules) and
passed `store-migrations/test_store.py` (38 tests), `test_backup.py` (59),
`test_retention.py` (59), and `test_traffic.py` (32). The latter includes the
Burp-index same-context DDL case that failed under strong cursor tracking.
These module passes validate the weak-reference correction in the matrix.
The run subsequently completed all 15 `store-migrations` modules, bringing
the current fingerprint to 34/59 passing modules with `unit-fast` and
`store-migrations` fully credited. The other seven groups and live rollout
checks remain open.

On 2026-10-18, `api-specialists/test_api_runtime.py` passed all 45 tests on
the current source-bound matrix in 1930.68 seconds. Two no-output warnings
reported 4,833 and 4,140 pytest CPU ticks; a read-only stack sample showed
local authorization/Evidence SQLite work, and test output resumed afterward.
The slowest five cases took 146-219 seconds under host contention. The API
group subsequently passed all three assigned modules and is credited on the
same source fingerprint. Six groups and live rollout checks remain open.

At 00:30 UTC, the live BugHunter TOML still lacked `resources.required_mount`
despite the systemd mount dependency. The setting was added for
`/mnt/volume_sfo2_1788290659423` without restarting the running service.
`storage status` then parsed the config and reported the mounted block volume,
and encrypted backup `20261017T231359Z-fa2a711b` verified again. The TOML
remained mode 0600. A missing-mount fixture already covers fail-closed
admission; the actual mount was not unmounted for testing. The active service
will load this setting only after the controlled rollout restart.

At 01:16 UTC on 2026-10-18, the source-bound nine-group matrix finished with
59/59 assigned modules, `complete=true`, and `passed=true` on fingerprint
`cb98417cbfbc2751eb35358c5a5e9b8fb4c50bf5e642fea46e7c91e68b721774`.
The optional local Playwright Chromium isolation smoke, skipped by the matrix
because no binary was explicitly configured, also passed 1/1 with the installed
local browser. This is a prior-source matrix after the later unit/test edit.

Before migration, encrypted generation `20261018T011827Z-6d775eae` was
created from the live schema-34 service, verified, and rehearsed privately to
schema 46 with all 80 Evidence rows preserved, integrity OK, and matching
268-value JSON-reference audit. Both CPU load thresholds (4.0 high, 8.0
critical per available CPU) were configured. Only `bughunter-agent.service`
was stopped; the stopped database was copied into a mode-0700 quarantine with
a byte-identical SHA-256 and mode-0600 file. No other process held the database.
The reviewed migration reached schema 46, and `storage check` reported
integrity and foreign keys OK with zero missing core tables. The agent was
started under the hardened unit; `/v1/health` returned `ok`, `/v1/ready`
returned `READY` before a later high-load sample, the socket and runtime
directory remained 0700, and the state database remained 0600. A schema-46
encrypted generation `20261018T012516Z-d9e8edd3` was created, verified,
rehearsed privately, and audited with zero mismatches across 268 JSON values.

Live Operations initially reported Burp storage `UNAVAILABLE`: the config
omitted its runtime root. Adding the actual root made the standalone CLI scan
complete (585 entries, about 703 MB), but the hardened service still cannot
traverse the Burp-owned mode-0700 directory without DAC-bypass capabilities.
This remains an explicit degraded telemetry limitation; Burp itself reports
available. No Burp runtime permissions or capability bounds were loosened to
make the warning disappear.

The first controlled service stop replaced `/run/bughunter-agent`, leaving the
dashboard container bind-mounted to an old empty directory. Authenticated
Operations API calls returned 503 even though the private socket was healthy.
`RuntimeDirectoryPreserve=yes` was added to the source and installed unit, with
a unit regression assertion; the focused three-test module and
`systemd-analyze verify` passed. After `daemon-reload`, a BugHunter-only restart
preserved the runtime-directory inode. A dashboard-only restart remounted the
current directory; live authenticated panel and Operations API returned 200,
an unauthenticated panel redirected to login, and a CSRF-less maintenance POST
returned 403. This unit/test change produced fingerprint
`ae47ef41abbc523fe8677be7a70558545419db24510703c2454ceb7937380e15`.
The full matrix must pass again on that fingerprint before final acceptance.

## Final verification on 2026-10-18

The current-source `verify_all.py` run completed at 02:27 UTC on fingerprint
`ae47ef41abbc523fe8677be7a70558545419db24510703c2454ceb7937380e15`:
59 of 59 assigned test modules and all nine required groups passed, with
`complete=true`, `passed=true`, and zero failed modules. The configured local
Chromium integration test ran and passed. A second source-bound invocation
reused the same checkpoint and returned the same combined result.

The live schema-46 store again passed integrity and foreign-key checks with
zero missing core tables. The retention dry-run scanned 47 artifact records
and found zero deletion candidates. Encrypted backup
`20261018T012516Z-d9e8edd3` verified with 48 files; its isolated rehearsal
reported `active_state_replaced=false`, 80 Evidence rows preserved, and 268
JSON-reference values matching. No production restore or live retention
deletion was performed.

The agent remained active with zero restarts and no active plans, browsers,
or cleanup-pending objects. Its control socket and runtime directory were
mode 0700, the database and private configuration/secret files mode 0600,
and BugHunter Burp/VNC listeners remained loopback-bound. The effective unit
has `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome=read-only`, empty capabilities, CPU weight, and memory/task caps.
An exact-value scan found no configured backup, recon, or Burp bridge secrets
in BugHunter/Burp journals, Operations JSON, or seven backup manifests.

Resource readiness temporarily became `DEGRADED` or `BLOCKED` under unrelated
shared-VPS high load, while storage, Burp, and recon checks stayed healthy.
Operations still reports `BURP_STORAGE_INVENTORY_INCOMPLETE` because the agent
cannot traverse Burp's private runtime without broader filesystem authority;
the standalone Burp-owner inventory works. Backups remain on the same block
volume as live state, so an off-host copy and separately escrowed key remain
operator disaster-recovery tasks. These limitations are explicit in the
operator runbook and do not enable autonomous Phase 31/32 work.
