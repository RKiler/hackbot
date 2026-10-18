# BugHunter Operations Runbook (Phase 30 draft)

BugHunter is a private, standalone service. Do not use these commands on the
production recon PostgreSQL database, and do not infer target-testing authority
from a successful health check. Run commands from `/root/bughunter-agent`.

## Routine checks

1. Check `systemctl status bughunter-agent.service bughunter-burp.service`.
2. Run `.venv/bin/hackbot --config /root/.config/bughunter-agent/config.toml storage status`.
   Run `storage check` separately for a read-only SQLite integrity and schema
   inspection. A nonzero exit means corruption, broken references, an incomplete
   schema, or a version mismatch; inspect the JSON state before recovery.
3. Once the new control-plane build is deployed, run the same CLI with `ops status`.
   Check private `/v1/health` for liveness and `/v1/ready` for local readiness;
   optional recon failure degrades readiness but does not return 503.
4. Review the authenticated `/hackbot/operations` page for disk, schema,
   Burp, notification, object-cleanup, and backup warnings.
5. Check `journalctl -u bughunter-agent.service --since today` without copying
   secrets or Evidence bodies into tickets. The repository unit stages a
   300-message/30-second rate limit, but the live unit has not adopted it.
   Check `systemctl show bughunter-agent.service -p LogRateLimitIntervalUSec
   -p LogRateLimitBurst` after deployment. This limits bursts, not total journal
   size. The shared VPS journal policy is
   `deploy/journald/90-vps-journal-budget.conf`, installed at the same name
   under `/etc/systemd/journald.conf.d/`: 4 GiB persistent, 512 MiB runtime,
   and 10 GiB root free-space reserve. It can eventually evict older logs from
   any service, including recon; it does not impose a fixed age cutoff. Check
   `journalctl --disk-usage` and `systemd-analyze cat-config
   systemd/journald.conf` after journald restarts. Roll back by removing only
   this drop-in and restarting journald; do not vacuum logs as part of rollback.
   The previous VNC process left four operational logs under
   `browser-vnc/`. `/etc/logrotate.d/bughunter-vnc` checks only those files
   through the daily timer and rotates weekly or when they exceed 10 MiB,
   retaining four compressed generations. A file can exceed 10 MiB between
   timer runs; `logrotate.timer` must remain active for legacy logs. The
   deployed launcher now sends child output to journald. On 2026-10-16 a
   VNC-only restart was performed after confirming no connected client,
   agent-owned browser process, or active browser-session row. Do not restart
   the visible display during an operator login. After future restarts,
   verify journal capture and that the old file logs stop growing;
   do not delete old logs without a separate retention review.
   An Operations `SUSPECTED_DISPLAY_ORPHAN` warning means an unexpected
   agent-cgroup display process remains without an active browser session,
   or the VNC endpoint is unavailable while its service cgroup still owns
   display processes. Inspect exact BugHunter cgroups and session state;
   do not kill an unrelated browser or infer that the persistent VNC display
   is itself an orphan.

The configured backup key is supplied through the root-owned service
environment file. For an interactive backup command, load that file into the
process environment without printing it. Do not put the key in shell history,
chat, a report, or a backup archive. Escrow the key separately from the VPS.
An encrypted generation can appear `unverified` in `backup list` when an
interactive CLI lacks this key. Run `backup verify` with the service key
available before treating that status as corruption; never display the key.

The production `[resources].required_mount` is set to the block-volume mount
path (currently
`/mnt/volume_sfo2_1788290659423`) and ensure the service starts only after
that mount is available. The root path must resolve under it. A missing mount
then fails startup before SQLite is opened and blocks new heavy work if lost
later. The Evidence artifact root must also resolve under the mount; otherwise
startup fails with `ARTIFACT_STORAGE_OUTSIDE_REQUIRED_MOUNT`. Verify both paths
after any restart. Do not omit the check merely because the root disk has
spare space.
The installed BugHunter unit has a read-only `storage startup-check`
`ExecCondition`. The live SQLite store and source are now both schema 46. A
future mismatch returns `MIGRATION_REQUIRED` and skips startup without touching
the database. If the dashboard is unavailable, inspect
`systemctl status bughunter-agent.service` and run the read-only startup check.
After the schema-46 rollout, `RuntimeDirectoryPreserve=yes` keeps the private
`/run/bughunter-agent` directory inode stable across service restarts. The
dashboard container bind-mounts this directory, so a one-time dashboard-only
restart was required after the earlier directory replacement. If authenticated
`/api/hackbot/operations` returns 503 while the private socket is healthy,
compare the socket inside that container before restarting any service.
The production unit separately requires its block-backed SQLite file to exist;
if it is missing, restore and verify the state rather than allowing the service
to create an empty replacement database.
The Burp runtime's persistent `data/burpbrowser` directory used about 668 MiB
on 2026-10-16. Monitor its size with `du -sh` during capacity reviews; it is
not a launcher-created `community-*` temporary project and is excluded from
automatic cleanup. Do not remove it without separately verifying Burp's
embedded-browser recovery behavior and preserving capture service availability.
Run `hackbot burp storage` for a bounded, path-free logical-byte inventory of
the runtime. `COMPLETE` means the scanner visited every regular entry within
its entry/time limits; `PARTIAL` and `UNAVAILABLE` do not prove a low disk
footprint. Operations reports the same aggregate under `burp_storage` and
degrades that component if the inventory is incomplete. These numbers are
monitoring data, not a list of files eligible for deletion.
For any future schema migration, do not remove the condition or opt into live
migration until a verified encrypted backup, isolated upgrade rehearsal,
complete source-bound test matrix, rollback plan, and controlled outage are
ready. Preserve the original database and confirm its integrity afterward.
Ordinary CLI, identity-registry, traffic, and service initialization refuses
an existing schema mismatch; the backup rehearsal opts in only for its
verified private restore stage.
The live configuration has `high_load_per_cpu = 4.0` and
`critical_load_per_cpu = 8.0` in `[resources]`. Verify `load_per_cpu` and any
`HIGH_LOAD`/`CRITICAL_LOAD` warning in Operations. These paired limits defer
new heavy work; they must not block backup, cleanup, or operator access.

The live SQLite schema was 34 at the October 15 inventory and was migrated to
46 during the October 18 controlled outage. The fresh encrypted pre-migration
generation `20261018T011827Z-6d775eae` was verified and rehearsed to schema
46; the stopped database was also preserved in a private, byte-matched
quarantine. The migrated database passed integrity and foreign-key checks and
retained all 80 Evidence rows. A new schema-46 generation
`20261018T012516Z-d9e8edd3` passed verification, isolated rehearsal, and the
268-value JSON-reference-index audit. Schema 39 adds indexed digest lookups used by
artifact cleanup and backup selection; schema 40 pins all Evidence used by
Finding-linked validations, schema 41 adds standalone Evidence retirement,
schema 42 adds reviewed TrafficStore payload retirement with late-link guards,
schema 43 adds a backfilled, trigger-maintained JSON traffic-reference index,
schema 44 adds the corresponding Evidence-ID index, schema 45 adds reviewed
ResearchBrief cache retirement with late-link guards, and schema 46 adds
schema-derived guards for retired DOM asset generations.
An invalid pre-existing JSON column blocks the schema-43/44 index migrations
without advancing the schema; review the affected local row on a backed-up
copy. Schema 45 also parses existing planner candidate and event reference JSON.
Do not migrate the active database merely to run a health check.
The active unit contains `ProtectHome=read-only`, an empty capability set, and
a write exception for the block-backed BugHunter directory. It was reloaded
and restarted after the migration; verify active restrictions again after
future unit changes with `systemd-analyze verify` and `systemctl daemon-reload`.
Check that
the control socket, browser profile, Burp bridge, and block-storage writes
work under the active restrictions; do not assume `ProtectSystem=strict` alone
makes `/root` read-only on this VPS.

## Backup and retention

- `hackbot backup create`: online SQLite snapshot and artifact manifest;
  encrypted in production, then verified. An unencrypted generation is rejected
  when any `SECRET` Evidence row exists, even if the smaller artifact policy
  would omit its body; the SQLite snapshot still contains its metadata. The
  verifier also rejects a plaintext generation in this state. Creation refuses
  to start when the backup filesystem cannot hold the snapshot plus its free
  space reserve, and rechecks selected artifact sizes before copying. For an
  encrypted generation it also reserves space for the full plaintext
  verification copy. The new generation is verified in private staging before
  it is published. Encrypted `backup verify` and any `backup stage` also check
  expected materialized size plus working allowance before decrypting/copying.
  GnuPG additionally limits each decrypted file to its manifest plaintext size;
  failures remove partial output. A corrupt or underreported manifest must be
  treated as an invalid generation, not retried without review.
  A concurrent disk fill can still cause a safe abort; review free space and
  incomplete staging before retrying. Failed attempts are recorded in the
  private backup maintenance audit with an error class, not raw error text.
- `hackbot backup list`: bounded inventory; an item marked unverified or
  invalid needs operator review.
- `hackbot backup verify <backup-id>`: dry-run integrity verification and
  last-verified timestamp; no active-state replacement.
- `hackbot backup audit-json-indexes <backup-id>`: on a verified schema-44
  generation, independently decode all JSON reference columns in a private
  staged copy and compare exact Evidence/Traffic ID counts with the derived
  indexes. It reports only counts, never referenced IDs, and removes the stage
  afterward. A mismatch exits nonzero; a row, ID, JSON-size, or time limit
  exits incomplete. The default cap is 250,000 JSON-column values and 60
  seconds; `--max-values` and `--max-seconds` allow a bounded larger audit.
  Run this after creating a current-schema backup, not against live SQLite.
- `hackbot backup rehearse <backup-id>`: verify and migrate a private restore
  stage, check SQLite integrity and key record counts, then independently
  compare all source JSON references with the schema-44 Evidence and Traffic
  indexes. A mismatch or audit limit fails the rehearsal and the decrypted
  stage is removed. Use `--max-values` and `--max-seconds` only to raise bounded
  limits when a complete audit would otherwise stop as incomplete. This does
  not replace or migrate the active database.
- A current manifest with `artifact_selection_version: 4` includes
  Finding-linked validation controls and contradictions, including related
  duplicate validations. `ALL` also omits only retired Evidence or TrafficStore
  payloads whose blobs have no other live digest owner. Legacy versions 1-3
  verify under their
  original selection rules. Make and verify a new generation
  before treating legacy `FINDING_LINKED` backups as complete recovery copies.
- `hackbot backup prune-plan`: review generations beyond the configured count.
- `hackbot backup prune --confirmed`: delete only older completed generations
  after every completed generation verifies and at least one retained
  generation remains. A malformed or corrupt generation blocks pruning for
  operator review; do not delete it manually merely to clear the error.
  Verification can be slow for artifact-heavy generations. Never prune the
  only usable backup.
- `hackbot backup incomplete-plan`: preview unfinished `.pending-*` backup
  directories older than 24 hours. These may contain plaintext state.
- `hackbot backup incomplete-cleanup --confirmed`: remove only the reviewed,
  stale unfinished generations. The command rejects symlinks and never selects
  completed backups or recent in-progress staging.
- `hackbot retention plan`: preview aged, physically unreferenced Evidence
  blobs, abandoned artifact temporary files, and estimated bytes; this does
  not expire Evidence or Traffic rows. If `truncated` is true, subsequent plans
  continue from a durable scan cursor; a plan with no candidates can still
  advance that cursor. The cursor lives in BugHunter's private state directory.
- `hackbot retention run --confirmed`: require a dry-run review from the last
  15 minutes and perform only its still-eligible candidates. A successful run
  consumes the review; make a new plan before another cleanup.
  If the audit log has STARTED without COMPLETED, treat the outcome as
  ambiguous and inspect the artifact store before retrying.
- `hackbot retention evidence-plan`: review a bounded set of old, explicitly
  expired or non-retained, standalone artifact-backed Evidence payloads.
  Pinned, finding-related, secret, and referenced Evidence is excluded.
- `hackbot retention evidence-run --confirmed`: recheck only the recent reviewed
  IDs and append retirement markers. It does not unlink bytes. Run the
  ordinary `retention plan` and `retention run --confirmed` separately after
  inspecting the orphan candidates. A shared digest is never collected while
  another live owner remains. The live store was migrated to schema 46 on
  2026-10-18; review the plan and backup state before any confirmed run.

- New DOM-owned and controlled-HTTP JS and source-map asset Evidence has configurable expiry in
  `[retention].js_artifact_hours` and `source_map_hours` (2160 hours each by
  default). Existing rows, exposure captures, and TrafficStore request/response
  Evidence are unchanged. `hackbot retention dom-plan --kind JS` or
  `--kind SOURCE_MAP` provides bounded eligibility review and stores one
  private 15-minute review; use `--after <next_after>` to continue a truncated
  page. `hackbot retention dom-run --kind JS|SOURCE_MAP --confirmed` rechecks
  only that reviewed kind and exact Evidence/digest tuples, then logically
  retires still-eligible Evidence. The command does not delete blobs. The live
  store is now schema 46; review the plan before any confirmed run. After
  logical retirement, run the separate ordinary
  `retention plan` and `retention run --confirmed` to reclaim only an aged,
  reviewed blob with no other owner or reference. A shared digest remains held;
  never manually remove a digest because its expiry or retirement marker has
  passed. Schema-46 guards reject late DOM-ID links while an owner's current
  Evidence is retired. Active cache reads skip retired Evidence; a fresh exact
  same-hash retrieval can restore the blob and attach new Evidence while
  preserving the old marker. Legacy schema-45 backups still include DOM bytes.

- `hackbot retention research-plan`: review expired ResearchBrief cache payloads
  after `research_brief_grace_days` (30 by default). Linked briefs are held;
  the output estimates logical JSON bytes, not immediate disk savings.
- `hackbot retention research-run --confirmed`: within 15 minutes of the plan,
  recheck its brief IDs, payload hashes, sizes, and references, then retire only
  still-unlinked advisory JSON. Brief,
  request, version, and source metadata remain; new links to a retired brief
  are rejected. A new research request may produce the next cache version.
  This command is not scheduled; the live store was migrated to schema 46 on
  2026-10-18. Review the plan before any confirmed run.

- `hackbot retention traffic-plan`: review a bounded set of expired, terminal
  traffic exchanges. The plan excludes finding/policy holds, outside Evidence
  links, and exchange/request/response references. Candidate bytes are an
  upper bound; no data is removed by this command.
- `hackbot retention traffic-run --confirmed`: within 15 minutes of that
  review, recheck the same exchanges and retire their linked Evidence payloads
  atomically. Traffic metadata remains. An incomplete reference check fails
  closed. This does not unlink physical blobs.
- To reclaim bytes, make a new `hackbot retention plan` and separately run
  `hackbot retention run --confirmed` after inspecting its digest candidates.
  Shared blobs and late references remain protected. A single complete Burp
  capture index with an exact target/provider/capture linkage is retained as
  retry metadata, not a payload hold; duplicate or inconsistent indexes still
  block retirement. Late bridge retries of retired captures are rejected.
  Burp project/history files are not removed by these commands and require
  separate operator review. The live store is now schema 46; review the plan
  and backup state before any confirmed retirement run.
- `hackbot burp temp-plan` reviews only old launcher-created
  `burp-runtime/tmp/community-*` directories and records a private 15-minute
  review. `hackbot burp temp-run <review-id> --confirmed` requires Burp stopped
  and no matching runtime process; it rechecks every reviewed tree and writes
  a private audit record. It never removes the active in-memory project,
  `burp-runtime/data`, generic Burp temp names, or canonical TrafficStore
  Evidence. Plan while Burp runs if needed, but schedule any cleanup as a
  capture outage and restart Burp manually afterward.

The authenticated Operations view has a separate anonymous-profile dry run
and cleanup action. It is not part of the CLI artifact collector. Review the
profile count and bytes, confirm the profile-specific checkbox, then run the
action. A process inventory that cannot prove no BugHunter-owned browser is
running blocks this action; do not bypass it by deleting profile directories
manually. Authenticated profiles are never selected automatically.

For an identity intentionally disabled for at least seven days, an operator
can separately review its old terminal profiles through the private control
socket. Run `hackbot ops disabled-profile-plan TARGET_ID IDENTITY_ID`, then
poll `hackbot ops maintenance-status` until the task completes and inspect
candidate count and estimated bytes. Run
`hackbot ops disabled-profile-run TARGET_ID IDENTITY_ID REVIEW_ID --confirmed`
with the same IDs and the completed plan task's ID. The review is one-use and expires after
15 minutes or process restart. This is not automatic; re-enabled identities,
active target work, unresolved disposable objects, and uncertain browser
process ownership block deletion. Keep profiles of active identities by
default, even when a session has expired. For an explicitly selected
active-identity session that has been terminal and unused for at least 30 days,
run `hackbot ops named-profile-plan TARGET_ID IDENTITY_ID SESSION_ID`, poll
`hackbot ops maintenance-status`, and inspect the one-session candidate and
estimated bytes. Then run
`hackbot ops named-profile-run TARGET_ID IDENTITY_ID SESSION_ID REVIEW_ID --confirmed`.
The review expires after 15 minutes or restart. A valid AuthContext still
bound to the session, active target work, a running browser, or uncertain
process ownership blocks deletion. This action preserves session metadata but
removes its local browser profile; verify the exact account and session before
confirming. Never bypass these gates with a manual filesystem delete.

All backup IDs are generated identifiers, not filesystem paths supplied by
the browser. Never run a recursive delete against active state or artifacts to
make room. Confirm the target mount with `findmnt -T` before assuming block
storage is present.

The maintenance UI runs one local action at a time and never accepts an
arbitrary path. Review a completed retention dry-run and check its explicit
confirmation before cleanup. The API requires that dry-run task's ID as the
`review_id` and accepts it once, within 15 minutes, in the same process.
Newly eligible items are excluded until another dry run. A task marked
`INTERRUPTED` after restart is not
replayed; inspect its audit record and physical state before retrying. Do not
run `VACUUM`, change SQLite journal mode, or force a checkpoint during active
work. The current rollback-journal database has no WAL to checkpoint.
Use `hackbot storage check` for bounded read-only integrity, foreign-key,
schema, journal, and free-page checks; compare database and free-page trends
before scheduling maintenance. The current database is small, so there is no
automatic `VACUUM`, `REINDEX`, or statistics rewrite. If measured query-plan
or fragmentation evidence warrants one, first create and verify an encrypted
backup, rehearse on an isolated copy, stop BugHunter for an operator-reviewed
maintenance window, and verify integrity and schema again before restart.
Never run these write-heavy operations merely to improve a health indicator.

## Isolated restore rehearsal

1. Verify the selected encrypted backup. A failed hash, missing key, schema
   mismatch, SQLite integrity failure, or foreign-key violation is a stop.
2. Run `hackbot backup rehearse <backup-id>` with the configured backup-key
   environment. It verifies and decrypts the generation, migrates only the
   staged SQLite copy to the current schema, checks integrity and foreign keys,
   compares critical record counts, and removes decrypted staging in a
   `finally` block. It never replaces active state.
3. For deeper manual inspection, use `hackbot backup stage <backup-id>` to
   create a private directory under `backups/restore-staging`. Inspect the
   manifest, references, and selected artifact hashes without exposing bodies.
   Remove only that exact staged directory when done; it contains plaintext
   sensitive material. Keep the encrypted generation.

A hard crash can leave a decrypted stage behind. `hackbot backup
restore-staging-plan` lists only stages older than 24 hours and their sizes.
After confirming that no restore inspection is still using one, run `hackbot
backup restore-staging-cleanup <exact-stage-name> --confirmed`. Fresh stages,
completed encrypted generations, unexpected filenames, and symlinks are not
removed by this command. It never runs automatically at startup.

## Production restore (manual, never one-click)

1. Obtain operator approval and record the recovery reason, chosen generation,
   observed schema, expected rollback state, and active disposable objects.
2. Stop `bughunter-agent.service`; do not stop recon or Burp unless separately
   required. Confirm the service's Unix socket is no longer serving requests.
3. Stage and verify the chosen backup as above. Preserve the current active DB
   and artifacts in a separately named, private quarantine on the block volume;
   do not overwrite them until the staging audit passes.
4. Copy the staged DB and selected artifact trees into a new private active
   directory, verify hashes and permissions, then atomically switch the
   BugHunter-owned paths according to an operator-approved maintenance plan.
   Never restore by copying a live SQLite file over another live file.
5. Start the service and check schema, health, operations, notification outbox,
   paused/ambiguous runs, BrowserSessions, Burp listener state, approvals,
   permits, and pending disposable-object cleanup. Do not automatically replay
   ambiguous target actions.
6. Keep the pre-restore quarantine until the operator confirms the recovered
   service and evidence. Remove the decrypted staging directory securely.

The current CLI deliberately stops at staged restore; production replacement
is manual. A same-volume backup cannot recover a lost block device, and a lost
GnuPG key makes encrypted backups unrecoverable.

## Degraded components

| Condition | First action | Safety rule |
| --- | --- | --- |
| Critical disk | Pause new heavy work; inspect `storage status` and retention dry-run | Preserve DB and linked Evidence; never blind-delete |
| Root filesystem low or critical | Inspect `system_disk_*` in `storage status` and journald usage; new heavy work is blocked at high/critical pressure | Do not mistake free block-volume space for root-disk headroom or prune unrelated logs blindly |
| DB corruption | Stop BugHunter and verify latest backup | Do not continue writes against a damaged schema |
| Burp unavailable | Check service and listener health | Capture-required traffic remains fail-closed |
| Browser/VNC unavailable | Check dedicated BugHunter-owned service/cgroup and profile state | Do not kill unrelated Chrome or recon processes |
| Recon unavailable | Keep existing local state usable | No fallback to recon writes or inferred scope |
| Research provider degraded | Review the last persisted local/external research attempt and its fixed error code; retry only the affected advisory request when the provider is available | Operations does not probe providers, and cached/local research remains advisory and usable |
| Notifier unavailable | Inspect persisted outbox and provider attempts | No blind resend of ambiguous sends |
| Orphan objects | Inspect object ledger and original account context | Cleanup requires original policy and manual review when ambiguous |

## Known limitations

- The Operations view reports Burp storage inventory as `UNAVAILABLE` when the
  hardened BugHunter service cannot traverse Burp's private runtime directory.
  Burp bridge availability is checked separately. Inspect storage as the Burp
  owner with `hackbot burp storage`; do not broaden service filesystem access
  solely to remove this warning.
- Encrypted backups currently reside on the same block volume as live state.
  Keep an independently escrowed key and an off-host copy for block-device
  failure recovery. A same-volume generation is not disaster recovery by itself.
- Production restore is deliberately manual after isolated verification and
  quarantine of the current store; there is no one-click live replacement.
- Retention and orphan-object cleanup require an operator-reviewed plan and
  explicit confirmation. They are not scheduled background deletion.
- The complete 59-module matrix may take a long time on this shared VPS.
  Resume only a source-matching checkpoint and confirm the final combined
  result; a passing segment is not complete coverage.

## Pre-Phase-31 checklist

For the final-source test matrix, keep the checkpoint on the mounted BugHunter
volume and invoke the runner without `--group`:

```bash
cd /root/bughunter-agent
.venv/bin/python scripts/verify_all.py \
  --resume-file /root/codex_artifacts/bughunter-agent/state/phase30-matrix.json
```

The runner checkpoints passing modules and completed groups. After interruption,
rerun the same command; a source, test, deployment-fixture, Python, dependency, or manifest
change refuses the old checkpoint. Start a new checkpoint file for the new
source and keep prior results only as historical evidence. The final
`MATRIX_RESULT` must report `complete=true` and `passed=true`; manifest-only
and individual-group passes do not satisfy the rollout gate. Do not launch
multiple runners against one checkpoint.

Under host contention, run one assigned module with the same checkpoint:

```bash
.venv/bin/python scripts/verify_all.py --module test_backup.py \
  --resume-file /root/codex_artifacts/bughunter-agent/state/phase30-matrix.json
```

The module pass is credited only for the identical source fingerprint. A group
is credited only after every assigned module has passed. Run the unfiltered
command above after all modules pass to obtain the authoritative combined
result; `--module` alone never reports the matrix complete.

Do not enable campaigns or continuous delta hunting until all Phase 30
verification gates pass, including a complete segmented test matrix, live
Operations auth/CSRF checks, retention and backup/restore fixtures, crash
reconciliation, listener and permission audits, and proof of no target traffic
or recon writes during acceptance.
