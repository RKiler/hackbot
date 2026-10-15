# Phase 29: Notifications, Reports, and Finding Workflow

Phase 29 turns deterministic Phase 17 findings into researcher-facing work. It does not
create findings, submit to a bounty platform, authorize testing, or change recon data.
The Target Package and existing Phase 13/14/16/17 gates remain authoritative.

## NotificationManager

The validator inserts an outbox event in the same SQLite transaction that first
creates a confirmed Finding. A later validation of the same root cause is a duplicate
candidate and does not create a second confirmed event. Workflow transitions append
version-keyed events; optional manual-review events are labelled unconfirmed.

`NotificationStore` owns events, per-provider deliveries, attempts, dedupe keys,
bounded retries, and per-provider/hour and per-target/day caps. The service wakes a
small local dispatcher after validation or workflow changes and polls the persisted
outbox after restart. Rate caps count completed attempts, including failures, and
in-flight claims so a broken provider cannot bypass them. Higher-priority events
are prepared and dispatched before older lower-priority work; suppressed duplicate
enqueues and duplicate validated root causes contribute to the deduplication
metric. A crash in the ambiguous sending window leaves the delivery in
`NEEDS_REVIEW`; it is not blindly resent. This is deliberate at-most-once safety for
uncertain provider outcomes, not a claim of network-level exactly-once delivery.
Provider failure degrades notifier health but does not revoke finding confirmation.

The typed provider boundary currently supports Discord webhooks, optional SMTP over
TLS, and a local console provider. No provider is enabled by default. Provider
credentials are Phase 7 secret references, not TOML literals or SQLite values. Recon
alerting is not modified or imported; this avoids coupling BugHunter's event ledger
to production recon notification state. Messages contain bounded, redacted metadata
only, never Evidence bodies or screenshots. A confirmed alert uses the executed
boundary request's structural path shape, or the validated browser route's origin,
instead of exposing object identifiers or raw URL parameters. Manual-review and
triage alerts are opt-in.
The dashboard's TEST action is explicit, authenticated, and CSRF protected.

## FindingWorkflow

Only an existing target-bound, deterministically confirmed Finding enters the manual
workflow. Transitions use an expected version and append a status event with a
redacted note and optional operator alias. A ready report draft is required before
`READY_FOR_REPORT`, and the latest report attempt must still be READY, not a failed
regeneration or an unreviewed edit. Submission requires an entered platform and external report ID.
Triage, duplicate, informative, resolution, and reward outcomes are manual.
Submission IDs, triage status, and reward amount/currency are retained in a separate
metadata row. Original validation and Evidence records are never removed when a
finding is marked duplicate or informative.

## ReportDraft

`ReportGenerator` requires the source Finding, deterministic confirmed ValidationResult,
completed PlanRun, target-bound Evidence, executed steps, demonstrated impact, and a
currently scoped affected surface. Missing material records a `NEEDS_EVIDENCE`
attempt rather than producing a polished report. Specialist sections are built from
the exact DOM, messaging, exposure, or API candidate linked to the plan. When a
GraphQL document cannot be safely emitted, the draft is marked
`NEEDS_MANUAL_REVIEW` instead of inventing a query. GraphQL query text is
rendered only when its SHA-256 matches the observed
operation version; parsing removes comments and rejects literal values, and
request variables are never copied into Markdown. DOM and messaging report
renderers recheck saved JS asset state and hashes; a stale asset remains historical
evidence but prevents a READY draft.

The generic Markdown structure includes summary, executed reproduction steps,
observed and expected results, demonstrated impact, potential impact if recorded,
Evidence IDs, controls, limitations, and a preliminary severity status. Potential
impact is always labelled not demonstrated. The summary names the tested actor,
failed boundary, and validated effect; an unknown effect or missing actor context
requires manual review instead of a generic READY report. Authentication values are placeholders,
not live headers or cookies. Target-controlled text is redacted and escaped before
report output. Evidence references remain opaque and are resolved only through the
private authenticated API. Draft content is stored in BugHunter's content-addressed
artifact store; SQLite retains immutable version metadata and content hash. A manual
edit creates a new `MANUALLY_EDITED` version and cannot overwrite the generated one.
Edits reject stale versions and oversize lines instead of silently discarding text.

The deterministic generator is complete without an LLM. Model-assisted prose is
deferred; any future model path must receive only validated structured facts and pass
the same quality/redaction checks. No automatic HackerOne/Bugcrowd login or submission
is implemented.

## API and Dashboard

The private service exposes target-bound findings, workflow transitions, report
generation/list/detail/edit/download, and notification status/history/TEST endpoints.
The existing same-origin gateway enforces dashboard authentication and CSRF for
mutations, strips browser credentials before proxying, and caps report downloads.
`/hackbot/findings` shows lifecycle, report, submission, and delivery status.
`/hackbot/reports` shows versioned drafts, escaped Markdown text, manual edits,
authenticated downloads, and notification status. The UI renders report content with
`textContent`, not HTML interpretation, because target strings can be hostile.

## Configuration and Operations

`[notifications]` accepts `discord_secret_ref`, optional SMTP host/sender/recipient/
username/`smtp_password_ref`, `console_enabled`, `manual_review_enabled`,
`triage_enabled`, `hourly_cap`, `target_daily_cap`, and `dashboard_base_url`.
Secret references resolve through the existing Phase 7 provider. Keep providers off
until their destination and handling policy are reviewed. A TEST notification is the
only operator smoke action; unit acceptance uses local fakes and sends no live alert.

Phase 30 should harden retention, artifact backup/recovery, notifier observability,
ambiguous-delivery operator reconciliation, resource bounds, and service lifecycle
before campaign or continuous scheduling is introduced.
