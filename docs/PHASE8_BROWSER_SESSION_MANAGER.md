# Phase 8: Browser Session Manager

Phase 8 adds local browser/session infrastructure only. No bounty target was
visited during implementation, and no recon service, table, or file was changed.
The original roadmap numbers browser work differently; this document uses the
operator's Phase 8 sequence after the completed Phase 7 AuthContext.

## Existing VPS Login Infrastructure

Read-only inspection on 2026-10-10 found:

| Component | Observed behavior |
| --- | --- |
| `codex-human-browser.service` | Active. `start_human_captcha_browser.sh` starts Xvfb `:99`, fluxbox, Chromium, x11vnc Unix socket, noVNC at loopback `:6080`, and Chrome CDP at loopback `:9222`. Its persistent Chrome profile is under `/root/codex_artifacts/browser_profiles/human-captcha/chromium`. |
| `codex-hunt-login-broker.service` | Active. `hunt_login_broker.py` attaches to that shared CDP browser, creates per-account Playwright contexts/windows, reads recon-owned credential records, and writes Playwright storage-state JSON under recon hunt artifact directories. |
| Login Complete | Recon dashboard/broker marker files indicate operator completion. The general path marks a session ready for identity verification; a Sidekick-specific path checks a `/me` response against an expected email. A marker or disappearing challenge is not universal proof of account identity. |
| Network/credentials | VNC and CDP listeners are loopback. The broker and dashboard use recon-owned files, run IDs, and account/session state. Production profiles and storage-state JSON are credential-bearing. |

**Decision: PARTIAL REUSE.** Reuse the installed Playwright/Chromium/Xvfb/noVNC
technology and the human-in-the-loop interaction pattern. Do not attach to
recon CDP `:9222`, use display `:99` or port `:6080`, import recon broker
modules, read its credential/session files, or treat broker completion markers
as BugHunter verification. Direct service reuse would bridge account and
profile trust boundaries and couple BugHunter to recon run IDs. BugHunter has a
separate browser driver, profile root, metadata table, and optional dedicated
VNC display.

## Model And Storage

`BrowserSession` has a generated `BSESSION-...` ID, one registered target,
optional one Identity and AuthContext, driver name, profile reference, process
state, verification state, timestamps, optional expiry, generic proxy reference,
and optional VNC reference. Anonymous sessions have neither Identity nor
AuthContext and can never be `VALID`. `SessionContext` is the compact future
agent view: it exposes statuses, IDs, browser availability, and **declared**
tenant/role IDs from the registry. Declared roles are not claims verified from
the live application. Neither model includes cookies, tokens, passwords,
storage-state bytes, or browser profile contents.

Migration `004_browser_sessions.sql` advances BugHunter's own SQLite schema
from 3 to 4. It stores only metadata and safe lifecycle event names. It has
no production PostgreSQL dependency. Profile references use the exact stable
`target_id/identity_id/session_id` structure, or `target_id/anonymous/session_id`.
The configurable profile root defaults to `<HACKBOT_HOME>/browser-profiles`.
Directories are mode `0700`; the root must be empty or carry a BugHunter
ownership marker. Existing nonempty unmarked paths and symlinks are rejected.
This is a **local development default**, not a final block-volume decision.
Persistent profile data is sensitive and must be backed up, encrypted, and
retained under a later explicit policy. Destroy preserves an authenticated
profile unless `purge_profile=True`; anonymous destroy purges it. Imported
source material in the configured secret provider is never deleted by cleanup.

States are `CREATED`, `STARTING`, `RUNNING`, `WAITING_LOGIN`,
`VERIFYING_IDENTITY`, `NEEDS_MANUAL_REVIEW`, `VALID`, `EXPIRED`,
`REAUTH_REQUIRED`, `FAILED`, and `STOPPED`. Process availability is checked
separately. A persisted `VALID` row from a prior process is **not** an active
session until the driver is running and the linked AuthContext still points to
that session. `reconcile_stale` fails closed after a browser exit or manager
restart. Expiry is recorded only when supplied; it is not guessed from cookie
presence. Stop/restart/expire do not submit credentials automatically.

## Driver And Verification

`BrowserDriver` is a small vendor-neutral protocol: start, stop, running
check, imported-session application, and current-page identity observation.
`BrowserSessionManager` owns lifecycle, SQLite, and registry/AuthContext
linkage; it does not issue navigation requests or crawl. The optional
`PlaywrightBrowserDriver` uses a persistent Chromium context per session and
never attaches to the recon CDP browser. Install with
`pip install -e '.[browser]'`. If the installed Playwright version expects a missing browser
revision, configure an explicit trusted Chromium binary; no recon profile is
copied. The driver remains in the same long-running Python process as the
manager. Short-lived CLI invocations cannot control a browser owned by another
process and will not falsely mark it stopped.

The target-specific `IdentityVerificationRule` pairs an expected application
user ID and/or email with current-page selectors; an optional expected tenant
ID has its own selector. `SessionVerifier` compares the resulting observation.
Only an exact `MATCH` atomically transitions both BrowserSession and
AuthContext to `VALID`. A wrong user or tenant enters `REAUTH_REQUIRED`; a
missing rule, missing field, or observation failure enters
`NEEDS_MANUAL_REVIEW`. A reliable authenticated self/profile page and a
target-specific rule are required. A login-complete button, cookies, local
storage, or blank login page is never enough. Future verifier providers may
use a scoped `/me` API or GraphQL current-user operation; Phase 8 implements
only current-page observation and does not navigate automatically.

## Manual And Imported Flows

`MANUAL_LOGIN` AuthContext -> create session -> start isolated headed browser ->
`WAITING_LOGIN`. The researcher manually opens an authorized URL in the
dedicated noVNC desktop and completes username/password, SSO, CAPTCHA, MFA,
email/device verification. `login_complete(session_id)` changes state to
`VERIFYING_IDENTITY` only; `verify(session_id, rule)` must still match the
expected account and tenant. No CAPTCHA/MFA bypass or automated credential
submission exists.

The optional helper `bash scripts/start_browser_vnc.sh` starts a **separate**
Xvfb display (default `:901`) and noVNC listener (default
`127.0.0.1:6901`). It refuses recon's `:99`/`:6080` and refuses occupied
display sockets. It does not start Chromium or attach CDP; the driver launches
the session's Chromium on that display. Configure `[browser].display = ":901"`
and `[browser].vnc_url = "http://127.0.0.1:6901/vnc.html"`; run the browser
process with `XAUTHORITY` pointing to the helper's private runtime
`Xauthority` file. Access noVNC only through an SSH tunnel. The helper is
optional and was **not started** during implementation. Browser egress is not
yet sandboxed; do not expose the listener publicly or give the browser access
to unrelated VPS management networks.

`IMPORTED_SESSION` requires an available Phase 7 `SESSION_IMPORT_REFERENCE`
binding, a matching active TargetPackage, and an isolated browser. The secret
is resolved only at the driver boundary. The current import format is a
bounded `hackbot-cookie-v1` JSON object with `cookies: [{url,name,value}]`.
Each cookie URL must be HTTPS, origin-root only, and affirmatively in package
scope. All cookies are validated before application. This phase intentionally
does not import localStorage, sessionStorage, service-worker state, or arbitrary
Playwright storage-state JSON. Imported cookies leave the browser in
`VERIFYING_IDENTITY`, not `VALID`. Missing/invalid material fails closed with
value-free errors. The provider currently supports only an explicitly bound,
allowlisted environment variable for this value; a protected file provider
remains deferred.

Chromium receives a minimal child environment instead of the worker's full
environment, so configured secret-provider variables are not inherited by the
browser process. The trusted Python/Playwright executor still runs in the
same process environment as the provider; stronger process-level isolation
and a protected file/keyring backend remain future work.

Anonymous sessions start `RUNNING` without Identity/AuthContext and cannot
become authenticated. They use a separate profile subtree and are purged on
explicit destroy. They are suitable for future public/private comparisons,
but Phase 8 sends no test traffic.

## CLI And Proxy Boundary

The safe CLI supports `hackbot browser create <target> <identity>`, `create
<target> --anonymous`, `list <target> [--limit N --cursor ID]`, `status
<session>`, `stop <session>`, and `reconcile <session>`. `create` allocates metadata and an isolated
profile but does **not** launch Chromium. The actual manual-login/verification
flow is an API for a long-running trusted caller; there is no daemon or
cross-process browser control in this phase. CLI output is metadata only.

`BrowserProxyConfig` is generic: enabled flag, endpoint supplied to the
driver, optional opaque reference, and deferred CA reference. Only safe
reference/flag metadata is persisted. The Playwright driver refuses a custom
CA reference rather than silently disabling TLS verification; it never
installs a CA globally. Future Burp can be inserted as a proxy provider
without changing `BrowserSession` or inventing Burp-specific core models.
There is no Burp, traffic capture/store, replay, dashboard, or target-wide
automation here. Any future automatic navigation must enforce TargetPackage
scope and program rules before traffic is sent; recon membership is not
authorization.

## Phase 9 Handoff

Recommended next task: implement a **generic, target-scoped authenticated
traffic attribution foundation** that consumes only verified SessionContext,
applies TargetPackage policy before every request/navigation, and records
vendor-neutral request/response provenance. Keep Burp as an optional future
capture/proxy adapter. Do not begin this without explicit operator approval.
