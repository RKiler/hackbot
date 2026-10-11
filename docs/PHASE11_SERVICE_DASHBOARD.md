# Phase 11: Private Service and Recon Dashboard Integration

## Existing dashboard and decision

The production recon dashboard is a Flask application in
`/root/enhanced_recon_framework/dashboard.py`, served by its existing Gunicorn
container on host loopback port 5000. Caddy already proxies the whole
`recon.base64.live` host to that port. The dashboard has a session/Basic-auth
gate, CSRF checks for JSON mutations, and template/static navigation for its
Research, Hunts, and Agentic views. Its normal data source is production
PostgreSQL. Neither Caddy routing nor recon workers needed to change.

**Decision A:** mount HackBot pages and a narrow API facade in the existing
Flask dashboard at `/hackbot` and `/api/hackbot/*`. The facade authenticates
with the dashboard's existing gate, checks the existing CSRF token on POST,
and forwards only JSON bodies and allowlisted query parameters to the private
BugHunter service. It never forwards dashboard cookies, Authorization values,
or CSRF tokens. This preserves one public login and a same-origin UI without
letting dashboard frontend code touch BugHunter SQLite or production SQL.
HackBot is unavailable if dashboard authentication is disabled. CORS is not
enabled.

## Service and runtime ownership

`hackbot.service:create_app()` is a small Flask WSGI service. Gunicorn runs
**exactly one worker and one thread**, so its BrowserSessionManager and
Playwright handles have one owner. It listens only on a root-owned mode-0700
Unix socket inside mode-0700 `/run/bughunter-agent`, mounted read-only into the dashboard
container. There is no direct public management listener and no static API
token. The socket and dashboard process boundary are trusted; do not grant
untrusted users access to either. API errors are generic and responses are
`no-store`/`nosniff`.

The service initializes only BugHunter-owned local SQLite and artifacts. On
startup it reconciles persisted browser metadata with process-local handles;
stale sessions lose their claim to a live/valid browser. It does not start a
hunt, browser, Burp, target request, recon query, or background worker.
`systemctl start|stop|status bughunter-agent.service` controls the API.
`/api/hackbot/health` and `/api/hackbot/status` report local dependencies;
absence of Burp is reported as `BURP_NOT_INSTALLED`, not a service failure.

The dedicated `bughunter-vnc.service` owns display `:901` and loopback noVNC
`127.0.0.1:6901`, separate from recon's `:99`/`:6080` browser. Open it only
through an SSH tunnel (for example, `ssh -L 6901:127.0.0.1:6901 <vps>`), then
use `http://127.0.0.1:6901/vnc.html`. The UI shows Open VNC only for a running
`WAITING_LOGIN` session. No VNC password is returned in API/HTML. Loopback
binding and SSH are mandatory; do not publish port 6901. The VNC service does
not start a browser until an operator creates and starts a session.

## API and workflow

All public-facing routes are dashboard-protected `/api/hackbot/*` forwarding
to private versioned `/v1/*`. They cover health/status/overview/activity,
target list/detail/scope, package account registration and identity status,
manual AuthContext preparation, browser create/list/detail/start/stop/reconcile,
Login Complete and verification, traffic list/stats/detail, Burp status, and
evidence **metadata**. IDs are resolved under an explicit Target Package and
cross-target session/identity/exchange access is denied. JSON input and list
pages are bounded. Traffic filtering uses target-scoped indexed SQL and
filter-bound keyset cursors. Captured bodies, secret-bearing headers, browser
storage, raw Evidence, and credentials are never returned by these APIs.

Account setup is deliberate: install a Phase 5 Target Package with authoritative
program scope and alias/reference-only owned accounts under the configured
targets root, then use **Register package accounts**. No recon domain row or
discovered URL grants active testing authorization. Prepare Auth uses only
`MANUAL_LOGIN` in this phase. Create and start a browser session, complete
the login in the isolated VNC profile, then click **Login complete**. The click
moves the session through verification; it never marks the account `VALID` by
itself. A trusted, private `<target-package>/verification.json` may supply an
exact current-page identity rule by account alias. Without a rule, or if the
observed identity mismatches, the session stays unverified or requires review.
The file is server-side, size-bounded, and cannot be supplied through the API.

## Dashboard views

The new top-level HackBot section includes Overview/activity, Targets and a
target detail with Overview/Scope/Accounts/Sessions/Traffic tabs, Accounts,
Sessions and manual VNC actions, safe Traffic filters and detail, Scope, and
Burp. Scope visibly separates **AUTHORIZED TARGET SCOPE** from **RECON
INVENTORY - NOT AUTHORIZATION**. Burp displays `NOT INSTALLED` until the
Phase 10 provider is genuinely available. The UI renders server values as
text nodes, not HTML. No protected traffic artifact viewer is present.
Future Hunts, Hypotheses, Skills, Research, Evidence, Findings, and Approvals
can be added as separate views without inventing Phase 11 data.

## Deployment and data placement

The current VPS uses `/root/.config/bughunter-agent/config.toml` (0600).
BugHunter state, profiles, artifacts, and VNC runtime are configured on the
resolved block-volume path under `/mnt/volume_sfo2_1788290659423/codex_artifacts/bughunter-agent`.
The human-friendly `/root/codex_artifacts` symlink points there, but the profile
guard requires the resolved physical path. The systemd units in
`deploy/systemd/` are installed separately; the dashboard container mounts
`hackbot_gateway.py` and the private socket directory read-only. Only the
dashboard container was recreated for UI deployment. Existing recon workers,
PostgreSQL, Caddy, DNS, and the old login broker were not restarted or changed.
The public URL is `https://recon.base64.live/hackbot` behind the existing login.

Burp's project/listener/bridge lifecycle remains deferred while not installed.
The `TrafficStore` can browse existing BugHunter-owned synthetic or future
captured traffic, but no active capture or target traffic starts automatically.
The optional read-only ReconRepository summary is also deferred; this phase
does not query production PostgreSQL from BugHunter or add recon DB tables.

## Phase 12 handoff

The original `docs/blueprint/02_ROADMAP.md` labels Phase 11 differently. The
operator's current Phase 11 brief supersedes that older numbering: this phase
is the service/dashboard control plane, not hypothesis generation.

Phase 12 should add an explicit, target-scoped, bounded research/hypothesis
workflow consuming authoritative Target Packages, the Phase 2 read-only
ReconRepository, and safe BugHunter traffic/evidence references. Its separate
approval and execution policy must be designed before any active requests.
Do not treat this control plane as authorization for autonomous hunting.
