# Phase 10: Burp Capture And Identity-Aware Proxy Routing

This document records the Phase 10 design and its pre-installation snapshot.
For the current Community Edition service and verified operator configuration,
see [`OPERATOR_BURP_COMMUNITY.md`](OPERATOR_BURP_COMMUNITY.md).

This phase adds a Burp capture adapter, not a hunting engine or traffic executor.
The operator's Phase 10 request overrides the older blueprint's Phase 10 label.
Phase 9 `TrafficStore`, `CapturedRequest`, `CapturedResponse`, `RequestRecord`,
`ResponseRecord`, and `TrafficSource.BURP` remain the canonical traffic model.
There is no Burp-specific core request/response type, active replay, Scanner,
Intruder, model agent, or production recon integration.

## Observed VPS Environment

Read-only inspection on 2026-10-10 found Java 21 with `jdk.compiler`, but no
`javac` or Gradle executable and no Burp executable/JAR in the checked local
install paths. The public Montoya API 2026.7 JAR was downloaded to a
block-backed dependency cache for compilation; **Burp itself was not installed**.
`hackbot burp check` reports `BURP_NOT_INSTALLED`. This is not evidence that a
licensed Burp process, proxy listener, HTTPS interception, or project file has
run successfully.

Production recon Docker services are running separately. The existing human
browser/login broker owns loopback `:6080`/`:9222`; PostgreSQL uses loopback
`:5432`; Caddy serves public `:80`/`:443`. BugHunter's default listener range
`:38080`-`:38179` and bridge `:38777` were unoccupied at inspection. These
must be checked again at deployment. `/root/codex_artifacts` is block-backed
under `/mnt/volume_sfo2_1788290659423`; it had about 68 GiB free at inspection.
No recon container, service, database, dashboard, or login broker was changed.

## Capture Architecture

```text
one BugHunter Target Package / one isolated Burp project
    BrowserSession with capture_required
      -> exact loopback listener 127.0.0.1:<session port>
      -> Burp Proxy (operator configured)
      -> authorized target

    Montoya final request/response callbacks
      -> bounded Java queue
      -> authenticated loopback HTTP bridge
      -> strict BurpObservation adapter
      -> Phase 9 TrafficStore and protected Evidence/Artifacts
```

Each active BrowserSession gets a unique listener key and port. Montoya's
`listenerInterface()` is matched **exactly** against the local binding; there
is no correlation header to accidentally forward to a target. The bridge
accepts only a listener bound to the current target and a running local
browser process. It then passes the BrowserSession ID to TrafficStore.
Only Phase 8's current `VALID`/`MATCH` SessionContext earns `VERIFIED`
identity attribution. Wrong or pending identity remains `UNVERIFIED_IDENTITY`;
an anonymous browser remains `ANONYMOUS` unless it emits auth material, in
which case Phase 9 downgrades it to unverified. Cookies, JWTs, usernames, and
the listener port alone never establish identity.

Montoya observes `handleRequestToBeSent` and `handleResponseToBeSent`, using
`listenerInterface()` plus `messageId()` and a random extension-instance ID
for capture correlation. Pending requests are keyed by listener and message ID
so concurrent listeners cannot share a request snapshot. The extension does
not modify either message. It retains
at most 128 pending request snapshots and 64 queued events. Request bodies
larger than one quarter of the event limit and response bodies larger than
half are omitted before copying; events exceeding the final encoded limit
are dropped. The bridge admits at most the configured concurrent requests,
rejects oversized/malformed JSON, and returns a bounded overload response.
The extension retries a transient failed send once. SQLite capture IDs and a
unique BURP provider-reference hash make retries idempotent; response events
can complete a request-only exchange or create a complete one directly.
Dropped-event telemetry is a last-reported extension count, not a global
lifetime total. Capture events refresh bridge liveness without resetting the
last-reported count.

## Bridge Security And Data Handling

`BurpBridgeServer` binds only to `127.0.0.1`. Every endpoint requires a
capability token; `from_secret_provider` resolves the opaque configured ref
through Phase 7 `SecretProvider`. The token is never stored in TOML, SQLite,
Evidence, CLI output, or logs. It must be 32-256 URL-safe header characters.
Phase 9's `TrafficCaptureProvider.read_batch` is a pull contract; Montoya is
callback-driven, so this provider uses authenticated push ingestion instead.
Both paths terminate in the same vendor-neutral `TrafficStore`; no parallel
Burp request database is introduced.
The Java extension reads the same token from a dedicated runtime environment
variable and accepts only a `http://127.0.0.1:<port>` bridge URL. It never
reads files, accepts remote instructions, or executes target requests.
`BaseHTTPRequestHandler` access logs are suppressed; all errors are generic.

Phase 9 redacts Authorization, Cookie, Set-Cookie, API-key, CSRF, signature,
and similar header values before protected Evidence persistence. Credential-
like query values are masked; bodies with credential-like markers are
withheld. Raw bodies are not searchable metadata. Other non-credential bodies
remain SECRET protected Evidence, not ordinary CLI output. Capture provenance
is `source=BURP`, `capture_provider=MONTOYA_V1`, hashed provider reference,
browser session, scope result, and timestamp. The small `burp_capture_index`
table is a local idempotency index, **not** a second traffic database.

The Target Package is the only scope authority. Default `DROP` discards
`OUT_OF_SCOPE` and `UNKNOWN` observations before TrafficStore. Optional
`METADATA_ONLY` strips third-party path/query, headers, and bodies, retaining
only origin/status/timing under its original non-in-scope classification. Scope
is evaluated against the pre-stripped URL without retaining that URL; an
authentication-presence boolean is preserved so an anonymous browser carrying
auth material is not mislabeled anonymous. Neither state
authorizes future active testing or feeds an agent in this phase.

## Browser, CA, And Failure Behavior

`BurpProxyProvider.provision_session` creates a generic Phase 8 proxy config
and local listener binding. `start_browser` requires an active binding,
recent bridge heartbeat, and reachable listener before launching. The generic
BrowserSessionManager refuses to start a capture-required session without a
healthy proxy. Playwright receives an explicit proxy and Chromium's
`--proxy-bypass-list=<-loopback>` so loopback targets do not silently bypass
capture; TLS errors remain enabled (`ignore_https_errors=False`). A dead
proxy after launch should yield a browser network error rather than direct
fallback, but real Chromium/Burp behavior remains to be verified on this VPS.

Only the **public** Burp CA PEM may be supplied. `install_profile_ca` validates
it and imports into an NSS database under that isolated profile's parent
directory. It never changes `/etc/ssl`, the VPS system trust store, recon's
browser profile, or a shared global NSS database. Missing `certutil`, bad PEM,
or failed import prevents the browser from starting; the code does not disable
certificate verification. No CA private key is copied or requested.

## Project And Process Boundaries

One project metadata row and project-file path are reserved per registered
target under configurable `[burp].project_root`. The default under the
BugHunter local artifact root is temporary, **not** a final root-disk storage
decision. For large Burp project files, configure a separate BugHunter-owned
path on block storage, with private permissions, backup, encryption, and
retention policy decided by the operator. Projects are never auto-deleted.
Separate targets need separate Burp projects and bridge processes/configured
ports; a bridge instance is bound to one Target Package. The local SQLite
file stores only project/listener/bridge/capture-index metadata and Phase 9
traffic records, never Burp history bytes or license material.

Phase 8's browser driver is in-process. Therefore the browser manager,
`BurpProxyProvider`, `BurpCaptureProvider`, and `BurpBridgeServer` must be
owned by the **same long-running trusted BugHunter process**. A short-lived
CLI process cannot attach to another process's browser driver and must not
pretend that it can. Phase 11 should host this stack through an API/service;
this phase does not add a daemon, Docker stack, GUI automation, or service
installation. The read-only commands are:

```text
hackbot burp check
hackbot burp status [target]
hackbot burp listeners <target> [--limit N]
hackbot burp bridge status <target>
```

They return availability, heartbeat, listener status, safe capture counts,
last capture time, and last-reported dropped events. TCP reachability and a
heartbeat do not prove a licensed Burp process or HTTPS interception.

## Operator Setup When Burp Is Available

1. Install/license a compatible Burp edition **outside** recon, under the
   operator's control. Do not put a license key in BugHunter config. Create a
   dedicated target-level Burp project. Confirm extension compatibility with
   the installed Burp version.
2. Build `integrations/burp-extension` against the public Montoya API JAR.
   On a full JDK use Gradle; on this stripped VPS runtime use `build.sh` with
   `MONTOYA_API_JAR=/absolute/path/to/montoya-api-2026.7.jar`. Load the
   generated JAR into that Burp project. The dependency JAR is compile-only.
3. Configure one loopback-only Burp listener per BrowserSession, matching
   its allocated `127.0.0.1:<port>` key. Do not expose listeners through
   Caddy or bind to `0.0.0.0`. Set the extension environment variables
   `HACKBOT_BURP_BRIDGE_URL=http://127.0.0.1:<bridge-port>`,
   `HACKBOT_BURP_LISTENERS=<comma-separated exact listener keys>`, and
   `HACKBOT_SECRET_BURP_BRIDGE` from a protected runtime source. No token
   value belongs in a shell command transcript or checked-in file.
4. Bind `ref:burp_bridge` in Phase 7 SecretSettings to
   `env:HACKBOT_SECRET_BURP_BRIDGE` with kind `API_TOKEN`; set
   `[burp].bridge_secret_ref="ref:burp_bridge"`. Configure the Burp JAR
   reference, project root, listener range, bridge port, and public CA PEM.
   Use a target-specific config/process if another target runs concurrently.
5. In the future trusted service process, initialize BugHunter's local store
   and Target Package, create the browser manager and capture provider, start
   the loopback bridge, then load/start Burp and its configured listeners.
   Wait for heartbeat and listener readiness before calling
   `BurpProxyProvider.start_browser`. Verify identity via Phase 8's exact
   rule before interpreting captured traffic as trusted.
6. Test a **local** HTTP and HTTPS fixture first. Confirm Burp history, bridge
   heartbeat, browser session linkage, Phase 9 Evidence, and no direct
   fallback. Do not enable Burp Scanner, Intruder, or active replay as part
   of this integration.

Official Montoya API references: [Proxy request/response handlers](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/Proxy.html),
[intercepted message ID/listener](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/InterceptedResponse.html),
and [extension loading](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp).

## Verification And Limits

Python fixtures cover request-only/complete ingestion, protected artifacts,
idempotent retries, four concurrent actor labels, wrong/unverified/anonymous
attribution, listener uniqueness/staleness, cross-target project/listener
isolation, scope dropping and metadata-only
storage, bridge auth/schema/size/backpressure, profile-only CA calls, safe CLI,
and a loopback fixture proxy/application path. A Java fixture validates
Montoya JSON encoding against the Python parser. The extension compiles
against public Montoya API 2026.7. No real Burp installation, live Burp
proxy, licensed project, Chromium TLS interception, or local HTTPS smoke test
was available; those remain operator verification gates, not claimed results.
No production PostgreSQL query/write or bounty-target request is performed.

## Phase 11 Handoff

Build a dedicated BugHunter service/API that owns the in-process browser and
bridge lifecycle; exposes the safe status/listener/count/error DTOs; supports
per-target project configuration and guarded manual-login actions; and lets
the existing recon dashboard consume those APIs without merging databases.
Keep program scope and secret resolution server-side. Do not treat Burp
history as a reasoning engine or add active traffic execution implicitly.
