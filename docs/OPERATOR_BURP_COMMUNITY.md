# Burp Community Operator Runbook

BugHunter uses Burp Suite Community Edition as a transient capture proxy. Burp
does not authorize target traffic, find vulnerabilities, or retain canonical
history. The Target Package, policy engine, browser session, and BugHunter
TrafficStore remain authoritative. This setup was verified only with loopback
fixtures; it does not authorize or perform live bounty testing.

## Installed Layout

| Item | Current installation |
| --- | --- |
| Edition/version | Official Burp Suite Community Edition 2026.9.2 |
| Application | `/opt/bughunter/burp/burpsuite_desktop_v2026.9.2.jar` |
| Extension | `/opt/bughunter/burp/hackbot-burp-bridge.jar`, built from `integrations/burp-extension` against Montoya API 2026.7 |
| Service | `bughunter-burp.service`, enabled at boot, dedicated `bughunter-burp` user |
| Runtime | Xvfb display `:902`, a temporary in-memory Community project, no disk project |
| Runtime data | `/mnt/volume_sfo2_1788290659423/codex_artifacts/bughunter-agent/burp-runtime` |
| Public CA | `/opt/bughunter/burp/burp-ca.pem` (public certificate only) |
| Proxy listeners | `127.0.0.1:38080` through `127.0.0.1:38083` |
| Bridge | `127.0.0.1:38777`, in the private BugHunter service |

The source-controlled templates are under `deploy/burp/`. The installed binary,
generated bridge capability, runtime data, and browser profiles are outside
Git. The capability is supplied to both services through systemd
`LoadCredential`; do not print it or put it in a command transcript. The
Burp service uses `-Xms128m -Xmx768m`, `MemoryMax=1600M`, `TasksMax=256`, a
20-second restart delay, and a limit of three starts in ten minutes. Java,
Xvfb, `fluxbox`, and `xdotool` are required. Check `MemoryCurrent` and
`MemoryPeak` with `systemctl show bughunter-burp.service` after upgrades.

Community Edition needs an AWT display here. It did not start the required
proxy/extension setup in true headless mode, and Community's project-file
option is not available. The launcher uses a private Xvfb display and
window-title/keyboard navigation of the Community startup wizard, not screen
coordinates. It starts a fresh temporary project after each service restart.
If the wizard changes in a later release, the service fails rather than
claiming that capture is ready.

## Capture Path

```text
isolated BugHunter BrowserSession
  -> one assigned loopback Burp listener
  -> local or explicitly authorized target
  -> capture-only Montoya extension
  -> authenticated loopback bridge in bughunter-agent.service
  -> BugHunter TrafficStore and protected Evidence
```

The listener is the session attribution key; the extension does not insert a
target-visible header. BugHunter assigns `VERIFIED` attribution only after its
independent current-page identity rule matches the intended account. A wrong
or unverified identity remains unverified; an anonymous browser remains
anonymous unless authentication material is observed. The local synthetic
fixture uses four listeners for A, B, wrong-identity, and anonymous controls.
Four is the installed capacity, not a license to share a listener between
concurrent sessions. Stop/release an unused session before reusing a port.

The public CA certificate is imported by `install_profile_ca` into the NSS
database beneath **each isolated BugHunter research profile parent**. It is
not installed in `/etc/ssl`, `/root/.pki`, recon profiles, or the system
browser. Chromium runs with an explicit proxy and TLS verification enabled;
its loopback proxy-bypass list is overridden so local fixtures also traverse
Burp. Do not copy the Burp CA private key or disable TLS verification to make
interception work.

Burp may start before or after the BugHunter agent. Extension heartbeats may
initially fail while the target-scoped bridge is not running; creating a Burp
capture session starts that bridge. Start the BrowserSession before sending
fixture traffic through its listener; a reserved listener alone is not an
active, attributable capture session, and those observations are dropped.
An agent restart releases old listener
reservations and discards the prior bridge heartbeat; status remains
`BURP_RUNNING` or `BRIDGE_DISCONNECTED` until a new authenticated heartbeat
arrives. A capture-required browser start is denied
until the listener is reachable and a recent authenticated heartbeat exists.
If Burp later stops, the browser retains its proxy route and does not fall
back to direct traffic. Existing direct-execution policy is unchanged.

## Operations

```bash
systemctl status bughunter-burp.service bughunter-agent.service
systemctl is-enabled bughunter-burp.service
journalctl -u bughunter-burp.service -n 40 --no-pager
ss -ltnp '( sport = :38080 or sport = :38081 or sport = :38082 or sport = :38083 or sport = :38777 )'
hackbot burp check
hackbot burp status burp-local-fixture
```

The private API is available only through the BugHunter Unix control socket:
`GET /v1/burp/status?target=<tracked-target>`. The authenticated dashboard
gateway at `/hackbot/burp` reads that API; it must not expose the bridge
capability, raw captured content, cookies, or credentials. A working target
reports `BRIDGE_CONNECTED`, a reachable listener, capture count, and last
capture time. The dashboard distinguishes physical loopback Burp listeners
from listeners assigned to the selected target. A global or idle target status
may say `BURP_RUNNING` with physical listeners available but no target bridge.

For a planned restart, stop/restart only the dedicated Burp service:

```bash
systemctl restart bughunter-burp.service
```

Wait for `Burp Community temporary project and loopback listener ready` in
the journal, then check target bridge heartbeat and listener reachability.
The extension queues are bounded; a short outage can drop events, and Burp's
in-memory history is not recovered. TrafficStore persists already ingested
exchanges. Do not restart the production recon framework to recover Burp.

If Burp is unavailable, check the service journal, process memory limit,
private Xvfb display, and loopback port conflicts. `BURP_STOPPED` means the
installed process/listener is absent; `BRIDGE_CONNECTED` additionally requires
an authenticated recent heartbeat for a target. Check that the bridge stays
bound only to loopback. An HTTP 200 from a page without a corresponding
TrafficStore `source=BURP` exchange is not proof that capture works.

The synthetic fixture is `deploy/burp/local_fixture.py` on
`127.0.0.1:39800` (HTTP) and `:39801` (HTTPS). Its Target Package is in
`deploy/burp/fixtures/burp-local-fixture/`; the installed copy lives in the
BugHunter target root. It is for isolated operator checks, not recon or a
real bounty target. Stop the fixture and its browser after smoke tests. The
current bridge is single-target; restart only `bughunter-agent.service` after
the fixture session is stopped to release its target reservation before
starting capture for another tracked package. Already captured TrafficStore
exchanges remain available. The idle status is then `BURP_RUNNING`, not
`BRIDGE_CONNECTED`; a new target session establishes the latter after its
first authenticated extension heartbeat.

## Security And Community Limits

- Community uses a temporary project; saved Burp project history is not a
  persistence mechanism. Use BugHunter TrafficStore and protected Evidence.
- One running bridge is bound to one tracked Target Package in the current
  service process. Do not assume simultaneous multi-target bridge support.
- The four installed listeners are fixed, loopback-only, and should not be
  exposed through Caddy or a public firewall rule.
- The extension observes and bounds traffic only. It does not scan, fuzz,
  replay, run Intruder, or perform active target requests.
- Captured authentication headers and credential-like bodies are removed or
  withheld by TrafficStore. Browser profiles and Burp's volatile process
  memory still require private host access and normal secret hygiene.
- Keep the capability file, systemd drop-in, and BugHunter-owned state
  protected; do not commit generated secrets, Burp binaries, browser profiles,
  or fixture certificates to Git.
