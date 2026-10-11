# BugHunter Montoya Capture Extension

Small capture-only Burp extension. It observes final proxy requests and
responses, sends bounded JSON to BugHunter's authenticated loopback bridge,
and never changes target traffic. It contains no Scanner, Intruder, replay,
model, or GUI automation code.

Requires a compatible operator-installed Burp and public Montoya API 2026.7.
The API JAR is compile-only and is not included in the resulting extension.

Build with Gradle on a full Java 17+ JDK, or with the local fallback builder:

```bash
MONTOYA_API_JAR=/absolute/path/to/montoya-api-2026.7.jar bash build.sh
```

The JAR is `build/hackbot-burp-bridge.jar`. The fallback builder also runs a
small JSON/schema fixture. Set `HACKBOT_BURP_BRIDGE_URL` to an exact
`http://127.0.0.1:<port>` origin, `HACKBOT_BURP_LISTENERS` to comma-separated
exact loopback listener keys, and `HACKBOT_SECRET_BURP_BRIDGE` through a
protected runtime secret source. Never put a token or license in this repo.
The extension fails to initialize if required configuration is missing.

The queue holds at most 64 events. An event is capped at 1 MiB; large bodies
are omitted before copying, and oversized encoded events are dropped. One
sender thread posts to loopback with short timeouts and one transient retry.
The bridge's capture-ID index makes retries idempotent. No raw messages or
secret values are logged. The project and listener setup is described in
[`docs/PHASE10_BURP_INTEGRATION.md`](../../docs/PHASE10_BURP_INTEGRATION.md).
