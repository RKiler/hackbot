# Dedicated BugHunter Burp Deployment Boundary

This directory intentionally has no Compose or systemd unit yet. A licensed
Burp installation and a persistent BugHunter browser/bridge owner process
are operator prerequisites; installing or starting one here would create a
misleading partial deployment. Do not attach to the production recon stack,
its browser broker, or its PostgreSQL database.

Use one Burp project per target, loopback-only listeners, a target-scoped
bridge port/token, and a configurable block-backed project directory. Follow
[`PHASE10_BURP_INTEGRATION.md`](../../docs/PHASE10_BURP_INTEGRATION.md) before
the future Phase 11 service wiring.

`config.example.toml` is a non-secret local configuration template. Select
real absolute paths and set `enabled = true` only after the operator has
installed/licensed Burp, loaded the extension, configured loopback listeners,
and provisioned a protected bridge token through Phase 7 SecretProvider.
