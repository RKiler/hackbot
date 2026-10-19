# First Real-Target Pilot (Future Operator Procedure)

Do not execute this runbook during Phase 33 acceptance. Start only after a
documented readiness assessment permits a supervised pilot and the program
rules explicitly authorize the selected work. A benchmark result cannot grant
scope or permission.

1. Sign in to the dashboard and open **HackBot > Targets > + Add Target**.
   Enter a display name, editable package slug, and primary hostname. In Scope,
   add only explicitly authorized hostnames, exclusions, schemes, and ports.
   Enter the real authorization source/reference, operator alias, program
   restrictions, automation rules, autonomy policy, and rate limits. Review
   every field and select **Create TargetPackage**. This writes the existing
   `targets/<slug>/target.yaml` file; no target traffic starts. A wildcard alone
   cannot seed cold start, so include an exact authorized host. TargetPackage
   scope is authoritative; recon never grants authorization. Confirm DNS/CDN
   and redirect destinations separately. The package files can still be managed
   manually by advanced operators.
2. Select **Configure Accounts** (or return later to the target's Accounts tab).
   Enter only owned identity aliases, tenant labels, and roles; save the
   non-secret `accounts.yaml`, then select **Register Accounts** to invoke the
   existing identity import. Never enter credentials, cookies, or tokens in
   account metadata. Open **Sessions** to create and verify each browser
   session's actual identity, role, tenant, and expiry using the separate
   SecretProvider/browser-session workflow. Prepare disposable objects only
   where the program permits them, with an owner and cleanup ledger.
3. Before bootstrap, confirm the BugHunter service has loaded
   `[executor] allow_direct = false` and `capture_required = true`. In the
   target detail page, inspect Recon, Bootstrap mode, Transport, Burp capture,
   anonymous capture, accounts, autonomy, and rate. A target absent from recon
   should show `COLD_START` automatically. Select **Provision Anonymous
   Capture**, start that session in Sessions, and refresh Bootstrap until the
   executor, transport, Burp capture, and cold-start status are ready. The
   **Start bootstrap** control stays disabled while blocked. Keep the listener
   loopback-only; do not borrow an
   authenticated account's listener. A blocked reason means no bootstrap
   request should be sent. Restart the BugHunter service to load a changed
   config or code only after checking that no other active real-target work
   would be resumed or interrupted.
4. Select **Start bootstrap** in the Bootstrap tab, then run normal-behaviour
   learning. Review
   provenance, currentness, scope, and gaps before selecting a hypothesis.
5. Start one `PLAN_ONLY` campaign with conservative requests, browser actions,
   time, and cleanup reserve. Inspect the top hypotheses, specialist/skill
   routing, policy decisions, and expected side effects. Reject generic or
   out-of-scope leads.
6. Approve a `BOUNDED_AUTONOMOUS` pass only after reviewing its exact target,
   actors, fixtures, methods, budget, and stop conditions. Keep continuous
   delta hunting disabled for the first pilot.
7. Monitor request count, duration, browser actions, model tokens and
   configured cost, manual waits, cleanup, validation controls, and evidence
   quality. Stop on unexpected target data, resource pressure, scope
   uncertainty, or unreviewed external side effects.
8. Confirm any Finding independently with fresh controls and a complete audit
   chain. Treat candidate leads, scanner signals, and status differences as
   unconfirmed. Clean up only pilot-created disposable objects and verify
   final state.

Useful early indicators are high-quality top-ranked hypotheses, low false
review load, bounded requests and cost, useful manual-review leads, sound
cleanup, and a confirmed Finding if one is genuinely present. A bounty is
not required to demonstrate operational software, and no ROI should be
fabricated before real campaign accounting exists.
