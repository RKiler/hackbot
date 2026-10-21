# First Real-Target Pilot (Future Operator Procedure)

This procedure is for a future supervised pilot after deployment review and an
explicit program authorization check. A benchmark or recon record never grants
scope. The Hunt UI remains deployment-gated; do not use this procedure while
the running service is on an older schema than the tested source.

## Normal Workflow

1. In **HackBot > Targets**, select **Add Target**. Enter the primary host and
   only explicitly authorized hosts, exclusions, schemes, and ports. Enter the
   actual program reference, forbidden actions, autonomy decisions, and rate
   policy. Review and create the file-backed TargetPackage. Creation itself
   sends no target traffic. Recon can prioritize only hosts already authorized
   by this package. Include an exact host even when a wildcard is authorized.
2. Select **Configure Accounts**. Add only owned aliases, tenant labels, and
   roles. Saving `accounts.yaml` also registers the identities. Do not put
   passwords, cookies, tokens, or MFA secrets in account metadata. The
   browser/SecretProvider workflow handles authentication separately.
3. Select **Start Hunt** in **SUPERVISED** mode. This is the first action that
   may send policy-controlled target traffic. HackBot prepares capture,
   reconciles sessions, uses recon or cold-start data as appropriate, maps the
   application, and routes work through the existing policy, permit, rate,
   TrafficStore, evidence, planner, validator, and cleanup owners. No separate
   Bootstrap, Behaviour, Planner, or Campaign click is required. The global
   Hunt ceiling bounds total work; each tranche shrinks under local pressure
   or target latency, and a captured 429 pauses new work until cooldown.
   TargetPackage request rates and program rules always remain in force.
4. Follow **Needs You** only when shown. Open each account's isolated visible
   browser and complete login or MFA yourself. Confirm the configured alias if
   HackBot cannot verify identity automatically; a conflicting identity fails
   closed. The hunt continues after valid session binding. Access the VPS
   noVNC browser through an SSH tunnel, not an internet-exposed VNC port.
5. Review approvals and evidence-backed findings. The supervised mode may
   execute low-risk actions allowed by the TargetPackage against owned,
   disposable objects, while higher-risk permitted actions require approval.
   Check that final cleanup and read-back succeeded before accepting a report.
6. Stop on unexpected third-party data, scope ambiguity, external side effects,
   or resource pressure that does not clear. Keep continuous delta hunting off
   during the first pilot. Do not treat a hypothesis, status difference, or
   scanner signal as a confirmed vulnerability.

## Existing `zapier-hunt` After Deployment

1. After the backed-up schema migration and matching service/UI rollout, open
   **HackBot > Targets > zapier-hunt**. Review its current explicit scope,
   exclusions, program rules, autonomy decisions, and rate limits before any
   request. Do not infer authorization from the Zapier recon inventory.
2. Open **Accounts** and save only owned account aliases, tenant labels, and
   roles that are authorized for this pilot. Saving registers them; do not put
   credentials or cookies in account metadata.
3. Open **Hunt**, select **Supervised**, and click **Start Hunt** once. This is
   the first step that may send authorized target traffic; do not click it
   during deployment verification.
4. Follow each **Needs You > Open** login action through the existing SSH-tunneled
   visible browser. Complete CAPTCHA/MFA yourself. If automatic identity
   verification is unavailable, confirm only the exact account alias shown.
5. Return to **Hunt** to review mapping, current activity, approval requests,
   validated findings, report drafts, and disposable-object cleanup. Use
   **Advanced** pages only when a blocker needs diagnosis. Do not manually
   start Bootstrap, Behaviour, Planner, or Campaigns for this normal flow.

## Advanced Diagnostics

The Bootstrap, Sessions, Traffic, Behaviour, Authorization, API/GraphQL,
Planner, Campaigns, and Operations pages remain available for investigation,
but are not required steps in the normal workflow. Use them to inspect exact
capture readiness, scope decisions, request/byte budgets, per-account identity
attribution, source freshness, validation controls, and cleanup state.
`PLAN_ONLY` remains available when active testing is not yet authorized.

Before any rollout, verify the configured executor is capture-required with
direct traffic disabled, Burp listeners are loopback-only, schema migration is
backed up and reviewed, and no other active target work would be interrupted
by the service restart. Do not deploy a new source tree against an older local
BugHunter schema. The production recon database is read-only to HackBot.

Useful early indicators are high-quality top-ranked hypotheses, low false
review load, bounded requests and cost, useful manual-review leads, sound
cleanup, and a confirmed Finding if one is genuinely present. A bounty is
not required to demonstrate operational software, and no ROI should be
fabricated before real campaign accounting exists.
