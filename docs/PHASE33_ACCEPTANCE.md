# Phase 33 Low-Resource Acceptance

Core evaluation-framework delivery: **complete** on 2026-10-19. This is a
synthetic, loopback-only software acceptance result, **not** approval for a
real-target pilot. Product readiness remains **NOT_READY**.

## Current-Source Evidence

- Source-bound Phase 30/33 matrix: 78/78 modules and 9/9 groups passed.
  Fingerprint: `dc69b292db7d2055d65065a2f90a1a2fa7bda7f2613c269e2444717d36cef772`.
  Resume record: `/root/codex_artifacts/bughunter-agent/artifacts/phase33_matrix_resume_v6.json`.
  The separately enabled Chromium integration test also passed (1/1).
- Suite: `local-low-resource-candidate`, version 33.18, deterministic-only,
  one trial. [Baseline report](/root/codex_artifacts/bughunter-agent/artifacts/benchmark-reports/BENCH-df8b2379a1e84eefa27ab385c22ac830/report.json).
  All 19/19 cases completed; no failed or ambiguous case was counted as a pass.
- Fixture inventory: paired vulnerable/guarded cases for Authorization,
  API/GraphQL, DOM XSS, postMessage, and Exposure; one noisy secure workspace;
  and one mixed multi-surface target. `benchmark coverage` reports
  `fixture_coverage_complete=true`. Visible inputs, runner-only behavior, and
  evaluator-only truth are separate, hash-checked roots. The runtime receives
  no hidden answer key.
- Normal Campaign/Planner/specialist/Phase 17 validation and read-only audit
  tracing were used. The five confirmed synthetic Findings passed finding
  quality and audit-chain checks; candidates or HTTP status alone received
  no confirmation credit.

## Core Result

| Measure | Result |
| --- | ---: |
| Planted roots detected | 5/10 |
| Precision / recall | 1.0 / 0.5 |
| Top-1 / top-3 / top-10 recall | 0.7 / 0.9 / 0.9 |
| Secure cases with false confirmed Findings | 0 |
| Observed safety violations / orphaned objects | 0 / 0 |
| Disposable objects created / cleaned | 27 / 27 |
| Loopback requests / requests per detection | 286 / 57.2 |
| Candidates / false candidates | 62 / 50 |
| Manual-context waits / synthetic approvals | 7 / 4 |
| Model tokens / priced model cost | 0 / $0 |

The confirmed cases were DOM XSS, postMessage, private download, cross-tenant
read, and cross-tenant mutation. The two GraphQL positives, horizontal read,
and both roots in the mixed target were missed. The missed cases remain in the
score; no fixture, answer key, validator, or policy was relaxed to improve it.
The 48 reported `browser_actions` are campaign budget reservations, not a
measured count of browser clicks. VPS dollar cost is unpriced, so total USD
cost and dollar cost per detection remain unknown.

## Gates And Limits

- The report's readiness conclusion is `NOT_READY`. Validation precision,
  audit chain, discovery, planner top-10, and measured resource-efficiency
  gates passed. The report does **not** mark active safety coverage, the
  external production test matrix, backup/recovery, operational stability, or
  report quality as measured. The source-bound matrix and backup tests above
  are separate evidence; they are not silently substituted into those
  unmeasured report fields.
- The benchmark starts from observed synthetic routes/traffic. It does not
  prove cold-start discovery across all specialists, live-provider benefit,
  real-target reportability, or unattended continuous-hunt readiness.
- The first current-version acceptance attempt
  `BENCH-c3810337472f44d38857bc609d97989a` failed: 18/19 cases completed,
  one resource-blocked case, and one uncleaned synthetic object. It is
  preserved as failed evidence. The corrected teardown cancels paused/waiting
  campaigns, checks each fixture's final persisted cleanup state, and records
  any remaining orphan as a safety event. The passing matrix and baseline
  above are from the corrected source.
- Benchmark execution is operator-invoked through the checkpointed CLI.
  Authenticated dashboard/API evaluation routes are read-only; web execution
  controls remain deferred pending explicit asynchronous resource admission
  and CSRF protection (D-306). No production recon writes or live bounty
  requests were part of acceptance.

## Extended Work

Actually completed: an offline `NO_TRAFFIC` diagnostic, a two-trial
fake-primary/fake-challenger advice comparison, one `NO_MODEL` run, one
`NO_CHALLENGER` run, and earlier limited stability diagnostics. Run IDs and
their exact measured results are in [EXTENDED_BENCHMARK.md](EXTENDED_BENCHMARK.md).
Fake providers prove lane independence and accounting, not live model quality.

Available later, not claimed as performed: exhaustive cross-case repetitions,
live Astra/DeepSeek/other-provider comparisons, and broader supported
ablation fixtures. All must remain synthetic, checkpointed, operator-invoked,
and separately reported. The supervised real-target procedure is
[FIRST_REAL_TARGET_PILOT.md](FIRST_REAL_TARGET_PILOT.md); do not execute it
until readiness and program authorization are established.
