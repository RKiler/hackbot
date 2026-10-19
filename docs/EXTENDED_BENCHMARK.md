# EXTENDED_BENCHMARK

This is optional work after the one-trial Phase 33 low-resource acceptance run.
It is operator-invoked, synthetic-only, checkpointed, and must not silently
start a real-target campaign. A case with an ambiguous interrupted action is
not replayed on resume.

## Actually Completed

- Version-33.18 offline `NO_TRAFFIC` diagnostic:
  `BENCH-b0c852d328a0405b88194ea40ed1d1b1`. It completed with no
  confirmations, false confirmations, or safety events. This verifies the
  traffic ablation path, not active discovery.
- Version-33.18 two-trial `local-advice` fake-primary/fake-challenger diagnostic:
  `BENCH-ca7db4c629a7452a8aa83bf4d439c3f2`. Both vulnerable trials
  confirmed; both guarded trials had zero false confirmations. The report
  recorded four calls in each fake lane, 80 loopback requests, four created
  and cleaned fixtures, and zero safety events. Fake ordering cannot establish
  live-provider effectiveness.
- Version-33.18 `local-advice` ablations: `NO_MODEL` run
  `BENCH-e5f4315ddf634035ba67592d0fd952e7` and `NO_CHALLENGER` run
  `BENCH-1ea0cf1f72a743ecac6b23ffd16cd401`. Both completed with zero
  false confirmations and safety events, but neither confirmed its planted
  issue. The latter recorded two primary calls and no challenger call.
  These one-trial differences are not an estimate of model benefit.
- Three-trial, operator-assisted GraphQL field pair:
  `BENCH-67f9190e5749483ba932c339070f47f0` (benchmark version 33.15).
  The planted field vulnerability was ranked in the top five in all three
  trials but confirmed in none. The secure variant had zero false confirmed
  Findings; 12/12 disposable objects were cleaned, with zero safety events.
  This is a stability diagnostic, not a current-build acceptance run.
- One deterministic versus fake-lane advice-pair diagnostic from version
  33.4: `BENCH-91126d3b0b0d4230bafb328d9011e9c7` and
  `BENCH-0f51557dd9d549afb4a1559b1e2b5869`. The fake ordering changed
  the selected noisy lead in that single comparison; it does not establish
  live-model benefit or a repeatable quality improvement.

## Available On Demand

Run only when the 2-vCPU host has room for the selected work. The CLI uses
BugHunter-owned block-backed state/artifacts and serial local fixtures.

```text
hackbot benchmark run local-low-resource-candidate --mode local --trials 3 --seed 33
hackbot benchmark run local-advice --mode local --fake-providers --trials 3 --seed 33
hackbot benchmark resume BENCH-<run-id>
hackbot benchmark compare BENCH-<baseline-id> BENCH-<current-id>
```

`NO_TRAFFIC` removes imported recorded traffic in offline mode. `NO_MODEL`
suppresses all selected advisor calls; `NO_CHALLENGER` suppresses only the
challenger. Fake providers return deterministic candidate orderings from the
same bounded packet. They use no hidden answer, and their output cannot
approve an action or confirm a Finding. The report records each applied
ablation and labels fake-provider output as a plumbing diagnostic.

## Not Yet Available

- Live Astra, DeepSeek, or other-provider comparison: no benchmark provider
  adapter or credential is configured. Provider independence is tested with
  fake lanes; no live-model result is claimed.
- `NO_RESEARCH`, `NO_BEHAVIOUR`, and `NO_RECON` comparisons: the current
  scored local fixtures do not contain those input channels. A no-op would be
  misleading, so these selections fail closed until paired fixtures support
  them.
- Full cross-product repetition of every case, provider, and ablation: not
  run. The resumable runner and versioned fixture catalog support bounded
  future campaigns, but there is no fabricated aggregate result.
