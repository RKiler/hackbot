# BugHunter Agent Instructions

Build an evidence-driven, authorized security research system. Follow the
phase order in `docs/blueprint/02_ROADMAP.md`; work only on the phase the
operator requests. Read `docs/DECISIONS.md` before changing architecture.

- `/root/enhanced_recon_framework` and its production database are external
  systems. Do not change their files, services, jobs, containers, data, or
  schemas without a separate explicit integration task.
- During Phase 0, use only local inspection and bounded read-only database
  transactions. Do not send bug-bounty target requests or run agents.
- Discovery records are not authorization. Require explicit target/program
  scope before any later active test. Keep credentials, cookies, tokens, and
  private customer data out of prompts, logs, and reports.
- Keep recon access behind a narrow read-only adapter when Phase 2 is
  authorized. Query and paginate; do not copy whole production tables or
  feed raw inventories to a model.
- Preserve evidence and distinguish hypotheses, leads, duplicates, rejected
  tests, and confirmed findings. Deterministic checks and clean controls are
  required before confirmation.
- For each future phase, inspect first, implement only that phase, test it,
  record decisions, and stop. Do not silently advance to the next phase.
