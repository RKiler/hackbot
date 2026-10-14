# Implementation Roadmap

This is the authoritative Phase 24-33 sequence from the Phase 23 roadmap review (decisions D-136 and D-137). Phases 0-23 were complete at that review. Phases 24-26 were delivered afterward; Phases 27-33 remain. Completion status may advance, but the phase numbers below do not change. Future sessions must use this numbering rather than conflicting older blueprint labels or phase-specific next-step recommendations. Use the phase implementation docs and `docs/DECISIONS.md` for delivered behavior. Do not infer active-testing authorization from recon membership or from a roadmap phase.

## Complete at reconciliation (0-23)

| Phase | Delivered focus |
| --- | --- |
| 0 | VPS and production recon discovery |
| 1 | Standalone project foundation |
| 2 | Read-only recon adapter |
| 3 | Evidence and fact store |
| 4 | Core domain model |
| 5 | Target Package and scope model |
| 6 | Identity registry |
| 7 | SecretProvider and AuthContext |
| 8 | Browser and session manager |
| 9 | Vendor-neutral Traffic Store |
| 10 | Burp capture integration |
| 11 | Private service and dashboard control plane |
| 12 | Bounded passive target profiles and hypotheses |
| 13 | Deterministic scope, risk, and rate policy |
| 14 | Policy-gated traffic executor |
| 15 | Skill registry and bounded plans |
| 16 | Single-plan Investigation Orchestrator |
| 17 | Deterministic Validator Engine |
| 18 | Object Factory and disposable-object ledger |
| 19 | Authorization specialist |
| 20 | Typed authorization mutations |
| 21 | DOM XSS specialist |
| 22 | postMessage / MessagePort specialist |
| 23 | Sensitive exposure specialist |

Completion of a phase does not imply complete coverage of its bug class. In particular, Phase 12 profiling is passive and bounded; Phase 16 orchestrates one plan, not cross-specialist campaigns; and Phases 19-20 support only narrow, observed GraphQL authorization cases.

## Reconciled sequence (24-33)

Phases 24-26 have been delivered. Implement Phases 27-33 in the order below. Each phase reuses the existing Target Package authority, Phase 13/14 execution gates, Phase 16 run records, and Phase 17 independent confirmation rather than creating a parallel path.

### Phase 24 - Cold-start bootstrap (complete)

Build bounded target context when recon coverage is absent or thin, without treating discovery as active-testing authorization.

### Phase 25 - Target/normal-behaviour learning (complete)

Learn observed workflows, operations, roles, and object relationships from trusted, existing traffic without treating observations as policy or findings.

### Phase 26 - GraphQL/API specialist expansion (complete)

Expand beyond the existing narrow single-ID GraphQL query and typed rename mutation. Use observed operations and schemas to cover operation, field, nested-object, mutation, bulk, and API authorization boundaries with owned controls and independent validation.

### Phase 27 - ResearchCoordinator

Research specific knowledge gaps using bounded, source-backed retrieval. Cache concise ResearchBriefs, attribute sources, and keep outside material advisory rather than authoritative for scope, execution, or findings.

### Phase 28 - Cross-specialist planner

Select minimal evidence context, rank hypotheses, route specialists and skills, manage request/token budgets and backtracking, and invoke existing validators. This is distinct from the completed Phase 16 single-plan orchestrator.

### Phase 29 - Notifications/reports

Add deduplicated notifications for confirmed findings and explicitly labeled high-value manual-review leads. Generate reports from validated evidence and preserve the distinction between leads and confirmed findings.

### Phase 30 - Production hardening

Define retention and backup/recovery, observability, resource controls, operational safeguards, and failure handling before long-running autonomous campaigns.

### Phase 31 - Campaign coordination

Coordinate bounded, resumable multi-hypothesis campaigns across specialists with explicit limits, state, pause/resume, and evidence-aware deduplication. Do not treat a campaign as authority to bypass per-action policy.

### Phase 32 - Continuous delta hunting

Use new or changed recon observations to trigger only relevant, deduplicated campaign work after the planner and campaign controls are stable. Do not replay the entire recon corpus or treat delta presence as active-testing authorization.

### Phase 33 - Evaluation/benchmarking

Evaluate against local or recorded cases and measure precision, false positives, coverage, requests per useful result, token use, manual interventions, recovery, and confirmed-finding yield. Keep this last so it measures the completed pipeline.

## Superseded blueprint labels

The original roadmap's labels and any phase-specific next-step recommendations that conflict with the sequence above are historical, not instructions to start work under those numbers. In particular:

| Older label or recommendation | Authoritative disposition |
| --- | --- |
| Original Phase 5-12 planning labels | Use the completed-phase table above and the implementation decisions, not those original labels, for delivered work. |
| Phase 9 target profiler / normal-behaviour learner | Phase 9 delivered Traffic Store; Phase 12 delivered bounded passive profiles; full learning is Phase 25. |
| Phase 16 ResearchCoordinator | Phase 16 delivered the single-plan Investigation Orchestrator; ResearchCoordinator is Phase 27. |
| Phase 17 static-analysis layer | Phase 17 delivered the Validator Engine; static analysis is embedded in relevant specialists, not a pending Phase 17. |
| Phase 20 GraphQL authorization capability | Phase 20 delivered typed authorization mutations; broader GraphQL/API work is Phase 26. |
| Phase 23 recommendation to make the planner Phase 24 | Phase 24 is cold-start bootstrap; the cross-specialist planner is Phase 28. |
| Phase 24 planner / orchestrator | Phase 28 cross-specialist planner; Phase 16 single-plan orchestration is already complete. |
| Phase 25 notifications and reporting | Phase 29 notifications/reports. |
| Phase 26 delta hunter / campaign mode | Split into Phase 31 campaign coordination and Phase 32 continuous delta hunting. |
| Phase 27 evaluation harness | Phase 33 evaluation/benchmarking. |

## V1 completion gate

Do not call V1 successful until the system can:

1. ingest recon context;
2. authenticate multiple identities safely;
3. learn target roles/objects;
4. generate one bounded hypothesis;
5. select one skill;
6. resolve prerequisites;
7. run one permitted experiment;
8. validate it independently;
9. persist evidence and classification;
10. resume correctly after restart.
