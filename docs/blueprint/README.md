# HackBot Codex Blueprint

This folder is the implementation brief for building an evidence-driven, recon-aware, authenticated bug-bounty research agent on the VPS.

## Read order

1. `00_START_HERE.md`
2. `AGENTS.md`
3. `01_ARCHITECTURE.md`
4. `02_ROADMAP.md`
5. `03_RECON_VPS_INTEGRATION.md`
6. `04_TARGET_PACKAGE.md`
7. `05_IDENTITY_AUTH_TESTING.md`
8. `06_SKILLS_RESEARCH_ENGINE.md`
9. `07_HYPOTHESIS_VALIDATION.md`
10. `08_TOKEN_EFFICIENCY.md`
11. `09_SAFETY_AUTONOMY_POLICY.md`
12. `10_DATA_MODEL.md`
13. `CODEX_BOOTSTRAP_PROMPT.md`

## Design principle

HackBot is not a giant prompt, scanner, or payload sprayer. It is a research system:

`recon + authenticated context -> target model -> hypotheses -> skills -> bounded experiments -> deterministic validation -> evidence -> findings/learning`

The LLM proposes. The system verifies.
