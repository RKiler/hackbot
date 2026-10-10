# Minimal Data Model

Use the existing recon DB for bulk recon. HackBot persists research state separately unless Phase 0 proves a cleaner integrated design.

## Core entities

### Target
Program/asset identity, scope/rules reference and current profile.

### Identity / Principal / Role / Tenant
Configured account and observed application identity/authorization relationships.

### AuthContext
Session metadata and secret references, never raw secrets in normal research tables.

### ObjectReference
Application object type/id, tenant, creator/owner, source evidence and disposable state.

### Fact
`subject, predicate, object, confidence, evidence_ids`

### Evidence
Immutable ID, type, target, timestamp, source, content/hash reference, metadata and redaction status.

### Hypothesis
Specific testable security claim with prerequisites, controls, positive/negative signals, risk, priority and lifecycle state.

### Experiment
Concrete bounded test linked to hypothesis, identity, objects, policy decision and outputs.

### Task
Dependency-graph node with inputs, outputs, status, dependencies, owner agent and retry policy.

### SkillMetric
Runs, candidates, confirmed/rejected, token/request cost and quality/yield metrics.

### ResearchBrief
Cached compact research result with sources and freshness.

### Finding
Confirmed or manual-review result that references evidence and validator outcome.

## Avoid premature duplication

Do not create new host/endpoint/JS tables if existing recon tables already provide them reliably. Store stable references/adapters instead.
