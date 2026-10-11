---
name: internal-surface-candidate
description: Triage passive internal host or admin-panel references without probing VHOSTs or Host headers.
category: exposure
vulnerability_classes: [INTERNAL_SURFACE, EXPOSURE]
triggers: [INTERNAL_SURFACE, INTERNAL_HOST]
prerequisites: [in_scope_target]
risk: LOW
required_validators: [scope_review, current_reachability]
token_budget: 1000
request_budget: 0
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for a sourced internal hostname, panel reference, or administrative path candidate.
when_not_to_use: Do not treat lexical references as reachable or authorized targets.
alternatives: [hidden-function-authorization]
features: [admin functions]
boundaries: [INTERNAL]
---

# Internal surface candidate

Prepare a future bounded experiment only. Resolve authoritative scope before any Host-header or VHOST probe; none occurs in this phase.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Correlate source references and currentness without network probing.}
  - {type: MANUAL_REVIEW, description: Request explicit program scope and a bounded future validation method.}
controls: [In-scope first-party source, Stale or unrelated reference check]
positive_signals: [Scoped current service exposes a privileged surface]
negative_signals: [Historical string or unrelated infrastructure]
evidence_requirements: [Source record ID, Scope decision, Currentness marker]
confirmation_requirements: [Authorized current reachability, Sensitive function, Impact]
rejection_conditions: [Stale hostname, Third-party service, Lexical-only evidence]
action_intents: []
```
