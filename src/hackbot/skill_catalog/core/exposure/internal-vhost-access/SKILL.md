---
name: internal-vhost-access
description: Compare one sourced internal virtual host against normal and invalid Host controls on the same authorized destination.
category: exposure
vulnerability_classes: [INTERNAL_SURFACE]
triggers: [INTERNAL_VHOST_CANDIDATE]
prerequisites: [in_scope_target]
risk: MEDIUM
required_validators: [scope_review, current_reachability, protected_effect]
token_budget: 1000
request_budget: 3
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use only when explicit program policy permits bounded VHOST checks and the hostname is in current first-party evidence.
when_not_to_use: Never use for arbitrary Host guessing, IP scans, unapproved routing, or a login/title difference alone.
alternatives: [internal-surface-candidate]
features: [internal routing]
boundaries: [INTERNAL]
---

# Internal virtual-host access

The route and candidate Host are derived from one current in-scope artifact. Send exactly normal, deterministic invalid, and candidate Host controls to the same scoped destination. Stop on redirects and never disable TLS verification.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Recheck current first-party source and explicit VHOST permission.}
  - {type: EXECUTE_REQUEST, description: Normal Host control on one observed path.}
  - {type: EXECUTE_REQUEST, description: Invalid Host control on the same path.}
  - {type: EXECUTE_REQUEST, description: Sourced candidate Host on the same path.}
  - {type: COMPARE_RESPONSE, description: Compare protected content and authorization boundary.}
controls: [Normal Host, Invalid Host, Candidate Host]
positive_signals: [Candidate-only protected configuration or privileged content]
negative_signals: [Denied candidate Host, Equivalent public response, Branding-only change]
evidence_requirements: [Current source hash, Exact Host provenance, Policy decisions, Protected response evidence]
confirmation_requirements: [Explicit policy, Three controls, Candidate-only protected impact]
rejection_conditions: [Title-only variation, Login page, Untrusted or stale source]
action_intents: []
```
