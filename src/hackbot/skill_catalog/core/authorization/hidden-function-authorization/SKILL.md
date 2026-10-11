---
name: hidden-function-authorization
description: Test whether an observed backend operation hidden from a lower-role UI is enforced server-side.
category: authorization
vulnerability_classes: [BFLA, HIDDEN_FUNCTION]
triggers: [ROLE_AUTHORIZATION, INTERNAL_SURFACE, HIDDEN_FUNCTION]
prerequisites: [in_scope_target, role_hidden_operation, multiple_roles, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [role_matrix, protected_effect]
token_budget: 1400
request_budget: 4
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use when JS or captured traffic shows an actual backend function absent in a lower-role UI.
when_not_to_use: Do not use when only a route string or hidden button is known without runtime behavior.
alternatives: [vertical-role-authorization]
boundaries: [ROLE]
---

# Hidden-function authorization

UI visibility is only a clue. Capture the higher-role request and expected policy before a controlled lower-role comparison.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Identify observed backend operation and UI role difference.}
  - {type: ESTABLISH_CONTROL, description: Capture a higher-role successful control.}
  - {type: EXECUTE_REQUEST, description: Propose lower-role request with its own session.}
  - {type: COMPARE_RESPONSE, description: Verify protected result or durable effect.}
controls: [Higher-role request, Lower-role expected denial]
positive_signals: [Hidden operation succeeds for lower role with meaningful impact]
negative_signals: [Server rejects lower role or returns public content only]
evidence_requirements: [Observed operation, Verified roles, Legitimate request shape]
confirmation_requirements: [Permission model known, Server-side bypass, State read-back for mutation]
rejection_conditions: [UI-only cosmetic hiding, Public endpoint, Lower role legitimately delegated]
action_intents: [AUTHORIZATION_TEST]
```
