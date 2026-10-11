---
name: vertical-role-authorization
description: Compare a privileged operation across verified higher and lower roles in the same authorized tenant.
category: authorization
vulnerability_classes: [BFLA, VERTICAL, ROLE_AUTHORIZATION]
triggers: [ROLE_AUTHORIZATION, ROLE_ADMIN]
prerequisites: [in_scope_target, authenticated_endpoint, multiple_roles, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [role_matrix, state_readback]
token_budget: 1500
request_budget: 5
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for observed admin or manager operations with a lower-role owned identity.
when_not_to_use: Do not use when roles or expected permission semantics are unknown.
alternatives: [hidden-function-authorization]
boundaries: [ROLE]
---

# Vertical role authorization

Use a real higher-role baseline and the lower role's own session. For writes, require a disposable fixture and read-back before any confirmation.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Establish roles and expected permission for the exact operation.}
  - {type: ESTABLISH_CONTROL, description: Capture higher-role valid request and lower-role denied control.}
  - {type: EXECUTE_REQUEST, description: Propose a single lower-role replay against a disposable fixture if needed.}
  - {type: COMPARE_RESPONSE, description: Compare protected fields or durable state.}
controls: [Higher-role authorized request, Lower-role denied or harmless baseline]
positive_signals: [Lower role completes privileged operation or receives protected data]
negative_signals: [Backend enforces role regardless of UI]
evidence_requirements: [Verified role assignments, Observed request shape, Disposable fixture for writes]
confirmation_requirements: [Expected role restriction, Unauthorized effect, Read-back for mutation]
rejection_conditions: [Custom role grants access, Operation is available to members by design]
action_intents: [AUTHORIZATION_TEST]
```
