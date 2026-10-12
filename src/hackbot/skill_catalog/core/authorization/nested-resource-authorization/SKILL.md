---
name: nested-resource-authorization
description: Compare a known child under its verified parent and a foreign disposable parent.
category: authorization
vulnerability_classes: [BOLA, IDOR]
triggers: [PARENT_CHILD]
prerequisites: [in_scope_target, authenticated_endpoint, multiple_tenants, known_object_identifier, known_ownership, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [ownership_matrix, response_diff, protected_content]
token_budget: 1600
request_budget: 4
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for a current observed nested GET with two verified parent objects and one verified child.
when_not_to_use: Do not use for inferred paths, unknown objects, or mutations.
alternatives: [cross-tenant-object-authorization]
boundaries: [TENANT]
---

# Nested resource authorization

Bind the child and both parents to verified disposable objects. Confirm that
the owner request and body agree on the parent-child relationship, then change
only the parent path segment. Independently compare protected child content.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Verify exact owner request and object relationship.}
  - {type: EXECUTE_REQUEST, description: Owner control.}
  - {type: EXECUTE_REQUEST, description: Invalid child control.}
  - {type: EXECUTE_REQUEST, description: Foreign parent and owned child boundary.}
  - {type: EXECUTE_REQUEST, description: Fresh bounded boundary reproduction.}
  - {type: COMPARE_RESPONSE, description: Compare protected child identity and content.}
controls: [Owner child under correct parent, Invalid child under correct parent]
positive_signals: [Foreign actor receives the protected child under its own parent]
negative_signals: [Foreign actor is denied or receives no protected child]
evidence_requirements: [Verified ownership facts, Observed parent-child response, Two verified sessions]
confirmation_requirements: [Protected child content, Two reproducible boundary reads]
rejection_conditions: [Public child, Authorized sharing, No child content]
action_intents: [AUTHORIZATION_TEST]
```
