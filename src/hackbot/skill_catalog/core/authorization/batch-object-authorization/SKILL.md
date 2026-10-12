---
name: batch-object-authorization
description: Compare a small observed batch read against a mixed owned and foreign object selection.
category: authorization
vulnerability_classes: [BOLA, IDOR]
triggers: [BATCH]
prerequisites: [in_scope_target, authenticated_endpoint, multiple_tenants, known_object_identifier, known_ownership, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [ownership_matrix, response_diff, protected_content]
token_budget: 1600
request_budget: 4
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use only for an observed two-ID GET batch with three verified disposable objects.
when_not_to_use: Do not use for writes, unbounded arrays, inferred methods, or unknown IDs.
alternatives: [cross-tenant-object-authorization]
boundaries: [TENANT]
---

# Batch object authorization

The source owner request must contain exactly two owned IDs. Bind a third
object from another verified tenant, then compare the foreign item in a mixed
batch by its own ID and protected fields. A 200 or aggregate count is not proof.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Verify all three owned object references and exact source request.}
  - {type: EXECUTE_REQUEST, description: Owner two-object batch control.}
  - {type: EXECUTE_REQUEST, description: Acting identity own-object control.}
  - {type: EXECUTE_REQUEST, description: Mixed owned and foreign batch.}
  - {type: EXECUTE_REQUEST, description: Fresh bounded mixed-batch reproduction.}
  - {type: COMPARE_RESPONSE, description: Compare each returned object with its owner control.}
controls: [Owner batch returns both owner objects, Acting identity reads its own object]
positive_signals: [Mixed batch returns the protected foreign object]
negative_signals: [Foreign object filtered or entire batch denied]
evidence_requirements: [Three verified disposable IDs, Owner batch response, Two verified sessions]
confirmation_requirements: [Per-object protected content, Two reproducible mixed reads]
rejection_conditions: [Public object, Authorized sharing, Aggregate-only response]
action_intents: [AUTHORIZATION_TEST]
```
