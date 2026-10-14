---
name: api-observed-read
description: Compare a current observed API read across verified disposable object owners.
category: api
vulnerability_classes: [API_AUTHORIZATION, BOLA]
triggers: [API_AUTHORIZATION, FIELD_AUTHORIZATION]
prerequisites: [in_scope_target, known_object_identifier, known_ownership, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [api_semantic_data, ownership_matrix, negative_control]
token_budget: 1600
request_budget: 5
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use only with a current observed owner operation and two verified disposable objects.
when_not_to_use: Do not use for writes, inferred routes, guessed IDs, or unknown field policy.
alternatives: [graphql-object-authorization, cross-tenant-object-authorization]
technologies: [graphql, rest]
boundaries: [OWNER, TENANT, ROLE]
---

# Observed API read authorization

Keep the observed method, document, variables, and selection set. Compare two
owned controls, one invalid object, and two boundary reads. GraphQL HTTP 200
with null data or only errors is a denial, not proof. A field name alone does
not establish private classification. Do not generate arbitrary operations.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: "Review observed operation, object ownership, and field policy."}
  - {type: EXECUTE_REQUEST, description: Execute a bound owned or boundary read.}
  - {type: COMPARE_RESPONSE, description: Compare semantic data with independent controls.}
controls: [Owner read, Actor-owned read, Invalid object]
positive_signals: [Foreign actor receives protected object or restricted field]
negative_signals: [Foreign object is null or denied without protected data]
evidence_requirements: [Current observed operation, Verified objects, Valid sessions]
confirmation_requirements: [Semantic protected data, Ownership boundary, Fresh reproduction]
rejection_conditions: [Error-only response, Public or shared object, Unproven field policy]
action_intents: [AUTHORIZATION_TEST]
```
