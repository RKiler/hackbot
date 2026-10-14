---
name: typed-authorization-mutation
description: Compare a recipe-backed disposable object mutation across verified authorization boundaries with independent read-back.
category: authorization
vulnerability_classes: [BOLA, BFLA, CROSS_TENANT]
triggers: [CROSS_TENANT, ROLE_AUTHORIZATION, HIDDEN_FUNCTION]
prerequisites: [in_scope_target, authenticated_endpoint, known_ownership, verified_sessions, baseline_traffic]
risk: HIGH
required_validators: [ownership_matrix, state_readback, restore_readback]
token_budget: 1600
request_budget: 8
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use only with a pinned MutationRecipe, reserved verified disposable objects, and separate verified owner and boundary sessions.
when_not_to_use: Never use for real objects, arbitrary fields, missing read-back or cleanup, or unknown role semantics.
alternatives: [cross-tenant-object-authorization]
boundaries: [OWNER, ROLE, TENANT]
---

# Typed authorization mutation

The plan binds only opaque object, recipe, identity, and phase references. The dispatcher resolves an exact request from the pinned recipe and current object registry. Every action receives a fresh policy decision and one-use permit. A successful mutation response is not proof of effect. The optional disposable DELETE variant uses a separate owner-delete control and an owner preflight of the boundary target before the foreign attempt.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Verify disposable ownership and the expected permission boundary.}
  - {type: EXECUTE_REQUEST, description: Owner reads initial object state.}
  - {type: EXECUTE_REQUEST, description: Owner performs the typed control mutation.}
  - {type: EXECUTE_REQUEST, description: Owner independently reads back control state.}
  - {type: EXECUTE_REQUEST, description: Lower-authority actor attempts the same typed mutation.}
  - {type: EXECUTE_REQUEST, description: Owner independently reads back boundary state.}
  - {type: EXECUTE_REQUEST, description: Owner restores the original safe value.}
  - {type: EXECUTE_REQUEST, description: Owner reads back restored state.}
  - {type: COMPARE_RESPONSE, description: Compare verified state and record cleanup status.}
controls: [Owner mutation succeeds and reads back, Boundary expectation is evidenced, Original state is restored]
positive_signals: [Unauthorized durable state change on verified disposable object]
negative_signals: [Boundary mutation denied or read-back unchanged]
evidence_requirements: [Verified object ownership, Pinned recipe, Two verified sessions, Read-back exchanges]
confirmation_requirements: [Owner control, Independent boundary read-back, Permission expectation, Reproduction]
rejection_conditions: [Mutation response only, Failed owner control, Legitimate sharing, Missing read-back]
action_intents: [AUTHORIZATION_TEST]
```
