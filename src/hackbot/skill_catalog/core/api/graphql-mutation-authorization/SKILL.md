---
name: graphql-mutation-authorization
description: Test a captured GraphQL mutation against disposable objects and lower-authority identities.
category: api
vulnerability_classes: [GRAPHQL_AUTHORIZATION, BFLA, BOLA]
triggers: [GRAPHQL_MUTATION, GRAPHQL_AUTHORIZATION]
prerequisites: [in_scope_target, graphql_operation, graphql_mutation, verified_sessions, known_ownership, baseline_traffic]
risk: HIGH
required_validators: [state_readback, role_matrix]
token_budget: 1800
request_budget: 6
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use when a real mutation envelope and disposable owned object are known.
when_not_to_use: Do not use for queries or non-disposable production objects.
alternatives: [graphql-object-authorization]
technologies: [graphql]
boundaries: [OWNER, ROLE, TENANT]
---

# GraphQL mutation authorization

All mutation proposals need policy review, a disposable object, and read-back. Preserve the captured operation and modify only one authorization variable.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Record observed mutation envelope and controlled object state.}
  - {type: ESTABLISH_CONTROL, description: Capture authorized mutation on a disposable fixture.}
  - {type: EXECUTE_REQUEST, description: Propose one lower-authority mutation variant for policy review.}
  - {type: COMPARE_RESPONSE, description: Read back owned object and inspect GraphQL errors.}
  - {type: MANUAL_REVIEW, description: Require cleanup and fresh reproduction before reporting.}
controls: [Authorized mutation, Lower-role expected denial, State read-back]
positive_signals: [Unauthorized durable state change]
negative_signals: [Mutation rejected without side effect]
evidence_requirements: [Captured mutation, Verified sessions, Disposable fixture, Ownership proof]
confirmation_requirements: [Durable effect, Read-back, Cleanup, Reproduction]
rejection_conditions: [HTTP 200 with mutation errors, Authorized role, No durable change]
action_intents: [AUTHORIZATION_TEST]
```
