---
name: graphql-object-authorization
description: Compare a known GraphQL query and nested fields across controlled object owners and roles.
category: api
vulnerability_classes: [GRAPHQL_AUTHORIZATION, BOLA]
triggers: [GRAPHQL_AUTHORIZATION, GRAPHQL_QUERY]
prerequisites: [in_scope_target, graphql_operation, known_object_identifier, known_ownership, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [graphql_data_diff, ownership_matrix]
token_budget: 1800
request_budget: 6
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use when a real query operation and controlled object ownership are known.
when_not_to_use: Do not use for mutation-only paths or unverified lexical GraphQL matches.
alternatives: [graphql-mutation-authorization]
technologies: [graphql]
boundaries: [OWNER, TENANT]
---

# GraphQL object authorization

Preserve the observed operation envelope; no introspection or guessed IDs. Inspect GraphQL data and errors, not HTTP status alone.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: "Capture operation name, variables, selected protected fields, and ownership."}
  - {type: ESTABLISH_CONTROL, description: Establish owner query and foreign-owner denied controls.}
  - {type: EXECUTE_REQUEST, description: Propose one controlled object-variable substitution.}
  - {type: COMPARE_RESPONSE, description: Compare GraphQL data and errors for protected fields.}
controls: [Owner query, Foreign-owner query, Invalid controlled object]
positive_signals: [Foreign actor receives protected GraphQL object or nested field]
negative_signals: [Foreign object is null or denied without protected data]
evidence_requirements: [Observed query operation, Known ownership, Valid sessions, Owner baseline]
confirmation_requirements: [GraphQL data proof, Ownership mismatch, Fresh reproduction]
rejection_conditions: [Only HTTP 200 with GraphQL error, Public field, Authorized sharing]
action_intents: [AUTHORIZATION_TEST]
```
