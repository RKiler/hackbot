---
name: overexposed-api-response
description: Compare an observed owner response with a lower-role response for one policy-restricted field.
category: exposure
vulnerability_classes: [EXPOSURE]
triggers: [OVEREXPOSED_API_RESPONSE]
prerequisites: [in_scope_target, authenticated_endpoint, verified_sessions, sensitive_artifact, baseline_traffic]
risk: MEDIUM
required_validators: [field_policy, owner_control, role_boundary]
token_budget: 1200
request_budget: 3
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use with an owned disposable object, two verified roles, and a sourced field-access policy.
when_not_to_use: Do not infer field privacy from a name, guess object IDs, or use unowned data.
alternatives: [sensitive-data-exposure]
features: [API response fields]
boundaries: [ROLE]
---

# Overexposed API response

Run only one observed owner GET, one lower-role GET to the same owned object, and one invalid-object control. Confirm only if a trusted field policy marks the returned field restricted to the owner role.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: "Verify owned fixture, roles, field policy, and request provenance."}
  - {type: EXECUTE_REQUEST, description: Owner baseline read.}
  - {type: EXECUTE_REQUEST, description: Lower-role boundary read.}
  - {type: EXECUTE_REQUEST, description: Invalid-object control.}
  - {type: COMPARE_RESPONSE, description: Compare only policy-restricted field presence and hash.}
controls: [Owner baseline, Lower-role read, Invalid-object denial]
positive_signals: [Restricted field value returned to lower role]
negative_signals: [Field omitted or resource public]
evidence_requirements: [Trusted field policy, Role facts, Three audited responses]
confirmation_requirements: [Verified role difference, Exact object, Restricted field disclosure]
rejection_conditions: [Public field, Missing policy fact, Unrelated object]
action_intents: []
```
