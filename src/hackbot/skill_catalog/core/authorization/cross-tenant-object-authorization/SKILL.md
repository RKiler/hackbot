---
name: cross-tenant-object-authorization
description: Compare known owned objects across separate tenants; never infer authorization from a status code alone.
category: authorization
vulnerability_classes: [BOLA, IDOR, CROSS_TENANT]
triggers: [CROSS_TENANT]
prerequisites: [in_scope_target, authenticated_endpoint, multiple_tenants, known_object_identifier, known_ownership, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [ownership_matrix, response_diff, protected_content]
token_budget: 1800
request_budget: 6
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use when two owned identities belong to different tenants and controlled objects have known ownership.
when_not_to_use: Do not use for same-tenant horizontal access or unknown customer objects.
alternatives: [horizontal-object-authorization]
boundaries: [TENANT]
---

# Cross-tenant object authorization

Use only owned tenant A and B objects. Establish both owner controls before swapping a single object reference. Verify the returned protected fields or durable effect; do not guess IDs.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: "Identify the tenant, principal, owner, parent, and controlled object IDs."}
  - {type: ESTABLISH_CONTROL, description: Capture valid owner requests for A and B objects.}
  - {type: EXECUTE_REQUEST, description: Propose one foreign-tenant object substitution under an owned session.}
  - {type: COMPARE_RESPONSE, description: Compare protected content and tenant ownership against owner and denied controls.}
  - {type: MANUAL_REVIEW, description: Require fresh reproduction and policy-aware impact review.}
controls: [Owner A reads object A, Owner B reads object B, Foreign-owned object is denied or redacted]
positive_signals: [Foreign identity receives protected object data or durable unauthorized effect]
negative_signals: [Foreign identity receives no protected content or effect]
evidence_requirements: [Known ownership facts, Two verified owned sessions, Owner baseline traffic, Redacted response comparison]
confirmation_requirements: [Ownership mismatch proven, Valid controls, Protected content or effect, Fresh reproduction]
rejection_conditions: [Intentionally public object, Authorized sharing, Admin scope permits access]
action_intents: [AUTHORIZATION_TEST]
```
