---
name: horizontal-object-authorization
description: Compare same-tenant objects owned by separate principals with known ownership and product rules.
category: authorization
vulnerability_classes: [BOLA, IDOR, HORIZONTAL]
triggers: [HORIZONTAL, OBJECT_ID]
prerequisites: [in_scope_target, authenticated_endpoint, multiple_principals, known_object_identifier, known_ownership, verified_sessions, baseline_traffic]
risk: MEDIUM
required_validators: [ownership_matrix, response_diff]
token_budget: 1600
request_budget: 6
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for two owned principals in one tenant with distinct private objects.
when_not_to_use: Do not use for cross-tenant access or objects intentionally shared within a tenant.
alternatives: [cross-tenant-object-authorization]
boundaries: [OWNER]
---

# Horizontal object authorization

Check intended same-tenant sharing semantics first. Substitute only known controlled identifiers, one dimension at a time.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Record same-tenant ownership and sharing semantics.}
  - {type: ESTABLISH_CONTROL, description: Capture each principal reading its own object.}
  - {type: EXECUTE_REQUEST, description: Propose one controlled foreign-owner read.}
  - {type: COMPARE_RESPONSE, description: Compare protected fields and object identity.}
controls: [Principal A owner request, Principal B owner request, Clearly denied object]
positive_signals: [Non-owner receives private object or performs unauthorized change]
negative_signals: [Non-owner is denied or receives public-only fields]
evidence_requirements: [Same tenant membership, Distinct known ownership, Owner traffic, Redacted protected field diff]
confirmation_requirements: [Expected owner-only boundary, Protected content or effect, Reproduction]
rejection_conditions: [Tenant-wide sharing by design, Public object, Owner or delegated admin access]
action_intents: [AUTHORIZATION_TEST]
```
