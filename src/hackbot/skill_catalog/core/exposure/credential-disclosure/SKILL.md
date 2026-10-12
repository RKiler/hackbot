---
name: credential-disclosure
description: Review a current anonymous first-party asset for a non-public credential used by the application.
category: exposure
vulnerability_classes: [EXPOSURE, INFORMATION_DISCLOSURE]
triggers: [CREDENTIAL_EXPOSURE, EXPOSURE]
prerequisites: [in_scope_target, sensitive_artifact]
risk: LOW
required_validators: [current_artifact, credential_semantics, public_by_design_check]
token_budget: 1200
request_budget: 0
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for protected evidence of an exact current first-party JS or source-map credential.
when_not_to_use: Do not use for public client IDs, placeholders, stale assets, or unknown service privileges.
alternatives: [sensitive-data-exposure]
boundaries: [DATA_EXPOSURE]
---

# Credential disclosure

Use protected artifact evidence and a bound candidate fingerprint. Do not use the credential. Confirm only current anonymous reachability, non-public secret semantics, target association, and actual use in application code. Otherwise request manual review.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Inspect protected current artifact metadata.}
  - {type: ESTABLISH_CONTROL, description: Freeze candidate and current artifact fingerprints.}
  - {type: COMPARE_RESPONSE, description: Compare public and placeholder controls without a network request.}
controls: [Current anonymous asset, Public identifier rejection, Placeholder rejection]
positive_signals: [Current non-public credential used in application request construction]
negative_signals: [Stale asset, Public browser identifier, Placeholder, Unrelated provider]
evidence_requirements: [Controlled anonymous retrieval, Artifact hash, Protected source evidence]
confirmation_requirements: [Current source, Target relevance, Non-public secret semantics]
rejection_conditions: [Public client ID, Test data, Stale artifact]
action_intents: []
```
