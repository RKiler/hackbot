---
name: sensitive-data-exposure
description: Review a current in-scope response or artifact for non-public data with strict redaction.
category: exposure
vulnerability_classes: [EXPOSURE, INFORMATION_DISCLOSURE]
triggers: [EXPOSURE, PII_EXPORT, CREDENTIAL_EXPOSURE]
prerequisites: [in_scope_target, sensitive_artifact]
risk: LOW
required_validators: [sensitivity_review, public_by_design_check]
token_budget: 1500
request_budget: 2
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for an evidence-linked response that appears to expose non-public data or credentials.
when_not_to_use: Do not use for token-shaped strings, public client IDs, or route names alone.
alternatives: [unauthenticated-sensitive-download]
boundaries: [DATA_EXPOSURE]
---

# Sensitive data exposure

Classify source, audience, currentness, and sensitivity. Do not retrieve or place secret values in planning context; validators later determine impact.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Inspect only redacted evidence metadata and audience.}
  - {type: OBSERVE, description: Compare public-by-design and placeholder explanations.}
  - {type: MANUAL_REVIEW, description: Specify the smallest safe validation needed without using a discovered credential.}
controls: [Public configuration control, Current asset and intended audience]
positive_signals: [Non-public protected value exposed to unauthorized audience]
negative_signals: [Public identifier or test fixture with no privileged capability]
evidence_requirements: [Current exposure location, Redacted type and fingerprint, Intended audience]
confirmation_requirements: [Current reachability, Sensitivity, Unauthorized audience, Impact]
rejection_conditions: [Public browser key, Placeholder, Stale artifact, Unrelated third party]
action_intents: []
```
