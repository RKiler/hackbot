---
name: protected-response-exposure
description: Re-read one exact observed scoped response and verify non-public configuration or credential disclosure.
category: exposure
vulnerability_classes: [EXPOSURE]
triggers: [EXPOSURE, CONFIG_DISCLOSURE, DEBUG_ENDPOINT, BACKUP_ARTIFACT]
prerequisites: [in_scope_target]
risk: LOW
required_validators: [current_response, credential_semantics, public_by_design_check]
token_budget: 1000
request_budget: 1
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for an exact Phase 14 captured anonymous response whose protected bytes may contain non-public application secrets.
when_not_to_use: Do not guess paths, enumerate archives, use credentials, or claim a stack trace alone is exploitable.
alternatives: [sensitive-data-exposure]
features: [configuration, debug, backups]
boundaries: [ANONYMOUS]
---

# Protected response exposure

Bind one observed GET URL without carrying cookies or headers. Re-read once through the policy engine and executor. Compare exact content hash, reject samples and public identifiers, and stop after minimum proof.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Recheck exact protected capture and scoped URL.}
  - {type: EXECUTE_REQUEST, description: Re-read the same URL anonymously once.}
  - {type: COMPARE_RESPONSE, description: Compare current hash and non-public semantics.}
controls: [Original controlled capture, Fresh anonymous response, Public and placeholder classification]
positive_signals: [Current non-public application credential in the same response]
negative_signals: [Denied, changed, public, placeholder, or unrelated content]
evidence_requirements: [Exact request observation, Protected original body, Fresh protected response]
confirmation_requirements: [Current same-body proof, Non-public credential, Target relevance]
rejection_conditions: [Sample data, Public client identifier, Login page, Changed body]
action_intents: []
```
