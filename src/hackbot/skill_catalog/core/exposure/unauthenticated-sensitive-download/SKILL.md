---
name: unauthenticated-sensitive-download
description: Compare protected owner download metadata with anonymous retrieval using one owned artifact.
category: exposure
vulnerability_classes: [EXPOSURE, DOWNLOAD]
triggers: [EXPOSURE, DOWNLOAD]
prerequisites: [in_scope_target, authenticated_endpoint, verified_sessions, sensitive_artifact, baseline_traffic]
risk: MEDIUM
required_validators: [content_hash_match, authorization_control]
token_budget: 1400
request_budget: 4
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for a private owned document or export with an observed download route.
when_not_to_use: Do not use for public documents or unknown third-party files.
alternatives: [sensitive-data-exposure]
features: [downloads, exports]
boundaries: [AUTHENTICATED]
---

# Unauthenticated sensitive download

Compare owned authenticated retrieval to anonymous retrieval of the same controlled artifact. Never persist sensitive file bytes in the plan.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: "Establish ownership, privacy expectation, and observed download route."}
  - {type: ESTABLISH_CONTROL, description: Capture authenticated owner content hash.}
  - {type: EXECUTE_REQUEST, description: Propose one anonymous retrieval for policy simulation.}
  - {type: COMPARE_RESPONSE, description: Compare response hashes and protected-content indicators.}
controls: [Authenticated owner download, Anonymous retrieval, Invalid artifact]
positive_signals: [Anonymous response matches private owner artifact]
negative_signals: [Anonymous request denied or serves only public content]
evidence_requirements: [Owned private artifact metadata, Owner traffic, Redacted content hash]
confirmation_requirements: [Protected-content equality, Privacy expectation, Fresh reproduction]
rejection_conditions: [Intentionally public share link, Generic login HTML, Redirect without file]
action_intents: [SAFE_READ]
```
