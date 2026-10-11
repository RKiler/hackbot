---
name: check-before-transform-dom-xss
description: Trace attacker input validated before decoding or normalization into an executable browser sink.
category: client-side
vulnerability_classes: [DOM_XSS]
triggers: [DOM_XSS]
prerequisites: [in_scope_target, current_js, attacker_controlled_source, transformation_trace, dangerous_dom_sink]
risk: LOW
required_validators: [browser_execution, source_sink_trace]
token_budget: 2000
request_budget: 4
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for a current bundle with a traceable source, security decision, later transform, and sink.
when_not_to_use: Do not use for static sink strings or reflection without a reachable browser path.
alternatives: [postmessage-trust-analysis]
technologies: [javascript]
boundaries: [CLIENT_SERVER_TRUST]
---

# Check-before-transform DOM XSS

Trace source to validation, transformation, and sink. Do not confirm from source maps alone. Later runtime proof must use a harmless DOM marker in a fresh browser.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: Resolve the current bundle hash and full source-to-sink trace.}
  - {type: ESTABLISH_CONTROL, description: Plan benign input and direct-dangerous negative controls.}
  - {type: VERIFY_BROWSER, description: Later test only supported transformation variant with harmless execution marker.}
  - {type: COMPARE_RESPONSE, description: Distinguish execution from reflection or navigation.}
controls: [Benign allowed input, Direct dangerous input rejected, Encoded transform candidate]
positive_signals: [Current browser executes harmless marker after post-check transform]
negative_signals: [Final value remains inert or browser controls block execution]
evidence_requirements: [Current JS hash, Attacker-controlled source, Validation-transform-sink trace, Browser control plan]
confirmation_requirements: [Fresh browser execution, Negative controls, CSP and sandbox behavior, Duplicate check]
rejection_conditions: [Static-only path, Reflection only, Open redirect only, Stale bundle]
action_intents: []
```
