---
name: postmessage-trust-analysis
description: Map sender, origin/source checks, transferred ports, and privileged message capabilities.
category: client-side
vulnerability_classes: [POSTMESSAGE, MESSAGEPORT]
triggers: [POSTMESSAGE]
prerequisites: [in_scope_target, current_js, message_listener]
risk: LOW
required_validators: [origin_control, capability_proof]
token_budget: 2000
request_budget: 5
version: 1.0.0
source: CORE
execution_mode: PLAN_ONLY
when_to_use: Use for reachable message receivers or MessageChannel protocols crossing origins.
when_not_to_use: Do not require a DOM XSS sink or claim impact from a listener alone.
alternatives: [check-before-transform-dom-xss]
technologies: [javascript]
boundaries: [CROSS_ORIGIN]
---

# postMessage trust analysis

Model sender, receiver, event.origin, event.source, accepted data, channel creation, port transfer, and RPC methods. Determine what private data or action crosses origin.

## Plan
```yaml
workflow:
  - {type: OBSERVE, description: "Reconstruct message types and origin/source validation."}
  - {type: OBSERVE, description: Trace MessagePort possession and RPC capabilities if present.}
  - {type: ESTABLISH_CONTROL, description: "Compare trusted sender, unrelated origin, wrong source, and wrong type."}
  - {type: VERIFY_BROWSER, description: Later demonstrate a harmless protected capability in an owned browser.}
controls: [Trusted sender, Unrelated origin, Wrong message type, Wrong source window]
positive_signals: [Foreign origin obtains privileged data or capability]
negative_signals: [Untrusted sender cannot gain privileged effect]
evidence_requirements: [Current handler location, Origin/source checks, Protocol sequence, Capability inventory]
confirmation_requirements: [Foreign-origin controlled proof, Sensitive effect, Negative controls, Fresh browser]
rejection_conditions: [Public message only, No sensitive effect, Harness-only behavior]
action_intents: []
```
