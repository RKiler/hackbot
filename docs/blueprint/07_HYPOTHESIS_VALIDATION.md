# Hypotheses, Experiments and Validation

## Hypothesis structure

Every active investigation has:

- ID;
- category;
- specific security statement;
- prerequisites;
- supporting facts/evidence;
- control experiment;
- boundary experiment;
- positive signal;
- negative signal;
- risk level;
- priority;
- status.

Example:

```text
AUTH-0042
Statement: POST /api/integrations/{id}/test may not enforce tenant ownership.
Control: org1_admin invokes the operation on org1 disposable object.
Boundary: org2_admin invokes the same operation on org1 disposable object.
Positive: protected result/action succeeds cross-tenant.
Negative: authorization failure.
```

## Intermediate verification

Verify claims separately:

`endpoint exists -> object ownership known -> session valid -> owner control works -> boundary test -> semantic result -> reproduction`

## Hunter/validator separation

Hunter produces candidates. Validator attempts to reproduce/disprove with deterministic rules wherever possible.

### Authorization validator

Compare status, normalized body, object identity, tenant identity, semantic data and side effects. HTTP 200 alone is insufficient.

### DOM XSS validator

Require attacker-controlled source, complete source/transform/sink trace, controls, browser execution proof and fresh-context reproduction.

### postMessage validator

Require unrelated attacker origin, exact protocol, missing/bypassable trust validation, unauthorized capability, controls and fresh-context reproduction.

## ObjectFactory

When experiments require objects, resolve prerequisites in this order:

1. knowledge store;
2. recon DB;
3. authenticated traffic;
4. operation registry;
5. safe creation of disposable owned object;
6. research;
7. researcher input.

Track each test object:

- type/id;
- creator identity;
- tenant;
- creation evidence;
- experiment purpose;
- disposable flag;
- cleanup method/status.

## Side-effect classification

- SAFE_READ
- SAFE_CREATE
- SAFE_UPDATE
- SAFE_DELETE
- EXTERNAL_SIDE_EFFECT
- PERMISSION_CHANGE
- FINANCIAL
- DESTRUCTIVE
- UNKNOWN

Only safe actions explicitly allowed by target policy execute autonomously.
