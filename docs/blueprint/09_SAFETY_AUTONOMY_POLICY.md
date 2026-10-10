# Scope, Safety and Autonomy

The goal is high autonomy inside explicit authorized boundaries, not unrestricted activity.

## Risk levels

- PASSIVE
- SAFE_READ
- BOUNDED_ACTIVE
- STATE_CHANGING
- DESTRUCTIVE

## Deterministic guards

Every active operation must pass:

- ScopeGuard
- TargetPolicy
- RiskPolicy
- RatePolicy
- MethodPolicy

Decision:

- ALLOW
- DENY
- REQUIRE_APPROVAL

Do not rely on model reasoning alone for scope enforcement.

## Recommended target policy

Autonomous when explicitly configured:

- passive analysis;
- safe reads;
- disposable-object creation;
- modifications/deletion of disposable objects;
- cross-identity tests involving researcher-owned/program-provided test accounts and owned test objects.

Require approval:

- user invitations/external communication;
- changes to real permissions;
- actions affecting non-test data;
- ambiguous side effects.

Deny by default:

- financial actions;
- destructive actions;
- testing third-party/out-of-scope origins;
- accessing unrelated real-user data;
- credential theft or MFA/CAPTCHA bypass.

## Human interruptions should be rare and meaningful

Expected reasons:

- MFA/CAPTCHA/SSO step;
- unclear scope/program rule;
- missing account relationship;
- high-risk side effect;
- strong finding needing human judgment;
- manual verification when deterministic validation is insufficient.
