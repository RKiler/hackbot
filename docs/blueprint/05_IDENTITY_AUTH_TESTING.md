# Identity and Authenticated Testing

## First-class entities

- Account: configured test identity.
- Principal: actual application user identity.
- Role: admin/member/custom role/etc.
- Tenant: organization/workspace/company boundary.
- AuthContext: complete authenticated request identity.

## Authentication modes

1. Imported session: researcher supplies current authorized browser/Burp/session state.
2. Browser-assisted login: isolated browser context; human handles MFA/CAPTCHA/SSO if needed.
3. Program-approved provisioning: optional target-specific account creation only when allowed.

## Session isolation

Each identity has its own browser context, cookie jar, bearer tokens, CSRF state, tenant headers and session metadata.

Never mix accounts.

## Session health

Before auth comparisons, verify session is valid with a harmless authenticated endpoint and identify the expected principal. Status:

- VALID
- EXPIRED
- REAUTH_REQUIRED
- LOCKED
- UNKNOWN

Never interpret a login redirect as authorization behaviour.

## Normal-behaviour learner

Before boundary tests, observe legitimate workflows per identity and build:

- ROLE x FEATURE map;
- PRINCIPAL x ACTION x OBJECT x TENANT results;
- known object ownership;
- UI/backend differences.

## Object ownership

Prefer known owned objects over random ID increments.

Example matrix:

```text
                 org1-object     org2-object
org1_admin          OWN             FOREIGN
org1_member      SAME_TENANT         FOREIGN
org2_admin          FOREIGN           OWN
```

## Traffic attribution

Every useful request should reference identity, role, tenant, endpoint and object when known.

## Auth abstraction

Agents should request:

```python
traffic.replay(request_id="REQ-192", as_identity="org2_admin")
```

The executor resolves cookies/tokens/CSRF/tenant headers. Raw secrets stay outside model context.
