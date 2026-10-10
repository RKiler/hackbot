---
name: cross-tenant-object-access
description: Test tenant-level authorization for known object identifiers using authorized identities from different tenants. Do not use for same-tenant horizontal access.
category: authorization
risk: bounded_active
requires_accounts: 2
requires_validator: authorization_boundary_validator
---

# Objective

Identify missing tenant ownership enforcement using known owned objects and valid sessions.

# Required Context

- at least two valid identities in different tenants;
- one known object per relevant tenant where possible;
- known endpoint/operation acting on the object.

# Recon Queries

Retrieve only endpoints/operations referencing the object type or identifier and relevant authenticated traffic.

# Workflow

1. Validate sessions.
2. Confirm ownership of test objects.
3. Run owner control.
4. Replay the exact operation using foreign authorized identity against owned test object.
5. Compare semantic result and side effects.
6. Reproduce if positive.

# Confirmation

Require proven tenant mismatch plus unauthorized protected action/data and successful owner controls.

# Reject If

- resource is intentionally shared/public;
- session is invalid;
- result is only cosmetic/error-code variance;
- ownership is unknown.
