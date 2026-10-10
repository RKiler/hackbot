# Target Package

HackBot should support domain-only discovery, but serious hunting should use a small target package containing human-provided context while heavy technical data remains in the recon DB.

## Suggested structure

```text
/root/bughunter-targets/<target>/
├── target.yaml
├── scope.md
├── program_rules.md
├── accounts.yaml
├── context.md
├── researcher_notes.md
└── local_evidence/
```

## target.yaml example

```yaml
id: example
primary_domain: app.example.com

scope:
  include:
    - app.example.com
    - api.example.com
  exclude: []

rate_limit:
  requests_per_second: 1

autonomy:
  passive: true
  safe_read: true
  create_disposable_objects: true
  modify_disposable_objects: true
  delete_disposable_objects: true
  cross_identity_owned_object_tests: true
  permission_changes: require_approval
  external_side_effects: require_approval
  financial: deny
  destructive: deny
```

## accounts.yaml example

```yaml
accounts:
  org1_admin:
    role: admin
    tenant: org1
    secret_ref: example_org1_admin

  org1_member:
    role: member
    tenant: org1
    secret_ref: example_org1_member

  org2_admin:
    role: admin
    tenant: org2
    secret_ref: example_org2_admin
```

No passwords/cookies/tokens in this file.

## context.md

Short human knowledge such as business concepts, known roles, interesting functionality or target quirks. HackBot should improve its own target knowledge rather than treating this document as complete truth.

## Modes

### Domain-only

`hackbot discover example.com`

Passive/recon-driven profiling and recommendations for useful accounts/context.

### Authenticated hunt

`hackbot hunt example`

Uses target package, sessions, recon and learned target state.

### Campaign

`hackbot campaign example`

Processes target deltas and resumes ongoing research.
