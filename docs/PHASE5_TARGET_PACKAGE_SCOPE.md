# Phase 5: Target Packages and Authoritative Scope

Target packages are local, human/program-authorized configuration. They are not
the recon corpus. A host's presence in recon, including under a recon wildcard,
does not grant BugHunter testing authorization. An active component must later
require an affirmative `ProgramScope` decision and applicable policy decision.
This phase provides pure evaluation only; it sends no traffic.

## Layout and configuration

```text
targets/<package-id>/
  target.yaml             required, machine-readable
  scope.md                optional human-readable scope text
  program_rules.md        optional program-rule text
  context.md              optional product context
  researcher_notes.md     optional private research notes
  accounts.yaml           optional non-secret aliases for Phase 6
```

See the fictional package at `tests/examples/targets/example/`. `target.yaml`
schema version 1 requires `id`, `target_id` (a Phase 4 Target ID), `name`,
`primary_domain`, `configured_at`, `source`, `scope`, `rules`, `autonomy`, and
`rate`. The directory name must equal `id`. `updated_at` defaults to
`configured_at`; status defaults to `TRACKED` (`PAUSED` and `ARCHIVED` deny
combined authorization). `source.kind` is one of `HACKERONE`, `BUGCROWD`,
`PRIVATE_DOCUMENT`, `RESEARCHER`, or `IMPORTED_SCOPE`, with an operator and
optional private reference. Timestamps must include a timezone.

The default target root is beside the optional BugHunter config file, normally
`~/.config/bughunter-agent/targets`. Set `[targets].root` in local TOML to
override it. CLI operations are local and read-only:

```bash
hackbot target validate tests/examples/targets/example
hackbot target show example
```

`show` reads the configured target root. Both commands print a bounded,
redacted JSON summary marked `authority: TARGET_PACKAGE` and
`recon_inventory: NOT_CONSULTED`; they do not print context documents,
program references, operator names, or secret references. `health` and
`status` still do not connect to recon.

## Scope semantics

`scope.include` requires at least one exact hostname or `*.domain` pattern.
`scope.exclude` has the same host-rule syntax. Host rules may have local
`schemes` and `ports`; top-level `scope.schemes`/`scope.ports` are defaults.
Defaults permit HTTP/HTTPS at their standard ports unless restricted.
Explicit ports must be 1-65535. Hostnames are lowercased, trailing dots
removed, and IDNA-normalized. Wildcards match one or more complete labels
below the apex, including deeper descendants, but **not** the apex itself.
`*.example.test` matches `a.example.test` and `b.a.example.test`, not
`example.test`, `notexample.test`, or `example.test.attacker.test`.

Decision order:

1. Invalid or ambiguous URL: `UNKNOWN`.
2. Matching explicit host exclusion: `OUT_OF_SCOPE` (overrides inclusion).
3. No matching host inclusion: `UNKNOWN` (never affirmative).
4. Disallowed scheme or port: `OUT_OF_SCOPE`.
5. With path rules, ambiguous path: `UNKNOWN`.
6. Matching path exclusion: `OUT_OF_SCOPE` (overrides path inclusion).
7. With path inclusions, no matching path inclusion: `OUT_OF_SCOPE`.
8. Otherwise: `IN_SCOPE`.

The explicit exclusion's own scheme/port constraints apply if given. An
unqualified exclusion covers all schemes/ports for that host. Path rules can
target an exact host or wildcard and use `EXACT` or segment-boundary `PREFIX`.
`/api` prefix matches `/api` and `/api/x`, not `/apix`. Query strings do not
change path scope. No percent decoding, path collapsing, or slash rewriting is
performed. With path rules present, percent escapes, backslashes, semicolons,
repeated slashes, and dot segments produce `UNKNOWN`; future traffic must deny
such unknown decisions. Userinfo, fragments, malformed ports, and control
characters are also not authorized. Decisions include a reason, matched rule
when available, and package ID; private source references remain withheld.

## Program and autonomy policy

`rules` preserves structured common metadata: automation and account-creation
permission, excluded vulnerability classes, forbidden actions, third-party and
data-handling restrictions, and special notes. `scope.md` and
`program_rules.md` preserve human-readable program text. The structured
rules are not a substitute for reviewing that text and confirming current
program policy. Unknown automation or account-creation permission requires
approval for the corresponding non-passive action; explicit disallow denies.
Excluded vulnerability classes are metadata for future consumers, not a
current execution filter.

`autonomy` has decisions `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` for risk levels
`PASSIVE`, `SAFE_READ`, `BOUNDED_ACTIVE`, `STATE_CHANGING`, `DESTRUCTIVE` and
specific actions (disposable-object create/modify/delete, cross-identity,
account creation, external side effect, permission change, financial). False
or true YAML values are accepted as deny/allow. The more restrictive risk or
action decision wins. Actions cannot be evaluated below their minimum risk;
cross-identity requires at least safe-read, while mutating/sensitive actions
require state-changing. Modify/delete/cross-identity require the owned-test-
object flag. A non-tracked package or non-affirmative scope always denies in
`TargetPackage.evaluate_url`. This is a pure policy assessment, not an action
executor or the final active-request ScopeGuard.

`rate` records future request limits: requests/second, optional
requests/minute, max concurrency, and burst. These are validated bounds, not
an implemented throttle; a later TrafficExecutor will enforce them.

## Secret and recon boundaries

`accounts.yaml` may list aliases with optional role/tenant hints and
`secret_ref: ref:<alias>`. Phase 6 can import this metadata into the Identity
Registry; it is not a secret provider. Raw credential-like keys/values in YAML and
known credential patterns in markdown are rejected, using the Phase 1
redactor. The check is defense in depth, not a guarantee against arbitrary
unlabeled secret text. Do not put passwords, cookies, bearer tokens, API keys,
MFA values, or session material in target packages. Optional markdown is read
only when explicitly requested and never included wholesale in summaries.

`resolve_recon_target(package, repository)` is an optional lookup through the
Phase 2 read-only interface. It returns a recon record or `None`; neither
outcome changes package scope. Phase 6 implements only the Identity Registry
with opaque references, keeping these scope and policy checks authoritative
and leaving login/session automation deferred.
