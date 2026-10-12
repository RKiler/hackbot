# Phase 23: Sensitive Exposure and Internal Surface Specialist

## Boundary and ownership

`ExposureSpecialist` is a deterministic, target-scoped lead generator. Recon remains the owner of host, endpoint, JS metadata, and scan history. BugHunter owns exposure candidates, source links, hypotheses, plans, run evidence, validation, and findings in its own SQLite store (schema 22). Recon presence never authorizes testing: the Target Package and Phase 13 policy govern every Phase 14 request. The specialist does not fetch arbitrary URLs, enumerate IDs, scan internal ranges, guess backup names, or use leaked credentials.

An `ExposureCandidate` has one of 15 categories: unauthenticated resource/download, PII, credential/config, JS/source-map secret, debug/admin/backup, internal-host/service/VHOST, overexposed API response, or unknown exposure. It stores only opaque source/evidence IDs, a redacted location, sensitivity, rank, status, and optional credential class, length, and SHA-256 fingerprint. Candidate status is not finding status. Repeated secret fingerprints deduplicate across bundles while preserving source links and updating the current representative hash. A changed hash reopens validation without deleting the historical finding; stale artifact links invalidate an unsupported candidate.

## Discovery and ranking

- Recon discovery is bounded by host and endpoint caps and uses only observed, scoped rows. Unchanged recon pointers reuse their local Evidence row. Admin, backup, debug, and config paths are leads, not proof.
- Saved Phase 21 JS and source-map bodies are analyzed without execution. The static pass caps JS at 1 MiB, maps at 8 MiB/32 embedded sources, and signals at 128. It scores credential shape, entropy, key semantics, application usage, and source context, while penalizing placeholders, test values, public identifiers, and browser configuration. A source-map URL alone is not exposure.
- Internal host references include private IPs, localhost, internal/service-discovery names, and unusual ports. Without demonstrated reachability or protected capability they remain informational or `NEEDS_RESEARCH`; the referenced host is never automatically scanned.
- Existing TrafficStore owner/anonymous pairs and captured HTTP_RESPONSE evidence can yield protected-resource or config leads. A field-comparison lead requires two verified identities, the exact same scoped GET URL and JSON body hash. Field names alone do not establish intended privacy.
- Anonymous access, current sensitive material, private object policy, recent change, and sourced internal routing raise priority; stale, public, placeholder, or out-of-scope material lowers it.

## Controlled verification

An owned read binds an existing observed owner GET to one Phase 18 verified disposable object and a verified owner session. Its skill plan uses an owner control, anonymous equivalent, bounded repeat, and invalid-object control. Phase 16 reconstructs only the bound request; Phase 13 policy and Phase 14 executor gate every send. Phase 17 compares actual content and trusted private/sensitive Facts, not just a 200 or a response length. Public contact data and denied anonymous reads reject.

The field comparison binds one observed owner/member pair, an owned object, and two verified sessions. Same-tenant role exposure needs a trusted `field_visibility` Fact naming the restricted field and role. Cross-tenant private PII needs independently sourced `PRIVATE` visibility and `SENSITIVE` classification plus distinct verified tenant membership. The validator inspects only a bounded protected JSON body, confirms the same object/value and denied invalid-object control, and never emits the value in a finding.

For current JS/source-map credentials, validation checks exact current asset hash, artifact source, placeholder/public-identifier exclusions, target association, and evidence of application relevance. It does not authenticate with the value or contact third-party providers. Unknown service types remain `NEEDS_RESEARCH`. A config, backup, or debug candidate sourced from an observed capture may be re-read once through the executor with exact current hash; a stack trace alone does not confirm. Protected HTTP_RESPONSE capture is bounded and redacted from API responses. Oversized or compressed bodies exceeding the executor cap are truncated and not promoted to exposure artifacts; archives are never extracted.

An internal VHOST check is opt-in through `internal_vhost_testing_allowed` in the Target Package. The host value must come from current first-party evidence. The executor sends normal, invalid, and sourced candidate Host controls to the *same authorized external destination*, disallows redirect following, and retains TLS verification. Phase 17 currently confirms only candidate-only non-public credential content; branding, title, and login page alone reject. Other admin capabilities remain manual review. There is no arbitrary Host probe API.

## Validation, privacy, and audit

Only Phase 17 may create a finding. Its exposure validators require current scope/policy evidence, a real protected-data boundary, clean controls, exact source binding, response provenance, and deduplication. Confirmation stops at the minimum proof; no additional sensitive records are enumerated. Candidate metadata, hypothesis context, default API, and dashboard expose fingerprints, labels, and opaque evidence IDs rather than secrets or PII. Protected Evidence remains behind its existing access controls.

The audit chain is Finding -> Validation -> PlanRun -> Skill -> Hypothesis -> ExposureCandidate -> source Evidence/Traffic/JS/map -> policy/permit. Metrics expose category and status counts, validation outcomes, request use, sensitive evidence count, rejection status reasons, and stop-on-proof events.

## Dashboard and API

The private service offers target-scoped candidate list/detail, metrics, current artifact and capture selectors, verified field-exchange selectors, offline discovery/analysis, and plan binding by opaque IDs. The authenticated `/hackbot/exposure` dashboard uses the existing CSRF-protected gateway. It does not provide raw secret reveal, arbitrary URL fetch, arbitrary Host input, or automatic credential validation. Separate gateway changes must be deployed through the normal operations workflow; code tests alone do not imply the running production dashboard has reloaded.

## Limits and next phase

These checks are deliberately narrow. Static analysis may miss obfuscated or runtime-built secrets; a private Fact must come from trusted target evidence or controlled fixtures; production VHOST routing may be SNI-dependent and is not bypassed by disabling TLS. No broad backup-path discovery, credential login, or internal network scanning is included. Phase 24 should implement the roadmap's cross-specialist planner/orchestrator: retrieve minimal context, rank hypotheses, route skills, budget requests/tokens, backtrack safely, and invoke existing validators without expanding this phase's traffic authority.
