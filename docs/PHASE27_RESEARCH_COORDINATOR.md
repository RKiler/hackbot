# Phase 27: ResearchCoordinator and Source-Backed Knowledge

## Authority

Research is advisory. A Target Package remains the scope authority; Phase 13/14
policy and traffic execution, Phase 15 skill validation, Phase 16 run ownership,
and Phase 17 validation remain unchanged. `ResearchCoordinator` has no
`TrafficExecutor`, browser, target-client, or Finding creation path. A source
reference is documentation, never runtime proof that a target is vulnerable.

The coordinator accepts only a structured `KnowledgeGap` emitted by a current
target-bound `NEEDS_RESEARCH` hypothesis, exposure candidate, or API candidate.
The private API does not accept an arbitrary topic, URL, query, report, or
payload. Existing specialist behavior is unchanged: no candidate automatically
triggers web research. Operator action starts at most two local research tasks
concurrently. Cancellation is recorded; an interrupted `RESEARCHING` task is
reconciled to `PARTIAL` after process restart and is never replayed silently.

## Typed records and persistence

`ResearchRequest` includes request/target/gap/hypothesis references, topic,
technology, category, specialist, budget, private/external flags, status,
timestamps, cache key, brief link, and per-request usage. Gap types include
unknown technology/framework/protocol/security primitive/object relationship/
product concept/auth mechanism, new API style/framework, skill gap, and low
hypothesis confidence. Statuses include `PENDING`, `CACHE_HIT`, `RESEARCHING`,
`COMPLETED`, `PARTIAL`, `FAILED`, `BLOCKED`, `STALE`, and `CANCELLED`.

`ResearchBrief` is a compact immutable version: topic, optional target binding,
summary, vulnerability classes, cited patterns, implementation details,
boundaries, false positives, static signals, runtime controls, limitations,
conflicts, existing skill hints, source IDs/quality, retrieval/expiry times, and
content hash. Research lives in BugHunter SQLite migration 034, not production
recon PostgreSQL. Source references persist title, publisher, canonical HTTPS
URL, type, quality, publication date when known, and retrieval date. Full
articles, scraped HTML, cookies, and credentials are not stored in briefs.
Every source link also creates compact `RESEARCH_REFERENCE` Evidence and a
`RESEARCHED` or `DOCUMENTED` Fact; neither is `OBSERVED` target behavior.
Hypothesis links preserve advisory skill/false-positive hints without changing
priority or status. Existing Findings remain Phase 17-only.
Target-documentation and manual relationship snippets may add cited
`documented_relation` Facts; they do not establish `OBSERVED` ownership.

The source registry distinguishes personal confirmed findings, disclosed
HackerOne reports, security research, PortSwigger, OWASP, vendor/framework docs,
academic work, GitHub research, researcher writeups, target docs, skills,
BugHunter observations, and manual sources. Quality is bounded and labeled,
not a probability of target exploitability. Personal-finding lookup returns
only generalized confirmed-category patterns; historical records need no
bulk migration. Disclosed-report text is reduced to cited preconditions, root
cause, signal, controls, impact, and false-positive lessons rather than copied
into agent context. A future richer source extractor can retain this provider
interface and audit contract.

## Providers, budgets, and cache

Local skill metadata and generalized confirmed finding patterns are consulted
first. `ManualResearchProvider` supports approved offline fixtures/imports.
`BraveWebResearchProvider` is optional and requires `[research] enabled=true`,
an opaque `search_secret_ref` configured through Phase 7 SecretProvider, and
any extra public knowledge hosts explicitly listed in `allowed_source_hosts`.
There is no provider token in TOML, Git, logs, or API responses. The web provider
uses the fixed Brave search endpoint, HTTPS-only vetted knowledge hosts,
robots-aware bounded retrieval, no redirects, and a transparent user agent.
Configured source hosts must be public DNS names; a public-address DNS check
runs before retrieval. This is a fail-closed preflight, not DNS pinning against
rebinding by a malicious configured host, so only trusted knowledge hosts
should be added.
It rejects result hosts matching a tracked target package; an inventory beyond
the bounded check fails closed. Search snippets can still produce `PARTIAL`
briefs when page bodies are blocked or unavailable. No bulk HackerOne scrape,
arbitrary web proxy, login-gated source access, or public bounty-target request
is implemented.

Per-request hard caps are 3 searches, 8 sources, 128 KiB source data, 4,000
estimated output tokens, and 60 seconds; defaults are smaller. The deterministic
extractor makes no model calls and records `model_calls=0`, estimated input/
output tokens, search count, source count, and source bytes. Only safe generic
technology/category terms are sent to public search. Credential-looking values,
private hostnames, email addresses, URLs, and long identifiers are rejected.
For private targets, a free-form hypothesis statement is never searched
publicly: only a separately structured, sanitized technology term can be used.
Local data remains available when external research is off or fails. Provider
errors yield `PARTIAL`/`FAILED`/`BLOCKED` metadata rather than stopping other
BugHunter work.

Cache keys include the gap category, technology/topic, and research version.
Generic public protocol research can be shared across targets; product/object
relationships and unsafe private topics are target-bound. A fresh brief causes
`CACHE_HIT`; a stale or expired brief can be refreshed into a new version.
Old versions and their citations remain queryable even if a source disappears.
TTL is 7 days for new-framework/API-style questions and 30 days otherwise.
`FRESH`, `STALE`, and `EXPIRED` describe research age, not target currentness.

## Untrusted content and skill boundary

Source HTML is parsed as text, not executed. Scripts/styles are discarded.
Instruction-like fragments, shell commands, and code fences are excluded from
compact pattern extraction. There is no model context receiving raw page text.
External text cannot override `AGENTS.md`, scope, policy, or validators. A
`SKILL_GAP` may create an `EphemeralSkillProposal` with exact brief/source IDs,
triggers, prerequisites, methodology hints, controls, and confirmation needs.
It remains `ADVISORY`: no automatic skill execution, file installation, or
permanent promotion. Phase 15 validation and researcher review are required
before any future use. One finding cannot rewrite global skill priority.

## Private API and dashboard

The private service exposes target-bound gap, request, metrics, and brief reads;
research, stale refresh, and cancel are explicit POSTs. The existing same-origin
gateway allowlists only these routes, enforces dashboard authentication and
CSRF, and strips client cookies/Authorization headers before proxying. The
`/hackbot/research` view shows gap priority, topic, specialist, request status,
freshness, quality, skill hints, compact brief sections, citations, and related
hypothesis provenance. The Target detail Research tab summarizes gaps and
cached work. No full scraped page or secret Evidence body is exposed.

## Limits and Phase 28 handoff

Extraction is deterministic and deliberately shallow; it may miss nuanced
source claims, and search snippets alone are not authoritative. Research
metrics show requests, briefs, hypothesis links, and later confirmed links,
not causal bounty value. The brief's sourced guidance can inform a later
planner's ranking and skill choice, but Phase 28 must still retrieve a small
target Evidence context and independently gate every experiment through the
existing policy, run, and validation path. Phase 27 adds no continuous
scheduling, autonomous cross-specialist plan, notification, or report draft.
