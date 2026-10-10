# Skills and Research Engine

## Purpose

Skills are vulnerability-specific research playbooks. Research fills gaps when existing skills/knowledge are insufficient.

## Skill sources

```text
skills/
├── core/       # our best custom bounty skills
├── imported/   # curated/adapted public skills
└── personal/   # generalized methods learned from successful findings
```

Use an Agent Skills compatible format where practical so good external skill repositories can be selectively reused. Do not automatically activate hundreds of imported skills.

## Progressive disclosure

At routing time, load only small metadata:

- name;
- description;
- category;
- triggers;
- prerequisites;
- risk;
- validator requirements.

Load full `SKILL.md` only for selected skills. Load references/scripts only when needed.

## Standard skill sections

- Objective
- When To Use
- Do Not Use When
- Required Context
- Recon Queries
- Preconditions
- Hypotheses To Generate
- Investigation Workflow
- Controls
- Candidate Ranking
- Runtime Testing
- Confirmation Standard
- Rejection Conditions
- Evidence Required
- Token / Request Budget

## Important custom skills

Initial high-value playbooks should include:

### Authorization
- cross-tenant-object-access
- horizontal-object-access
- vertical-role-bypass
- custom-role-backend-bypass
- hidden-function-authorization
- UI-backend-permission-mismatch
- nested-resource-authorization
- batch-endpoint-authorization

### GraphQL
- graphql-operation-discovery
- graphql-object-authorization
- graphql-field-authorization
- graphql-mutation-authorization
- graphql-nested-resource-authorization
- graphql-hidden-operation

### Client-side
- check-before-transform-dom-xss
- postmessage-origin-validation
- postmessage-capability-confusion
- messageport-rpc-trust
- client-side-sensitive-exposure

## Skill routing

1. deterministic triggers;
2. metadata scoring;
3. optional tiny LLM routing call only when ambiguous.

Examples:

- `MessageChannel` + message listener -> postMessage/MessagePort skills;
- GraphQL operation artifacts -> GraphQL skills;
- multiple tenants + object IDs -> cross-tenant authorization skills;
- URL source + decoder + sink -> DOM XSS skills.

## ResearchCoordinator

Research only when there is a defined gap:

- UNKNOWN_TECHNOLOGY
- UNKNOWN_PROTOCOL
- UNKNOWN_SECURITY_PRIMITIVE
- UNKNOWN_OBJECT_RELATIONSHIP
- SKILL_GAP
- LOW_HYPOTHESIS_CONFIDENCE
- NEW_FRAMEWORK

Research sources may include local skills, prior HackBot knowledge, public documentation, reputable security research, public vulnerability writeups, framework docs and relevant open source.

Output a small cached `ResearchBrief` containing:

- technology/pattern;
- target-specific relevance;
- priority attack patterns;
- implementation details;
- known false positives;
- recommended skills;
- useful static/runtime signals;
- source references/freshness.

Do not inject full articles into hunter prompts.

## Ephemeral skills

Research may create target-specific temporary skills. They remain ephemeral until repeated success or researcher review justifies promotion.

## Learn from our findings

Successful findings should be generalized into reusable personal skills. Track per-skill metrics:

- runs;
- candidates;
- confirmed findings;
- false positives;
- tokens;
- requests;
- severity/yield where useful.
