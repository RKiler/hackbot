# Token and Request Efficiency

Token efficiency is a core architecture requirement, not later optimization.

## Rules

1. Query structured data before LLM calls.
2. Use deterministic filtering, AST parsing, regex, hashing, diffs and parsers first.
3. Build a compact context packet for one hypothesis.
4. Reference evidence by ID rather than repeating raw blobs.
5. Cache JS/source-map analysis by content hash.
6. Analyze only deltas when assets are unchanged.
7. Load only selected skill bodies.
8. Cache common ResearchBriefs.
9. Require compact structured model output.
10. Track token/call/request budget per hypothesis.
11. Use deterministic validators rather than LLM confirmation.
12. Keep secrets out of prompts.

## Desired funnel

```text
28,000 recon URLs
        ↓ deterministic filtering
150 relevant endpoints/assets
        ↓ relationship/risk scoring
20 hypotheses
        ↓ compact DB context
5-10 high-priority experiments
        ↓ deterministic validation
confirmed/rejected/review
```

Not:

`all recon + all JS + all traffic + all skills -> giant LLM prompt`

## ModelGateway

All model calls pass through one gateway that records:

- model;
- prompt/template version;
- trace ID;
- input/output tokens;
- latency;
- retries/timeouts;
- hypothesis ID;
- budget consumed.

## Context packets

Typical authorization packet should include only endpoint/method, relevant parameter/object IDs, identity/tenant relationships, controls, small response summaries and evidence references.
