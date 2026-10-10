# Start Here

## Goal

Build `/root/bughunter-agent` from scratch while integrating closely with the existing `/root/enhanced_recon_framework` and VPS environment.

HackBot should help discover more valid bounty findings by combining:

- existing recon data;
- authenticated test accounts;
- target-specific application understanding;
- reusable vulnerability skills;
- just-in-time security research;
- hypothesis-driven testing;
- deterministic validation;
- persistent evidence and learning;
- delta-based continuous hunting;
- low token and request usage.

## Expected operator experience

For a mature target, the operator should normally provide only:

- scope/program rules;
- authorized accounts or sessions;
- role/tenant labels when known;
- optional short context/notes;
- autonomy/risk policy.

HackBot should discover the rest where possible from recon, JS, traffic, browser state, public documentation and research.

## Main operating modes

### Discover

`hackbot discover <target>`

Use existing recon and passive analysis to profile the application, technologies, features, trust boundaries and useful account requirements.

### Hunt

`hackbot hunt <target>`

Use target package + recon DB + authenticated sessions to select skills, generate hypotheses and run safe bounded tests.

### Campaign

`hackbot campaign <target>`

Watch recon deltas and investigate only new or changed attack surface, using existing target knowledge and sessions.

## Do not do this

Do not build:

- one monolithic autonomous agent;
- an unrestricted shell/network bot;
- a system that dumps the whole recon DB into model context;
- a scanner that declares bugs from anomalies alone;
- a system that mixes credentials into prompts;
- a workflow that asks the researcher for data the system can discover itself.

## Build order

Follow `02_ROADMAP.md`. Codex must finish and test one phase before beginning the next.
