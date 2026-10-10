# Architecture

## System

```text
PROGRAM / SCOPE ENGINE
        |
        v
IDENTITY REGISTRY ---- SECRET PROVIDER
        |
        v
AUTH / SESSION MANAGER
   |              |
Browser        HTTP Context
   \              /
    v            v
NORMAL-BEHAVIOUR + OBJECT/OWNERSHIP MODEL
                |
                v
EXISTING RECON DB + TRAFFIC + JS + TARGET NOTES
                |
                v
ATTACK-SURFACE MODEL / TARGET ONTOLOGY
                |
                v
TECH/FEATURE PROFILER
                |
                v
HYPOTHESIS GENERATOR
                |
                v
SKILL ROUTER <---- RESEARCH COORDINATOR
                |
                v
TASK DEPENDENCY GRAPH
                |
      +---------+----------+
      |         |          |
Authorization Client-side API/Other Research Agents
      |         |          |
      +---------+----------+
                |
                v
OBJECT FACTORY / CONTROLLED EXECUTOR
                |
                v
DETERMINISTIC VALIDATORS
                |
       +--------+--------+
       |        |        |
   REJECTED   REVIEW   CONFIRMED
                         |
                         v
                  NOTIFY / REPORT
```

## Key distinctions

### Agent vs skill

A research agent is the reasoning worker. A skill is a compact playbook describing how to investigate a specific vulnerability pattern.

Examples:

- Authorization Research Agent + `cross-tenant-object-access` skill
- Client-Side Research Agent + `check-before-transform-dom-xss` skill
- Client-Side Research Agent + `postmessage-capability-confusion` skill

### Recon vs HackBot state

Existing recon remains the source of truth for large machine-collected data such as hosts, endpoints, JS and historical scans.

HackBot stores research state such as identities, ownership facts, skills, hypotheses, tasks, experiments, evidence references, findings and rejections.

### Research vs exploitation

ResearchCoordinator fills knowledge gaps and creates concise ResearchBriefs. It does not directly confirm vulnerabilities.

### Hypothesis vs finding

A hypothesis is a testable security claim. A finding exists only after independent validation and reproducible evidence.
