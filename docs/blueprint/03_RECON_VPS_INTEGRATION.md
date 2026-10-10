# Recon and VPS Integration

## Principle

HackBot must become native to the existing VPS/recon system rather than creating a parallel universe.

## Phase 0 discovery checklist

Codex must inspect and document:

- Docker Compose files and running services;
- database engine(s), credentials mechanism and connection code;
- tables/models for domains, subdomains, live hosts, endpoints, parameters, JS assets, source maps, JS analysis, endpoint-JS links, scan history and deltas;
- existing target/scope representation;
- notification/Telegram components;
- saved HTTP/Burp request data if any;
- cron/tmux/workers relevant to recon;
- existing APIs/repositories that can be safely reused.

## Adapter rule

Agents never directly query production recon tables. Implement a read-only repository layer.

Suggested interface:

```python
class ReconRepository(Protocol):
    def get_target(self, target_id): ...
    def list_hosts(self, target_id): ...
    def list_endpoints(self, target_id, filters=None): ...
    def list_parameters(self, target_id, filters=None): ...
    def list_js_assets(self, target_id, changed_since=None): ...
    def get_js_analysis(self, asset_id): ...
    def list_graphql_artifacts(self, target_id): ...
    def list_changes(self, target_id, since): ...
```

## Query, do not dump

The model should ask structured questions such as:

- which endpoints contain `workspaceId`?
- which JS assets changed since the last hunt?
- which requests reference object 782?
- which operations are present in JS but absent from traffic?

It should not receive complete endpoint or JS inventories unless explicitly required.

## Delta-first hunting

Prefer:

`previous recon -> diff -> changed surface -> hypotheses`

Prioritize new/changed:

- hosts;
- endpoints;
- parameters;
- JS hashes;
- GraphQL operations;
- features;
- auth/permission behaviour.

## Reuse

If the existing recon framework already provides scope validation, notification or parsing utilities, wrap/reuse them rather than replacing them unless tests demonstrate a limitation.
