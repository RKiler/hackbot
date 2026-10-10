from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.domain import (
    Endpoint, EndpointCategory, Feature, GraphQLOperation, GraphQLOperationType,
    Host, JavaScriptAsset, Lifecycle, ObjectLifecycle, ObjectReference,
    ObservationState, Operation, OperationKind, Parameter, ParameterLocation,
    Principal, RequestRecord, ResponseRecord, Role, SourceRef, Target,
    Technology, Tenant, TrafficSource, new_entity_id, normalize_hostname,
    normalize_method, normalize_path, normalize_url, validate_entity_id,
)
from hackbot.domain_recon import (
    endpoint_from_recon, host_from_recon, js_asset_from_recon,
    source_from_recon, target_from_recon,
)
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.recon import Provenance, ReconEndpoint, ReconHost, ReconJsAsset, ReconTarget
from hackbot.store import EvidenceFactStore


NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
EV = "EV-" + "a" * 32
DIGEST = hashlib.sha256(b"fixture").hexdigest()


class DomainModelTests(unittest.TestCase):
    def setUp(self):
        self.target = Target(name="Fixture", root_domain="Example.COM.", created_at=NOW)
        self.host = Host(target_id=self.target.id, hostname="APP.Example.COM.",
                         scheme="HTTPS", port=443, created_at=NOW)

    def test_target_creation_stable_id_and_json(self):
        self.assertRegex(self.target.id, r"^TARGET-[0-9a-f]{32}$")
        self.assertEqual(self.target.root_domain, "example.com")
        self.assertEqual(self.target.observation_state, ObservationState.CONFIGURED)
        self.assertEqual(json.loads(self.target.to_json())["id"], self.target.id)
        self.assertEqual(self.target.to_json(), self.target.to_json())
        self.assertEqual(self.target.to_reference(), {"id": self.target.id, "type": "Target"})
        with self.assertRaises(FrozenInstanceError):
            self.target.id = new_entity_id("TARGET")

    def test_id_validation_and_evidence_reference_validation(self):
        self.assertEqual(validate_entity_id(self.target.id, "TARGET"), self.target.id)
        for bad in ("TARGET-1", "HOST-" + "a" * 32, "TARGET-" + "A" * 32):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Target(name="bad", id=bad)
        with self.assertRaises(ValueError):
            Host(target_id=self.target.id, hostname="ok.example", evidence_ids=("not-evidence",))
        with self.assertRaises(ValueError):
            Host(target_id=self.target.id, hostname="ok.example", evidence_ids=(EV, EV))
        with self.assertRaises(ValueError):
            Host(target_id=self.target.id, hostname="ok.example", evidence_ids=(["not-hashable"],))

    def test_host_normalization_scheme_port_and_target(self):
        self.assertEqual(self.host.hostname, "app.example.com")
        self.assertEqual(self.host.scheme, "https")
        self.assertEqual(self.host.origin, "https://app.example.com")
        self.assertEqual(Host(target_id=self.target.id, hostname="2001:DB8::1",
                              scheme="https", port=8443).origin, "https://[2001:db8::1]:8443")
        self.assertEqual(normalize_hostname("BUECHER.de"), "buecher.de")
        with self.assertRaises(ValueError):
            Host(target_id="TARGET-bad", hostname="app.example.com")
        with self.assertRaises(ValueError):
            Host(target_id=self.target.id, hostname="app.example.com/path")
        with self.assertRaises(ValueError):
            Host(target_id=self.target.id, hostname="app.example.com", port=65536)

    def test_endpoint_method_path_category_and_host(self):
        endpoint = Endpoint(target_id=self.target.id, host_id=self.host.id,
                            path="api/Project/{id}", method="get", category=EndpointCategory.HTTP)
        self.assertEqual((endpoint.path, endpoint.method), ("/api/Project/{id}", "GET"))
        self.assertEqual(endpoint.host_id, self.host.id)
        self.assertEqual(normalize_method("patch"), "PATCH")
        self.assertEqual(normalize_path("/A//B"), "/A//B")
        with self.assertRaises(ValueError):
            Endpoint(target_id=self.target.id, host_id=self.host.id, path="/api?q=secret")
        with self.assertRaises(ValueError):
            Endpoint(target_id=self.target.id, host_id=self.host.id, path="/", category="HTTP")

    def test_parameter_locations_and_associations(self):
        endpoint = Endpoint(target_id=self.target.id, host_id=self.host.id, path="/api")
        for location in ParameterLocation:
            item = Parameter(target_id=self.target.id, name="workspaceId",
                             location=location, endpoint_id=endpoint.id)
            self.assertEqual(item.location, location)
            self.assertEqual(item.endpoint_id, endpoint.id)
        operation = Operation(target_id=self.target.id, name="update", kind=OperationKind.RPC)
        self.assertEqual(Parameter(target_id=self.target.id, name="arg",
                                   location=ParameterLocation.RPC_ARGUMENT,
                                   operation_id=operation.id).operation_id, operation.id)
        with self.assertRaises(ValueError):
            Parameter(target_id=self.target.id, name="x", location=ParameterLocation.QUERY)
        with self.assertRaises(ValueError):
            Parameter(target_id=self.target.id, name="x", location="QUERY", endpoint_id=endpoint.id)
        with self.assertRaises(ValueError):
            Parameter(target_id=self.target.id, name="x", location=ParameterLocation.QUERY,
                      operation_id=123)

    def test_javascript_asset_hash_metadata_and_private_url(self):
        asset = JavaScriptAsset(target_id=self.target.id, host_id=self.host.id,
                                url="HTTPS://APP.EXAMPLE.COM/app.js?v=private-value",
                                sha256=DIGEST, size_bytes=100, http_status=200,
                                artifact_hash=DIGEST,
                                evidence_ids=(EV,), source_ref=SourceRef(provider="js_analysis", record_id="42"))
        self.assertEqual(asset.sha256, DIGEST)
        self.assertEqual(asset.artifact_hash, DIGEST)
        self.assertEqual(asset.source_ref.provider, "JS_ANALYSIS")
        self.assertEqual(asset.evidence_ids, (EV,))
        self.assertEqual(asset.url, "https://app.example.com/app.js?v=private-value")
        self.assertNotIn("private-value", repr(asset))
        self.assertNotIn("private-value", asset.to_json())
        self.assertEqual(asset.to_dict(include_private=True)["url"], asset.url)
        with self.assertRaises(ValueError):
            JavaScriptAsset(target_id=self.target.id, host_id=self.host.id,
                            url="https://app.example.com/app.js", sha256="not-a-hash")

    def test_principal_role_and_tenant_have_no_credentials(self):
        principal = Principal(target_id=self.target.id, label="org1_admin",
                              external_user_id="opaque-user-id")
        role = Role(target_id=self.target.id, name="member", external_role_id="role-raw")
        tenants = [Tenant(target_id=self.target.id, label="A", kind=kind, external_id="007")
                   for kind in ("organization", "workspace", "team")]
        self.assertEqual([item.kind for item in tenants], ["organization", "workspace", "team"])
        self.assertEqual(tenants[0].external_id, "007")
        self.assertEqual(role.target_id, principal.target_id)
        self.assertNotIn("org1_admin", repr(principal))
        self.assertNotIn("org1_admin", principal.to_json())
        self.assertNotIn("opaque-user-id", principal.to_json())
        self.assertNotIn("role-raw", role.to_json())
        names = {item.name.lower() for model in (Principal, Role, Tenant) for item in fields(model)}
        self.assertFalse(names & {"password", "cookie", "token", "authorization", "session", "mfa_secret"})

    def test_object_reference_opaque_uuid_composite_and_hints(self):
        principal = Principal(target_id=self.target.id, label="owner")
        tenant = Tenant(target_id=self.target.id, label="A", kind="organization")
        for external_id in ("opaque~ID_+", "00000000-0000-4000-8000-000000000000", "org:A/project:007"):
            obj = ObjectReference(target_id=self.target.id, object_type="API Key",
                                  external_id=external_id, tenant_id_hint=tenant.id,
                                  creator_principal_id_hint=principal.id, disposable=True)
            self.assertEqual(obj.external_id, external_id)
            self.assertEqual(obj.object_type, "api_key")
            self.assertTrue(obj.disposable)
            self.assertEqual(obj.tenant_id_hint, tenant.id)
            self.assertNotIn(external_id, obj.to_json())
        with self.assertRaises(ValueError):
            ObjectReference(target_id=self.target.id, object_type="project",
                            owner_principal_id_hint=principal.id,
                            observation_state=ObservationState.OBSERVED)
        observed = ObjectReference(target_id=self.target.id, object_type="project",
                                   owner_principal_id_hint=principal.id,
                                   observation_state=ObservationState.OBSERVED,
                                   evidence_ids=(EV,), lifecycle=ObjectLifecycle.ACTIVE)
        self.assertEqual(observed.evidence_ids, (EV,))

    def test_feature_and_technology_are_observations_not_truth(self):
        feature = Feature(target_id=self.target.id, name="Team Management",
                          observation_state=ObservationState.INFERRED, evidence_ids=(EV,))
        tech = Technology(target_id=self.target.id, host_id=self.host.id,
                          name="Next.js", confidence=0.7, evidence_ids=(EV,))
        self.assertEqual(feature.name, "team_management")
        self.assertEqual(tech.confidence, 0.7)
        self.assertEqual(tech.observation_state, ObservationState.INFERRED)
        with self.assertRaises(ValueError):
            Technology(target_id=self.target.id, name="React", confidence=1.1)
        with self.assertRaises(ValueError):
            Technology(target_id=self.target.id, name="React", confidence=True)

    def test_operation_and_graphql_are_separate_composed_models(self):
        gql = GraphQLOperation(target_id=self.target.id, operation_type=GraphQLOperationType.MUTATION,
                               name="UpdateProject", variable_names=("projectId", "input"),
                               document_artifact_hash=DIGEST, observed_in_traffic=True,
                               source_js_asset_id=new_entity_id("JS"),
                               evidence_ids=(EV,))
        operation = Operation(target_id=self.target.id, name="update project",
                              kind=OperationKind.GRAPHQL, graphql_operation_id=gql.id,
                              acts_on_type="Project")
        self.assertEqual((gql.operation_type, operation.acts_on_type),
                         (GraphQLOperationType.MUTATION, "project"))
        self.assertEqual(gql.to_dict()["variable_names"], ["projectId", "input"])
        self.assertTrue(gql.source_js_asset_id.startswith("JS-"))
        self.assertEqual(GraphQLOperation(target_id=self.target.id,
                         operation_type="mutation").operation_type, GraphQLOperationType.MUTATION)
        with self.assertRaises(ValueError):
            GraphQLOperation(target_id=self.target.id, operation_type="INVALID")
        with self.assertRaises(ValueError):
            GraphQLOperation(target_id=self.target.id, operation_type=GraphQLOperationType.QUERY,
                             variable_names=("id", "id"))
        with self.assertRaises(ValueError):
            GraphQLOperation(target_id=self.target.id, operation_type=GraphQLOperationType.QUERY,
                             variable_names=("$invalid",))

    def test_traffic_is_vendor_neutral_and_secret_safe(self):
        endpoint = Endpoint(target_id=self.target.id, host_id=self.host.id, path="/callback")
        principal = Principal(target_id=self.target.id, label="owned test user")
        for source in TrafficSource:
            request = RequestRecord(target_id=self.target.id, method="post", source=source,
                                    principal_id=principal.id, endpoint_id=endpoint.id,
                                    correlation_id="trace-1",
                                    url="https://app.example.com/callback?access_token=PRIVATE_VALUE",
                                    artifact_hash=DIGEST, evidence_ids=(EV,))
            response = ResponseRecord(target_id=self.target.id, request_id=request.id,
                                      source=source, status_code=302,
                                      content_type="text/html; boundary=PRIVATE_VALUE",
                                      size_bytes=9, correlation_id="trace-1", artifact_hash=DIGEST)
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.principal_id, principal.id)
            self.assertEqual(request.origin_reference, "https://app.example.com")
            self.assertEqual(response.request_id, request.id)
            self.assertEqual(response.content_type, "text/html")
            self.assertNotIn("PRIVATE_VALUE", repr(request))
            self.assertNotIn("PRIVATE_VALUE", request.to_json())
            self.assertNotIn("PRIVATE_VALUE", response.to_json())
            self.assertEqual(request.to_dict(include_private=True)["url"], request.url)
        with self.assertRaises(ValueError):
            RequestRecord(target_id=self.target.id, method="GET", source="BURP")
        with self.assertRaises(ValueError):
            RequestRecord(target_id=self.target.id, method="GET", source=TrafficSource.FIXTURE,
                          operation_id=123)
        with self.assertRaises(ValueError):
            normalize_url("https://user:secret@app.example.com/path")
        names = {item.name.lower() for model in (RequestRecord, ResponseRecord) for item in fields(model)}
        self.assertFalse(names & {"password", "cookie", "token", "authorization", "headers", "body", "session"})

    def test_source_reference_is_private_and_extensible(self):
        source = SourceRef(provider="new_provider", record_id="PRIVATE_VALUE", qualification="manual")
        self.assertEqual(source.provider, "NEW_PROVIDER")
        self.assertNotIn("PRIVATE_VALUE", repr(source))
        self.assertNotIn("PRIVATE_VALUE", source.to_json())
        self.assertEqual(source.to_dict(include_private=True)["record_id"], "PRIVATE_VALUE")
        self.assertEqual(source.to_reference(), {"provider": "NEW_PROVIDER", "entity": None,
                                                 "observed_at": None})
        with self.assertRaises(ValueError):
            SourceRef(provider="invalid provider")

    def test_domain_ids_are_fact_subjects_and_objects(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = EvidenceFactStore(root / "state.sqlite3", ArtifactStore(root / "blobs"),
                                      StoreSettings(root / "blobs"))
            store.initialize()
            evidence = store.create_evidence(EvidenceType.RECON_RECORD, b"fixture",
                source="FIXTURE", provenance=EvidenceProvenance("FIXTURE"))
            role = Role(target_id=self.target.id, name="member")
            principal = Principal(target_id=self.target.id, label="user1")
            fact = store.create_fact(principal.id, "has_role", role.id, confidence=1,
                                     evidence_ids=(evidence.evidence_id,), source="RULE")
            self.assertEqual(store.find_facts(principal.id, "has_role").items[0].object, role.id)
            self.assertEqual(store.find_relationships(role.id).items[0].subject, principal.id)
            self.assertEqual(fact.evidence_ids, (evidence.evidence_id,))


class ReconMappingTests(unittest.TestCase):
    def setUp(self):
        self.provenance = Provenance("live_hosts", 25, NOW, "latest_recon_row")
        self.target_id = new_entity_id("TARGET")
        self.host_id = new_entity_id("HOST")

    def test_target_and_host_mapping_keeps_provenance_not_scope(self):
        record = ReconTarget(5, "Example.COM", True, True,
                             Provenance("domains", 5, NOW, "latest_recon_row"))
        target = target_from_recon(record, target_id=self.target_id, created_at=NOW,
                                   evidence_ids=(EV,))
        self.assertEqual(target.id, self.target_id)
        self.assertEqual((target.source_ref.entity, target.source_ref.record_id), ("domains", "5"))
        self.assertEqual(target.lifecycle, Lifecycle.UNKNOWN)
        self.assertEqual(target.evidence_ids, (EV,))
        self.assertNotIn("scope", target.to_json().lower())
        host_record = ReconHost(25, 5, "APP.EXAMPLE.COM", "https://app.example.com", 200, self.provenance)
        host = host_from_recon(host_record, target_id=target.id, host_id=self.host_id,
                               created_at=NOW)
        self.assertEqual(host.origin, "https://app.example.com")
        self.assertEqual(host.id, self.host_id)
        self.assertEqual(host.observation_state, ObservationState.OBSERVED)
        self.assertEqual(source_from_recon(self.provenance).provider, "RECON")
        with self.assertRaises(ValueError):
            host_from_recon(ReconHost(25, 5, "wrong.example.com", "https://app.example.com", 200,
                                      self.provenance), target_id=target.id, host_id=self.host_id,
                            created_at=NOW)

    def test_endpoint_and_js_mapping_are_pure_and_bounded(self):
        host = host_from_recon(
            ReconHost(25, 5, "app.example.com", "https://app.example.com", 200, self.provenance),
            target_id=self.target_id, host_id=self.host_id, created_at=NOW,
        )
        endpoint_row = ReconEndpoint(31, 25, "/api/projects?id=PRIVATE_VALUE", "GET", 403,
                                      "js_analysis", Provenance("endpoints", 31, NOW, "latest_recon_row"))
        endpoint_id = new_entity_id("ENDPOINT")
        first = endpoint_from_recon(endpoint_row, target_id=self.target_id, host=host,
                                    endpoint_id=endpoint_id, created_at=NOW, evidence_ids=(EV,))
        second = endpoint_from_recon(endpoint_row, target_id=self.target_id, host=host,
                                     endpoint_id=endpoint_id, created_at=NOW, evidence_ids=(EV,))
        self.assertEqual(first, second)
        self.assertEqual(first.path, "/api/projects")
        self.assertNotIn("PRIVATE_VALUE", first.to_json())
        self.assertEqual((first.source_ref.entity, first.source_ref.record_id), ("endpoints", "31"))
        js_row = ReconJsAsset(40, 25, "https://cdn.example.com/app.js?v=PRIVATE_VALUE", DIGEST,
                              250, 200, Provenance("js_assets", 40, NOW, "latest_recon_row"))
        asset = js_asset_from_recon(js_row, target_id=self.target_id, host=host,
                                    asset_id=new_entity_id("JS"), created_at=NOW,
                                    evidence_ids=(EV,))
        self.assertEqual(asset.sha256, DIGEST)
        self.assertEqual((asset.source_ref.entity, asset.source_ref.record_id), ("js_assets", "40"))
        self.assertNotIn("PRIVATE_VALUE", asset.to_json())
        with self.assertRaises(ValueError):
            endpoint_from_recon(ReconEndpoint(32, 999, "/other", "GET", 200, None,
                                              Provenance("endpoints", 32, NOW, "latest_recon_row")),
                                target_id=self.target_id, host=host, endpoint_id=new_entity_id("ENDPOINT"),
                                created_at=NOW)


if __name__ == "__main__":
    unittest.main()
