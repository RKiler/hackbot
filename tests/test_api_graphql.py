"""Phase 26 GraphQL parsing and API registry tests; no target traffic."""

from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.api_graphql import (GraphQLResult, classify_result, encode_observed_global_id,
                                 extract_js_api_artifacts, extract_js_api_page,
                                 extract_js_documents,
                                 graphql_batch_values, nested_child_values,
                                 observed_field_selection_pair, observed_global_id_type,
                                 parse_operations, single_nested_rename_operation,
                                 single_node_id_binding,
                                 single_node_id_variable,
                                 single_nodes_ids_variable)
from hackbot.api_registry import APIOperationRegistry, APIOperationType
from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.identity_registry import IdentityRegistry
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.response_compare import ResponseComparator
from tests import test_behaviour as _behaviour_fixture


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class GraphQLParsingTests(unittest.TestCase):
    def test_field_selection_pair_requires_exact_observed_flat_subset(self):
        owner = "query Read($id:ID!){node(id:$id){id name email}}"
        actor = "query Read($id:ID!){node(id:$id){id name}}"
        self.assertTrue(observed_field_selection_pair(owner, actor, "/node/email"))
        for changed in (
            "query Read($id:ID!){other(id:$id){id name}}",
            "query Read($other:ID!){node(id:$other){id name}}",
            "query Read($id:ID!){node(id:$id){id name invented}}",
            "query Read($id:ID!){node(id:$id){id name email}}",
            "query Read($id:ID!){node(id:$id){id alias:name}}",
            "query Read($id:ID!){node(id:$id){id name @include(if:true)}}",
        ):
            self.assertFalse(observed_field_selection_pair(owner, changed,
                                                           "/node/email"), changed)
        self.assertFalse(observed_field_selection_pair(owner, actor, "/other/email"))

    def test_field_selection_pair_accepts_only_one_observed_nested_scalar_gap(self):
        owner = ("query Read($id:ID!){node(id:$id){id name "
                 "profile{timezone email}}}")
        actor = ("query Read($id:ID!){node(id:$id){id name "
                 "profile{timezone}}}")
        self.assertTrue(observed_field_selection_pair(owner, actor,
                                                      "/node/profile/email"))
        for changed in (
            "query Read($id:ID!){node(id:$id){id name profile{timezone invented}}}",
            "query Read($id:ID!){node(id:$id){id name profile{timezone email}}}",
            "query Read($id:ID!){node(id:$id){id name profile{alias:timezone}}}",
            "query Read($id:ID!){node(id:$id){id name profile{timezone @include(if:true)}}}",
            "query Read($id:ID!){node(id:$id){id name profile{timezone} other{id}}}",
            "query Read($id:ID!){node(id:$id){id name profile{timezone} extra}}",
        ):
            self.assertFalse(observed_field_selection_pair(owner, changed,
                                                           "/node/profile/email"), changed)
        self.assertFalse(observed_field_selection_pair(owner, actor,
                                                       "/node/profile/timezone"))
        self.assertFalse(observed_field_selection_pair(owner, actor,
                                                       "/node/profile"))

    def test_fields_fragments_aliases_types_and_no_guessing(self):
        document = ("query GetNode($id:ID!){lookup:node(id:$id){id ...PrivateFields}} "
                    "fragment PrivateFields on User { privateEmail billingInfo { status } }")
        operation = parse_operations(document)[0]
        self.assertEqual(operation.name, "GetNode")
        self.assertEqual(operation.input_types, ("ID",))
        self.assertEqual(operation.variables, ("id",))
        self.assertEqual(operation.root_fields, ("node",))
        self.assertEqual([field.path for field in operation.fields],
                         ["/lookup", "/lookup/id", "/lookup/privateEmail",
                          "/lookup/billingInfo", "/lookup/billingInfo/status"])
        self.assertEqual(operation.fields[2].sensitivity, "SENSITIVE_NAME")
        with self.assertRaises(ValueError):
            parse_operations("query x{" + "x{" * 10 + "id" + "}" * 11)

    def test_reuses_babel_parser_without_executing_bundle(self):
        source = b"const a=gql`query Read($id:ID!){node(id:$id){id}}`; throw Error('not executed');"
        documents = extract_js_documents(source)
        self.assertEqual(len(documents), 1)
        self.assertEqual(parse_operations(documents[0][0])[0].name, "Read")
        self.assertEqual(extract_js_documents(b"const a=`not graphql`;"), ())

    def test_literal_rest_routes_are_bounded_static_hints(self):
        source = (b"fetch('/api/v1/admin/export',{method:'POST'});"
                  b"axios.get('/api/v1/projects');"
                  b"fetch('https://other.invalid/api/leak');"
                  b"fetch('/api/../private');"
                  b"fetch('/api/v1/items?token=secret');"
                  b"throw Error('not executed');")
        documents, routes = extract_js_api_artifacts(source)
        self.assertEqual(documents, ())
        self.assertEqual([(item.method, item.path) for item in routes],
                         [("POST", "/api/v1/admin/export"),
                          ("GET", "/api/v1/projects")])

    def test_js_api_pages_reach_operations_after_legacy_first_page(self):
        body = b"".join(
            (f"const q{index}=gql`query Dense{index}($id:ID!)"
             "{node(id:$id){id}}`;" ).encode() for index in range(30))
        body += b"fetch('/api/v1/after-documents',{method:'POST'});"
        legacy, _ = extract_js_api_artifacts(body)
        self.assertEqual(len(legacy), 24)
        offset = 0
        names = []
        while True:
            page = extract_js_api_page(body, offset=offset)
            names.extend(item.value for item in page.entries)
            self.assertFalse(page.truncated)
            if page.next_offset is None:
                break
            offset = page.next_offset
        self.assertEqual(len(names), 31)
        self.assertIn("query Dense29", names[-2])
        self.assertEqual(names[-1], "/api/v1/after-documents")
        with self.assertRaises(ValueError):
            extract_js_api_page(body, offset=1025)

    def test_js_api_page_reports_hard_cap_instead_of_complete_coverage(self):
        body = b"".join(
            f"fetch('/api/v1/item_{index}');".encode() for index in range(1025))
        page = extract_js_api_page(body, offset=1008)
        self.assertEqual(len(page.entries), 16)
        self.assertEqual(page.entries[-1].ordinal, 1023)
        self.assertIsNone(page.next_offset)
        self.assertTrue(page.truncated)

    def test_http_200_errors_partial_and_null(self):
        self.assertEqual(classify_result({"data": {"node": None},
            "errors": [{"extensions": {"code": "FORBIDDEN"}}]}),
            GraphQLResult.AUTHORIZATION_DENIED)
        self.assertEqual(classify_result({"data": {"node": {"id": "a"}},
            "errors": [{"extensions": {"code": "FORBIDDEN"}}]}),
            GraphQLResult.PARTIAL_DATA)
        self.assertEqual(classify_result({"errors": [{"extensions": {"code": "BAD_USER_INPUT"}}]}),
                         GraphQLResult.VALIDATION_ERROR)
        self.assertEqual(classify_result({"errors": [{"message": "No such field"}]}),
                         GraphQLResult.EXECUTION_ERROR)

    def test_global_id_recognition_requires_exact_known_id_and_node_argument(self):
        encoded = encode_observed_global_id("Project", "owned-12")
        self.assertEqual(observed_global_id_type(encoded, "owned-12"), "Project")
        self.assertIsNone(observed_global_id_type(encoded, "foreign-2"))
        self.assertIsNone(observed_global_id_type(encoded.rstrip("="), "owned-12"))
        self.assertEqual(single_node_id_variable(
            "query Read($id:ID!){chosen:node(id:$id){id}}"), "id")
        self.assertEqual(single_node_id_binding(
            "query Read($id:ID!){chosen:node(id:$id){id name}}"),
            ("id", "chosen"))
        self.assertIsNone(single_node_id_variable(
            "query Read($id:ID!){node(other:$id){id}}"))
        self.assertIsNone(single_node_id_variable(
            "mutation Write($id:ID!){node(id:$id){id}}"))

    def test_nested_child_values_are_bound_to_exact_parent_and_path(self):
        parent = hashlib.sha256(b"parent-a").hexdigest()
        child = hashlib.sha256(b"child-a").hexdigest()
        payload = {"data": {"node": {"id": "parent-a", "dashboards": [
            {"id": "child-a", "name": "synthetic-private", "tenant": "tenant-a"}]},
            "other": {"id": "parent-b", "dashboards": [
                {"id": "child-a", "name": "synthetic-private"}]}}}
        self.assertIn("name", nested_child_values(payload, "/node/dashboards", parent, child))
        self.assertEqual(nested_child_values(payload, "/other/dashboards", parent, child), {})
        self.assertEqual(nested_child_values(payload, "/node/other", parent, child), {})
        self.assertEqual(nested_child_values(payload, "/node/dashboards", parent,
                                             hashlib.sha256(b"child-b").hexdigest()), {})

    def test_observed_nodes_batch_requires_one_list_variable_and_per_item_data(self):
        document = "query ReadMany($ids:[ID!]!){chosen:nodes(ids:$ids){id name}}"
        self.assertEqual(single_nodes_ids_variable(document), ("ids", "chosen"))
        self.assertIsNone(single_nodes_ids_variable(
            "query ReadMany($ids:[ID!]!){nodes(ids:$ids){id}}"))
        self.assertIsNone(single_nodes_ids_variable(
            "query ReadMany($ids:[ID!]!){nodes(ids:$ids){id name} other{id}}"))
        self.assertIsNone(single_nodes_ids_variable(
            "query ReadMany($ids:ID!){nodes(ids:$ids){id name}}"))
        hashes = frozenset(hashlib.sha256(item.encode()).hexdigest() for item in ("a", "b"))
        values = graphql_batch_values({"data": {"chosen": [
            {"id": "a", "name": "owned"}, {"id": "b", "name": "actor"}]}},
            "chosen", hashes)
        self.assertEqual(len(values), 2)
        self.assertEqual(graphql_batch_values({"data": {"chosen": [
            {"id": "a", "name": "owned"}, {"id": "c", "name": "unknown"}]}},
            "chosen", hashes), {})
        self.assertEqual(graphql_batch_values({"data": {"chosen": [
            {"id": "a", "name": "owned"}, {"id": "a", "name": "owned"}]}},
            "chosen", hashes), {})
        array = [{"data": {"chosen": {"id": "a", "name": "owned"}}},
                 {"data": {"chosen": {"id": "b", "name": "actor"}}}]
        self.assertEqual(len(graphql_batch_values(array, "chosen", hashes,
                                                   envelope="OPERATION_ARRAY")), 2)
        self.assertEqual(graphql_batch_values(array + array, "chosen", hashes,
                                              envelope="OPERATION_ARRAY"), {})

    def test_nested_rename_accepts_only_exact_parent_child_contract(self):
        document = ("mutation RenameDashboard($parentId:ID!,$id:ID!,$name:String!)"
                    "{renameDashboard(parentId:$parentId,id:$id,name:$name)"
                    "{id name parentId}}")
        self.assertEqual(single_nested_rename_operation(document), "RenameDashboard")
        self.assertIsNone(single_nested_rename_operation(
            document.replace("parentId:$parentId,", "")))
        self.assertIsNone(single_nested_rename_operation(
            document.replace("{id name parentId}", "{id name parentId secret}")))
        self.assertIsNone(single_nested_rename_operation(
            document + " mutation Other{x}"))


class APIOperationRegistryTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        blobs = root / "blobs"
        self.evidence = EvidenceFactStore(root / "state/bughunter.sqlite3", ArtifactStore(blobs),
                                          StoreSettings(blobs, max_page_size=50))
        identities = IdentityRegistry(self.evidence)
        identities.initialize()
        self.package = load_target_package(EXAMPLE)
        identities.register_target(self.package)
        self.registry = APIOperationRegistry(self.evidence)

    def test_distinct_observed_documents_can_coexist_for_one_operation_name(self):
        target = self.package.target.id
        kwargs = dict(target_id=target, package_id=self.package.id, name="GetNode",
                      kind=APIOperationType.GRAPHQL_QUERY, endpoint="https://app.example.test/graphql",
                      method="POST")
        first = self.registry.upsert_operation(**kwargs, version_hash=hashlib.sha256(b"v1").hexdigest())
        second = self.registry.upsert_operation(**kwargs, version_hash=hashlib.sha256(b"v2").hexdigest())
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(self.registry.get_operation(target, first.id).state, "CURRENT")
        self.assertEqual(self.registry.get_operation(target, second.id).state, "CURRENT")
        self.assertEqual(self.registry.counts(target)["operations_current"], 2)

    def test_bounds_and_no_raw_operation_body_in_metadata(self):
        target = self.package.target.id
        with self.assertRaises(ValueError):
            self.registry.upsert_operation(target_id=target, package_id=self.package.id,
                name="GetNode", kind=APIOperationType.GRAPHQL_QUERY,
                endpoint="https://app.example.test/graphql?token=secret", method="POST",
                version_hash=hashlib.sha256(b"doc").hexdigest())

    def test_global_id_metadata_is_typed_and_conflicts_fail_closed(self):
        target = self.package.target.id
        kwargs = dict(target_id=target, package_id=self.package.id, name="GetNode",
                      kind=APIOperationType.GRAPHQL_QUERY,
                      endpoint="https://app.example.test/graphql", method="POST",
                      version_hash=hashlib.sha256(b"query GetNode{node{id}}").hexdigest())
        first = self.registry.upsert_operation(**kwargs, global_id_type="Project")
        self.assertEqual(first.global_id_type, "Project")
        second = self.registry.upsert_operation(**kwargs, global_id_type="Workspace")
        self.assertEqual(second.global_id_type, "CONFLICT")
        third = self.registry.upsert_operation(**kwargs, global_id_type="Project")
        self.assertEqual(third.global_id_type, "CONFLICT")
        other = self.registry.upsert_operation(
            **{**kwargs, "version_hash": hashlib.sha256(b"another document").hexdigest()},
            global_id_type="PLAIN")
        self.assertEqual(other.global_id_type, "PLAIN")
        mixed = self.registry.upsert_operation(
            **{**kwargs, "version_hash": hashlib.sha256(b"another document").hexdigest()},
            global_id_type="Project")
        self.assertEqual(mixed.global_id_type, "CONFLICT")


class GraphQLResponseFeatureTests(unittest.TestCase):
    def test_partial_data_tracks_field_hash_and_error_path_without_value(self):
        fx = _behaviour_fixture.BehaviourTests(
            methodName="test_role_feature_absence_is_not_denial_and_explicit_denial_is_recorded")
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        exchange = fx.capture("https://app.example.test/graphql", method="POST",
            request_body=b'{"query":"query Read { node { id } }"}',
            body=b'{"data":{"node":{"id":"fixture-id","privateEmail":"synthetic@example.test"}},'
                 b'"errors":[{"path":["node","other"],"extensions":{"code":"FORBIDDEN"}}]}')
        features = ResponseComparator(fx.evidence).features(exchange)
        self.assertEqual(features.graphql_result, GraphQLResult.PARTIAL_DATA.value)
        self.assertIn("/node/privateEmail", features.graphql_data_paths)
        self.assertIn("/node/other", features.graphql_error_paths)
        self.assertIn("FORBIDDEN", features.graphql_error_codes)
        self.assertIsNotNone(features.graphql_value("/node/privateEmail"))
        self.assertNotIn("synthetic@example.test", str(features.to_dict()))
