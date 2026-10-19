from __future__ import annotations

import urllib.error
import urllib.request
import json
import unittest

from hackbot.benchmark_fixture_server import BenchmarkHTTPFixture


def get(url: str, *, cookie: str | None = None) -> tuple[int, bytes]:
    headers = {"Cookie": cookie} if cookie else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class BenchmarkFixtureServerTests(unittest.TestCase):
    def test_vulnerable_and_secure_pair_have_same_visible_entry_point(self):
        results = []
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure) as fixture:
                self.assertTrue(fixture.base_url.startswith("http://127.0.0.1:"))
                index = get(fixture.base_url + "/")
                script = get(fixture.base_url + "/assets/app.js")
                owner = get(fixture.base_url + "/api/files/owned-file/download",
                            cookie="fixture_actor=owner")
                anonymous = get(fixture.base_url + "/api/files/owned-file/download")
                missing = get(fixture.base_url + "/api/files/missing/download")
                results.append((index, script, owner, anonymous, missing))
                self.assertNotIn("fixture_actor=owner", str(fixture.requests))
        self.assertEqual(results[0][0:3], results[1][0:3])
        self.assertEqual(results[0][3], results[0][2])
        self.assertEqual(results[1][3][0], 403)
        self.assertEqual(results[0][4][0], 404)

    def test_writes_are_rejected_and_budget_is_bounded(self):
        with BenchmarkHTTPFixture(secure=False, max_requests=2) as fixture:
            request = urllib.request.Request(fixture.base_url + "/api/files/owned-file/download",
                                             data=b"{}", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 405)
            self.assertEqual(get(fixture.base_url + "/")[0], 200)
            self.assertEqual(get(fixture.base_url + "/")[0], 429)
            self.assertLessEqual(len(fixture.requests), 3)

    def test_host_confusion_is_rejected(self):
        with BenchmarkHTTPFixture(secure=False) as fixture:
            request = urllib.request.Request(
                fixture.base_url + "/api/files/owned-file/download",
                headers={"Host": "other.example.test"})
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 421)

    def test_owned_document_lifecycle_and_anonymous_boundary(self):
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure) as fixture:
                url = fixture.base_url + "/fixture/tenant-a/documents"
                create = urllib.request.Request(
                    url, data=b'{"name":"benchmark-owned"}', method="POST",
                    headers={"Cookie": "fixture_actor=owner",
                             "Content-Type": "application/json"})
                with urllib.request.urlopen(create, timeout=3) as response:
                    self.assertEqual(response.status, 201)
                    document = json.loads(response.read())
                self.assertEqual(fixture.document_count, 1)
                detail = url + "/" + document["id"]
                self.assertEqual(get(detail, cookie="fixture_actor=owner")[0], 200)
                self.assertEqual(get(detail)[0], 403 if secure else 200)
                self.assertEqual(get(url + "/missing")[0], 404)
                delete = urllib.request.Request(
                    detail, method="DELETE", headers={"Cookie": "fixture_actor=owner"})
                with urllib.request.urlopen(delete, timeout=3) as response:
                    self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)
                self.assertEqual(get(detail)[0], 404)

    def test_noisy_guarded_surface_is_public_but_not_private_document_access(self):
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure, noisy=True) as fixture:
                for path in ("/admin/", "/graphql", "/api/internal/config",
                             "/api/files/public-sample/download", "/assets/noise.js",
                             "/assets/noise.js.map"):
                    self.assertEqual(get(fixture.base_url + path)[0], 200)
                status, public = get(fixture.base_url + "/api/files/public-sample/download")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(public)["visibility"], "public")
                self.assertEqual(get(fixture.base_url +
                                     "/fixture/tenant-a/documents/doc-1")[0], 404)

    def test_cross_tenant_pair_requires_auth_and_preserves_owner_controls(self):
        def create(base: str, tenant: str, actor: str) -> str:
            request = urllib.request.Request(
                base + f"/fixture/{tenant}/documents",
                data=b'{"name":"benchmark-owned"}', method="POST",
                headers={"Cookie": f"fixture_actor={actor}",
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(response.status, 201)
                return json.loads(response.read())["id"]

        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure, access_mode="TENANT") as fixture:
                owner_id = create(fixture.base_url, "tenant-a", "owner")
                foreign_id = create(fixture.base_url, "tenant-b", "foreign")
                owner_url = fixture.base_url + f"/fixture/tenant-a/documents/{owner_id}"
                foreign_url = fixture.base_url + f"/fixture/tenant-b/documents/{foreign_id}"
                self.assertEqual(get(owner_url, cookie="fixture_actor=owner")[0], 200)
                self.assertEqual(get(foreign_url, cookie="fixture_actor=foreign")[0], 200)
                self.assertEqual(get(owner_url, cookie="fixture_actor=foreign")[0],
                                 403 if secure else 200)
                self.assertEqual(get(foreign_url, cookie="fixture_actor=owner")[0],
                                 403 if secure else 200)
                self.assertEqual(get(owner_url)[0], 403)
                self.assertEqual(get(foreign_url)[0], 403)
                self.assertEqual(get(fixture.base_url +
                                     f"/fixture/tenant-b/documents/{owner_id}")[0], 404)
                mutation = urllib.request.Request(
                    owner_url, data=b'{"name":"changed"}', method="PATCH",
                    headers={"Cookie": "fixture_actor=foreign",
                             "Content-Type": "application/json"})
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(mutation, timeout=3)
                self.assertEqual(error.exception.code, 403)
                for url, actor in ((owner_url, "owner"), (foreign_url, "foreign")):
                    delete = urllib.request.Request(
                        url, method="DELETE",
                        headers={"Cookie": f"fixture_actor={actor}"})
                    with urllib.request.urlopen(delete, timeout=3) as response:
                        self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)

    def test_cross_tenant_mutation_pair_keeps_reads_private(self):
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure,
                                      access_mode="TENANT_MUTATION") as fixture:
                create = urllib.request.Request(
                    fixture.base_url + "/fixture/tenant-a/documents",
                    data=b'{"name":"benchmark-owned"}', method="POST",
                    headers={"Cookie": "fixture_actor=owner",
                             "Content-Type": "application/json"})
                with urllib.request.urlopen(create, timeout=3) as response:
                    document_id = json.loads(response.read())["id"]
                detail = (fixture.base_url +
                          f"/fixture/tenant-a/documents/{document_id}")
                self.assertEqual(get(detail, cookie="fixture_actor=foreign")[0], 403)
                patch = urllib.request.Request(
                    detail, data=b'{"name":"benchmark-changed"}', method="PATCH",
                    headers={"Cookie": "fixture_actor=foreign",
                             "Content-Type": "application/json"})
                if secure:
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(patch, timeout=3)
                    self.assertEqual(error.exception.code, 403)
                else:
                    with urllib.request.urlopen(patch, timeout=3) as response:
                        self.assertEqual(response.status, 200)
                owner = json.loads(get(detail, cookie="fixture_actor=owner")[1])
                self.assertEqual(owner["name"], "benchmark-owned" if secure
                                 else "benchmark-changed")
                self.assertEqual(get(detail, cookie="fixture_actor=foreign")[0], 403)
                delete = urllib.request.Request(
                    detail, method="DELETE",
                    headers={"Cookie": "fixture_actor=owner"})
                with urllib.request.urlopen(delete, timeout=3) as response:
                    self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)

    def test_same_tenant_pair_separates_ownership_from_membership(self):
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure,
                                      access_mode="HORIZONTAL") as fixture:
                documents = {}
                for actor in ("owner", "foreign"):
                    create = urllib.request.Request(
                        fixture.base_url + "/fixture/tenant-a/documents",
                        data=b'{"name":"benchmark-owned"}', method="POST",
                        headers={"Cookie": f"fixture_actor={actor}",
                                 "Content-Type": "application/json"})
                    with urllib.request.urlopen(create, timeout=3) as response:
                        body = json.loads(response.read())
                    self.assertEqual(body["owner"], actor)
                    self.assertEqual(body["tenant"], "tenant-a")
                    documents[actor] = (fixture.base_url +
                                        f"/fixture/tenant-a/documents/{body['id']}")
                for actor in ("owner", "foreign"):
                    other = "foreign" if actor == "owner" else "owner"
                    self.assertEqual(get(documents[actor],
                                         cookie=f"fixture_actor={actor}")[0], 200)
                    self.assertEqual(get(documents[other],
                                         cookie=f"fixture_actor={actor}")[0],
                                     403 if secure else 200)
                    self.assertEqual(get(documents[actor])[0], 403)
                    patch = urllib.request.Request(
                        documents[other], data=b'{"name":"changed"}', method="PATCH",
                        headers={"Cookie": f"fixture_actor={actor}",
                                 "Content-Type": "application/json"})
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(patch, timeout=3)
                    self.assertEqual(error.exception.code, 403)
                for actor in ("owner", "foreign"):
                    delete = urllib.request.Request(
                        documents[actor], method="DELETE",
                        headers={"Cookie": f"fixture_actor={actor}"})
                    with urllib.request.urlopen(delete, timeout=3) as response:
                        self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)

    def test_graphql_pair_isolated_from_protected_rest_routes(self):
        query = "query GetDocument($id:ID!){node(id:$id){id name owner tenant}}"
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure,
                                      access_mode="GRAPHQL") as fixture:
                documents = {}
                for tenant, actor in (("tenant-a", "owner"),
                                      ("tenant-b", "foreign")):
                    create = urllib.request.Request(
                        fixture.base_url + f"/fixture/{tenant}/documents",
                        data=b'{"name":"benchmark-owned"}', method="POST",
                        headers={"Cookie": f"fixture_actor={actor}",
                                 "Content-Type": "application/json"})
                    with urllib.request.urlopen(create, timeout=3) as response:
                        documents[actor] = json.loads(response.read())
                target = documents["foreign"]["id"]

                def query_as(actor: str | None, object_id: str) -> dict:
                    body = json.dumps({"query": query,
                                       "operationName": "GetDocument",
                                       "variables": {"id": object_id}}).encode()
                    headers = {"Content-Type": "application/json"}
                    if actor is not None:
                        headers["Cookie"] = f"fixture_actor={actor}"
                    request = urllib.request.Request(
                        fixture.base_url + "/fixture/graphql", data=body,
                        method="POST", headers=headers)
                    with urllib.request.urlopen(request, timeout=3) as response:
                        self.assertEqual(response.status, 200)
                        return json.loads(response.read())

                self.assertEqual(query_as("foreign", target)["data"]["node"]["id"],
                                 target)
                self.assertEqual(query_as("owner", target)["data"]["node"],
                                 None if secure else documents["foreign"])
                self.assertIsNone(query_as(None, target)["data"]["node"])
                self.assertIsNone(query_as("owner", "missing")["data"]["node"])
                if secure:
                    self.assertEqual(query_as("owner", target)["errors"][0][
                        "extensions"]["code"], "FORBIDDEN")
                rest = (fixture.base_url + "/fixture/tenant-b/documents/" + target)
                self.assertEqual(get(rest, cookie="fixture_actor=owner")[0], 403)
                for tenant, actor in (("tenant-a", "owner"),
                                      ("tenant-b", "foreign")):
                    delete = urllib.request.Request(
                        fixture.base_url + f"/fixture/{tenant}/documents/" +
                        documents[actor]["id"], method="DELETE",
                        headers={"Cookie": f"fixture_actor={actor}"})
                    with urllib.request.urlopen(delete, timeout=3) as response:
                        self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)

    def test_graphql_field_pair_separates_public_object_from_private_field(self):
        query = "query GetDocument($id:ID!){node(id:$id){id name owner tenant email}}"
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure,
                                      access_mode="GRAPHQL_FIELD") as fixture:
                documents = {}
                for tenant, actor in (("tenant-a", "owner"),
                                      ("tenant-b", "foreign")):
                    request = urllib.request.Request(
                        fixture.base_url + f"/fixture/{tenant}/documents",
                        data=b'{"name":"benchmark-owned"}', method="POST",
                        headers={"Cookie": f"fixture_actor={actor}",
                                 "Content-Type": "application/json"})
                    with urllib.request.urlopen(request, timeout=3) as response:
                        documents[actor] = json.loads(response.read())

                def query_as(actor: str | None, object_id: str) -> dict:
                    body = json.dumps({"query": query, "operationName": "GetDocument",
                                       "variables": {"id": object_id}}).encode()
                    headers = {"Content-Type": "application/json"}
                    if actor:
                        headers["Cookie"] = f"fixture_actor={actor}"
                    request = urllib.request.Request(
                        fixture.base_url + "/fixture/graphql", data=body,
                        method="POST", headers=headers)
                    with urllib.request.urlopen(request, timeout=3) as response:
                        self.assertEqual(response.status, 200)
                        return json.loads(response.read())

                target = documents["owner"]["id"]
                owned = query_as("owner", target)
                foreign = query_as("foreign", target)
                self.assertEqual(owned["data"]["node"]["email"],
                                 "synthetic-private@example.test")
                self.assertEqual(foreign["data"]["node"]["id"], target)
                self.assertEqual(foreign["data"]["node"]["email"],
                                 None if secure else "synthetic-private@example.test")
                self.assertEqual("errors" in foreign, secure)
                self.assertIsNone(query_as(None, target)["data"]["node"])
                self.assertIsNone(query_as("foreign", "missing")["data"]["node"])
                rest = (fixture.base_url +
                        f"/fixture/tenant-a/documents/{target}")
                self.assertEqual(get(rest, cookie="fixture_actor=foreign")[0], 403)
                for tenant, actor in (("tenant-a", "owner"),
                                      ("tenant-b", "foreign")):
                    request = urllib.request.Request(
                        fixture.base_url + f"/fixture/{tenant}/documents/" +
                        documents[actor]["id"], method="DELETE",
                        headers={"Cookie": f"fixture_actor={actor}"})
                    with urllib.request.urlopen(request, timeout=3) as response:
                        self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)

    def test_mixed_pair_has_two_distinct_read_boundaries_and_safe_noise(self):
        for secure in (False, True):
            with BenchmarkHTTPFixture(secure=secure, access_mode="MIXED",
                                      noisy=True) as fixture:
                documents = {}
                for tenant, actor in (("tenant-a", "owner"),
                                      ("tenant-b", "foreign")):
                    create = urllib.request.Request(
                        fixture.base_url + f"/fixture/{tenant}/documents",
                        data=b'{"name":"benchmark-owned"}', method="POST",
                        headers={"Cookie": f"fixture_actor={actor}",
                                 "Content-Type": "application/json"})
                    with urllib.request.urlopen(create, timeout=3) as response:
                        document_id = json.loads(response.read())["id"]
                    documents[tenant] = (fixture.base_url +
                                         f"/fixture/{tenant}/documents/{document_id}")
                a, b = documents["tenant-a"], documents["tenant-b"]
                self.assertEqual(get(a, cookie="fixture_actor=owner")[0], 200)
                self.assertEqual(get(b, cookie="fixture_actor=foreign")[0], 200)
                self.assertEqual(get(a)[0], 403 if secure else 200)
                self.assertEqual(get(b, cookie="fixture_actor=owner")[0],
                                 403 if secure else 200)
                self.assertEqual(get(b)[0], 403)
                self.assertEqual(get(a, cookie="fixture_actor=foreign")[0], 403)
                self.assertEqual(get(fixture.base_url + "/admin/")[0], 200)
                self.assertEqual(get(fixture.base_url + "/graphql")[0], 200)
                public = json.loads(get(fixture.base_url +
                                        "/api/internal/config")[1])
                self.assertTrue(public["public"])
                for tenant, actor in (("tenant-a", "owner"),
                                      ("tenant-b", "foreign")):
                    delete = urllib.request.Request(
                        documents[tenant], method="DELETE",
                        headers={"Cookie": f"fixture_actor={actor}"})
                    with urllib.request.urlopen(delete, timeout=3) as response:
                        self.assertEqual(response.status, 204)
                self.assertEqual(fixture.document_count, 0)
