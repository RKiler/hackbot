"""Verify the local acceptance target before using it to evaluate HackBot."""

from __future__ import annotations

from http.cookiejar import CookieJar
import json
import os
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener

from tests.synthetic_saas import (APP_JS, GET_DOCUMENT, LOGIN_PASSWORD,
                                  RENAME_DOCUMENT, SyntheticSaaS)


class SyntheticSaaSTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SyntheticSaaS()
        self.fixture.__enter__()
        self.addCleanup(self.fixture.__exit__, None, None, None)

    def client(self):
        return build_opener(HTTPCookieProcessor(CookieJar()))

    def request(self, client, path: str, *, method: str = "GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        request = Request(self.fixture.base_url + path, data=data,
                          headers=headers, method=method)
        try:
            response = client.open(request, timeout=5)
        except HTTPError as exc:
            response = exc
        payload = response.read()
        try:
            value = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            value = payload.decode()
        return response.status, value

    def login(self, client, alias: str):
        request = Request(self.fixture.base_url + "/session/login",
                          data=urlencode({"alias": alias,
                                          "password": LOGIN_PASSWORD}).encode(),
                          method="POST")
        with client.open(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(urlsplit(response.url).path, "/app")

    def test_two_tenants_role_navigation_and_planted_boundary(self):
        admin1, member1, admin2, anonymous = (self.client() for _ in range(4))
        self.login(admin1, "org1_admin")
        self.login(member1, "org1_member")
        self.login(admin2, "org2_admin")
        self.assertEqual(self.request(admin1, "/api/me"),
                         (200, {"id": "org1_admin", "tenant": "org1", "role": "admin"}))
        self.assertEqual(self.request(member1, "/settings")[0], 403)
        self.assertEqual(self.request(admin1, "/settings")[0], 200)
        self.assertEqual(self.request(anonymous, "/api/documents/doc-org2-seed/preview")[0], 401)
        self.assertEqual(self.request(admin1, "/api/documents/doc-org2-seed")[0], 404)
        leaked_status, leaked = self.request(admin1, "/api/documents/doc-org2-seed/preview")
        self.assertEqual(leaked_status, 200)
        self.assertEqual(leaked["tenant"], "org2")
        self.assertEqual(leaked["content"], "org2-private-marker")
        self.assertEqual(self.request(admin2, "/api/documents/doc-org2-seed/preview")[0], 200)
        gql = {"operationName": "GetDocument", "query": GET_DOCUMENT,
               "variables": {"id": "doc-org2-seed"}}
        status, foreign = self.request(admin1, "/graphql", method="POST", body=gql)
        self.assertEqual(status, 200)
        self.assertIsNone(foreign["data"]["document"])
        self.assertEqual(self.request(admin2, "/graphql", method="POST", body=gql)[1][
            "data"]["document"]["tenant"], "org2")
        self.assertIn("/api/documents/{id}/preview", APP_JS)
        self.assertIn("RenameDocument", APP_JS)
        self.assertTrue(all(item.path.startswith("/") for item in self.fixture.requests))
        self.assertFalse(any(LOGIN_PASSWORD in item.path for item in self.fixture.requests))

    def test_reversible_disposable_rest_and_graphql_mutations(self):
        owner, foreign = self.client(), self.client()
        self.login(owner, "org1_member")
        self.login(foreign, "org2_admin")
        status, created = self.request(owner, "/api/documents", method="POST",
                                       body={"name": "disposable-one"})
        self.assertEqual(status, 201)
        document_id = created["id"]
        self.assertEqual(self.fixture.disposable_count, 1)
        self.assertEqual(self.request(foreign, f"/api/documents/{document_id}")[0], 404)
        self.assertEqual(self.request(foreign, f"/api/documents/{document_id}",
                                      method="PATCH", body={"name": "bad-change"})[0], 404)
        renamed = self.request(owner, f"/api/documents/{document_id}",
                               method="PATCH", body={"name": "disposable-two"})
        self.assertEqual(renamed[1]["name"], "disposable-two")
        mutation = {"operationName": "RenameDocument", "query": RENAME_DOCUMENT,
                    "variables": {"id": document_id, "name": "disposable-three"}}
        self.assertIsNone(self.request(foreign, "/graphql", method="POST", body=mutation)[1][
            "data"]["renameDocument"])
        self.assertEqual(self.request(owner, "/graphql", method="POST", body=mutation)[1][
            "data"]["renameDocument"]["name"], "disposable-three")
        self.assertEqual(self.request(owner, f"/api/documents/{document_id}")[1]["name"],
                         "disposable-three")
        self.assertEqual(self.request(owner, f"/api/documents/{document_id}",
                                      method="DELETE")[0], 204)
        self.assertEqual(self.fixture.disposable_count, 0)
        self.assertEqual(self.request(owner, f"/api/documents/{document_id}")[0], 404)
        self.assertEqual(self.request(owner, "/api/documents/doc-org1-seed",
                                      method="DELETE")[0], 403)

    def test_secure_variant_denies_preview_as_well_as_detail(self):
        with SyntheticSaaS(vulnerable=False) as secure:
            client = self.client()
            request = Request(secure.base_url + "/session/login",
                              data=urlencode({"alias": "org1_admin",
                                              "password": LOGIN_PASSWORD}).encode(),
                              method="POST")
            client.open(request, timeout=5).close()
            for route in ("/api/documents/doc-org2-seed",
                          "/api/documents/doc-org2-seed/preview"):
                with self.assertRaises(HTTPError) as response:
                    client.open(secure.base_url + route, timeout=5)
                self.assertEqual(response.exception.code, 404)

    @unittest.skipUnless(os.environ.get("HACKBOT_TEST_CHROMIUM"),
                         "requires explicit local Chromium fixture")
    def test_browser_login_navigation_and_current_js(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page()
                observed = []
                page.on("request", lambda outgoing: observed.append(outgoing.url))
                page.goto(self.fixture.base_url + "/login")
                page.locator("select[name=alias]").select_option("org1_admin")
                page.locator("input[name=password]").fill(LOGIN_PASSWORD)
                page.get_by_role("button", name="Sign in").click()
                page.locator("[data-user]").wait_for()
                self.assertEqual(page.locator("[data-user]").inner_text(), "org1_admin")
                self.assertEqual(page.locator("[data-tenant]").inner_text(), "org1")
                page.get_by_role("link", name="Documents", exact=True).click()
                page.get_by_role("link", name="org1-seed").wait_for()
                page.get_by_role("link", name="org1-seed").click()
                page.get_by_role("link", name="Preview").wait_for()
                self.assertEqual(page.evaluate("window.syntheticSaas.apiRoutes.length"), 5)
                self.assertTrue(observed)
                self.assertTrue(all(urlsplit(url).hostname == "127.0.0.1"
                                    for url in observed))
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
