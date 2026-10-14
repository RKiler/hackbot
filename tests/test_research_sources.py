from __future__ import annotations

import json
import time
import unittest
from unittest.mock import Mock, patch

from hackbot.research_sources import BraveWebResearchProvider
from hackbot.secrets import SecretValue


class Response:
    def __init__(self, status: int, body: bytes):
        self.status_code = status
        self.body = body
        self.headers = {"Content-Type": "text/html"}
        self.closed = False

    def iter_content(self, chunk_size=4096):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self):
        self.calls = []
        self.responses = {
            BraveWebResearchProvider.SEARCH_URL: Response(200, json.dumps({"web": {"results": [
                {"url": "https://private.example.com/api/secret", "title": "Target", "description": "target"},
                {"url": "https://hackerone.com/reports/123", "title": "Disclosed report", "description": "Root cause: old auth check."},
                {"url": "https://graphql.org/learn/authorization/", "title": "GraphQL auth", "description": "Control: check user."},
            ]}}).encode()),
            "https://hackerone.com/robots.txt": Response(200, b"User-agent: *\nDisallow: /reports/\n"),
            "https://graphql.org/robots.txt": Response(200, b"User-agent: *\nAllow: /\n"),
            "https://graphql.org/learn/authorization/": Response(200,
                b"<p>Security boundary: resolvers must check object authorization.</p>"),
        }

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses[url]


class PublicProviderTests(unittest.TestCase):
    def test_public_search_allowlist_robots_and_secret_boundary(self):
        session = FakeSession()
        secret = Mock()
        secret.get.return_value = SecretValue("fixture-secret")
        provider = BraveWebResearchProvider(secret, "ref:research", session=session,
                                            forbidden_host=lambda host: host == "private.example.com")
        with patch.object(provider, "_public_dns", return_value=True):
            sources = provider.search("GraphQL authorization documentation", limit=3,
                                      byte_limit=16_384, deadline=time.monotonic() + 10)
        self.assertEqual(len(sources), 2)
        self.assertEqual({source.source_type.value for source in sources},
                         {"HACKERONE_REPORT", "VENDOR_DOCUMENTATION"})
        self.assertFalse(any(url.startswith("https://private.example.com") for url, _ in session.calls))
        self.assertFalse(any(url == "https://hackerone.com/reports/123" for url, _ in session.calls))
        self.assertIn("resolvers must check", sources[1].text)
        self.assertIn("fixture-secret", session.calls[0][1]["headers"]["X-Subscription-Token"])
        self.assertTrue(all(session.responses[url].closed for url, _ in session.calls))

    def test_sensitive_query_never_reaches_provider_secret_or_network(self):
        secret = Mock()
        session = Mock()
        provider = BraveWebResearchProvider(secret, "ref:research", session=session)
        self.assertEqual(provider.search("Bearer very-secret", limit=2, byte_limit=8192,
                                         deadline=time.monotonic() + 5), ())
        secret.get.assert_not_called()
        session.get.assert_not_called()

    def test_private_dns_blocks_source_before_fetch(self):
        session = FakeSession()
        secret = Mock()
        secret.get.return_value = SecretValue("fixture-secret")
        provider = BraveWebResearchProvider(secret, "ref:research", session=session)
        with patch.object(provider, "_public_dns", side_effect=lambda host: host == "api.search.brave.com"):
            sources = provider.search("GraphQL authorization documentation", limit=3,
                                      byte_limit=16_384, deadline=time.monotonic() + 10)
        self.assertEqual(sources, ())
        self.assertEqual([url for url, _ in session.calls], [provider.SEARCH_URL])

    def test_dns_check_rejects_private_addresses(self):
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None,
                                                         ("127.0.0.1", 443))]):
            self.assertFalse(BraveWebResearchProvider._public_dns("example.org"))
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None,
                                                         ("93.184.215.14", 443))]):
            self.assertTrue(BraveWebResearchProvider._public_dns("example.org"))


if __name__ == "__main__":
    unittest.main()
