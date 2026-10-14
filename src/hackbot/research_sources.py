"""Local and opt-in public knowledge sources for Phase 27.

Public retrieval is restricted to research hosts and never follows redirects.
It is not an arbitrary URL fetch facility or a bounty-target HTTP client.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from typing import Callable, Iterable
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import requests

from .research import SourceMaterial, SourceType, _canonical_url, _public_term
from .secrets import SecretProvider
from .skills import SkillRegistry
from .store import EvidenceFactStore


_KNOWN_HOSTS = frozenset({
    "hackerone.com", "portswigger.net", "owasp.org", "cheatsheetseries.owasp.org",
    "developer.mozilla.org", "docs.python.org", "docs.djangoproject.com",
    "docs.github.com", "github.com", "graphql.org", "www.rfc-editor.org",
    "arxiv.org", "www.usenix.org", "spring.io", "docs.spring.io",
})


class SkillKnowledgeProvider:
    def __init__(self, catalog: SkillRegistry) -> None:
        self.catalog = catalog

    def search(self, query: str, *, limit: int, byte_limit: int, deadline: float) -> tuple[SourceMaterial, ...]:
        terms = {word.lower() for word in re.findall(r"[A-Za-z]{3,}", query)} - {"security", "documentation"}
        results: list[SourceMaterial] = []
        for meta in self.catalog.discover():
            if time.monotonic() >= deadline or len(results) >= limit:
                break
            searchable = " ".join((meta.name, meta.category, *meta.vulnerability_classes,
                                   *meta.technologies, *meta.triggers)).lower()
            if terms and not any(term in searchable for term in terms):
                continue
            text = ("Implementation detail: " + meta.description + ". "
                    "Control: " + meta.when_not_to_use + ".")
            if len(text.encode()) > byte_limit:
                continue
            results.append(SourceMaterial(SourceType.SKILL, meta.name, "BugHunter skill catalog", text))
            byte_limit -= len(text.encode())
        return tuple(results)


class FindingKnowledgeProvider:
    """Generalized *confirmed* local patterns; no private finding body leaves process."""

    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    def search(self, query: str, *, limit: int, byte_limit: int, deadline: float) -> tuple[SourceMaterial, ...]:
        terms = {word.lower() for word in re.findall(r"[A-Za-z]{3,}", query)} - {"security", "documentation"}
        if not terms:
            return ()
        with self.evidence._connection() as db:
            rows = db.execute("SELECT category,COUNT(*) AS n FROM findings WHERE status IN "
                              "('CONFIRMED','READY_FOR_REPORT','SUBMITTED','TRIAGED','RESOLVED','REWARDED') "
                              "GROUP BY category ORDER BY n DESC LIMIT 30").fetchall()
        found: list[SourceMaterial] = []
        for row in rows:
            if time.monotonic() >= deadline or len(found) >= limit:
                break
            category = row["category"].lower()
            if not any(term in category for term in terms):
                continue
            text = f"Root cause class: {category}. Control: require independent live validation."
            if len(text.encode()) > byte_limit:
                break
            found.append(SourceMaterial(SourceType.PERSONAL_FINDING,
                                        "Confirmed local pattern: " + category,
                                        "BugHunter validated findings", text))
            byte_limit -= len(text.encode())
        return tuple(found)


class ManualResearchProvider:
    """Injected researcher-approved sources, useful for offline fixtures/imports."""

    def __init__(self, materials: Iterable[SourceMaterial] = ()) -> None:
        self.materials = tuple(materials)

    def search(self, query: str, *, limit: int, byte_limit: int, deadline: float) -> tuple[SourceMaterial, ...]:
        result: list[SourceMaterial] = []
        for item in self.materials:
            if time.monotonic() >= deadline or len(result) >= limit:
                break
            size = len(item.text.encode())
            if size > byte_limit:
                continue
            result.append(item)
            byte_limit -= size
        return tuple(result)


def _source_type(host: str) -> SourceType:
    if host == "hackerone.com":
        return SourceType.HACKERONE_REPORT
    if host == "portswigger.net":
        return SourceType.PORTSWIGGER
    if host.endswith("owasp.org"):
        return SourceType.OWASP
    if host == "github.com":
        return SourceType.GITHUB_SECURITY_RESEARCH
    if host in {"arxiv.org", "www.usenix.org"}:
        return SourceType.ACADEMIC_PAPER
    if host.startswith("docs.") or host in {"developer.mozilla.org", "graphql.org", "www.rfc-editor.org"}:
        return SourceType.VENDOR_DOCUMENTATION
    return SourceType.RESEARCHER_WRITEUP


class BraveWebResearchProvider:
    """Optional fixed search API plus vetted public-source retrieval.

    The subscription token is resolved only at this HTTP boundary. No search
    result may redirect us onto a different host or into a private network.
    """

    SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"

    @staticmethod
    def _public_dns(host: str) -> bool:
        try:
            addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global
                                           for item in addresses)
        except (OSError, ValueError):
            return False

    def __init__(self, secrets: SecretProvider, secret_ref: str, *,
                 allowed_hosts: tuple[str, ...] = (), session: requests.Session | None = None,
                 forbidden_host: Callable[[str], bool] | None = None) -> None:
        self.secrets = secrets
        self.secret_ref = secret_ref
        self.allowed_hosts = _KNOWN_HOSTS | frozenset(allowed_hosts)
        self.session = session or requests.Session()
        self.forbidden_host = forbidden_host or (lambda _host: False)

    @staticmethod
    def _bounded_body(response: requests.Response, limit: int) -> bytes:
        if response.status_code != 200:
            return b""
        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            if len(chunks) + len(chunk) > limit:
                return b""
            chunks.extend(chunk)
        return bytes(chunks)

    def _robots_allowed(self, host: str, url: str, *, deadline: float,
                        byte_limit: int) -> tuple[bool, int]:
        if byte_limit < 512 or time.monotonic() >= deadline:
            return False, 0
        response = self.session.get(f"https://{host}/robots.txt", timeout=min(4, max(1, deadline-time.monotonic())),
                                    allow_redirects=False, stream=True,
                                    headers={"User-Agent": "BugHunterResearch/0.1 (+public security documentation)"})
        try:
            if response.status_code == 404:
                return True, 0
            if response.status_code != 200:
                return False, 0
            body = self._bounded_body(response, min(4096, byte_limit))
            if not body:
                return False, 0
            parser = RobotFileParser()
            parser.parse(body.decode("utf-8", "replace").splitlines())
            return parser.can_fetch("BugHunterResearch", url), len(body)
        finally:
            response.close()

    def search(self, query: str, *, limit: int, byte_limit: int, deadline: float) -> tuple[SourceMaterial, ...]:
        safe = _public_term(query)
        if not safe:
            return ()
        if time.monotonic() >= deadline:
            return ()
        if not self._public_dns("api.search.brave.com"):
            return ()
        token = self.secrets.get(self.secret_ref).reveal(execution_boundary=True)
        timeout = min(8, max(1, deadline - time.monotonic()))
        response = self.session.get(self.SEARCH_URL, params={"q": safe, "count": min(limit, 8)},
                                    headers={"Accept": "application/json", "X-Subscription-Token": token,
                                             "User-Agent": "BugHunterResearch/0.1 (+public security documentation)"},
                                    timeout=timeout, allow_redirects=False, stream=True)
        try:
            raw = self._bounded_body(response, min(32_768, byte_limit))
            data = json.loads(raw)
        finally:
            response.close()
        entries = data.get("web", {}).get("results", []) if isinstance(data, dict) else []
        found: list[SourceMaterial] = []
        used = len(raw)
        robots_cache: dict[str, bool] = {}
        for entry in entries[:limit * 3]:
            if not isinstance(entry, dict) or time.monotonic() >= deadline or len(found) >= limit:
                break
            url = _canonical_url(entry.get("url"))
            if not url:
                continue
            host = urlsplit(url).hostname
            if (host not in self.allowed_hosts or self.forbidden_host(host)
                    or not self._public_dns(host)):
                continue
            # Source pages are optional; snippets still provide a cited lead.
            excerpt = str(entry.get("description", ""))[:800]
            level = "SNIPPET"
            remaining = min(8192, byte_limit - used)
            if remaining > 1024:
                try:
                    if host not in robots_cache:
                        robots_cache[host], cost = self._robots_allowed(
                            host, url, deadline=deadline, byte_limit=remaining)
                        used += cost
                    if robots_cache[host] and byte_limit - used > 1024:
                        page = self.session.get(url, timeout=min(6, max(1, deadline - time.monotonic())),
                                                allow_redirects=False, stream=True,
                                                headers={"User-Agent": "BugHunterResearch/0.1 (+public security documentation)"})
                        try:
                            body = self._bounded_body(page, min(8192, byte_limit - used))
                            used += len(body)
                            if body:
                                excerpt = body.decode("utf-8", "replace")
                                level = "FULL"
                        finally:
                            page.close()
                except requests.RequestException:
                    pass
            size = len(excerpt.encode())
            if size > byte_limit - used:
                break
            used += size
            found.append(SourceMaterial(_source_type(host), str(entry.get("title", ""))[:180],
                                        host, excerpt, url, content_level=level))
        return tuple(found)
