"""Bounded authenticated page mapping over existing browser and traffic controls."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urljoin, urlsplit

from .bootstrap import TargetBootstrapper, _navigation_priority, _safe_url
from .browser import BrowserSessionManager
from .browser_navigation import (BrowserActionExecutor, BrowserNavigationBudgetReached,
                                 BrowserNavigationError)
from .evidence import EvidenceProvenance, EvidenceType, Sensitivity
from .logging import is_sensitive_key
from .policy import _strict_url_reason
from .profile import _shape
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .target_scope import ScopeResult


_STATIC_FORM_PATH = re.compile(r"/(?:[A-Za-z][A-Za-z0-9_-]{0,63}/?)*\Z")


def _form_schema(page_url: str, form: tuple[str, str],
                 fields: tuple[tuple[str, str], ...],
                 package: TargetPackage) -> dict[str, object] | None:
    action, method = form
    if method not in {"GET", "POST"}:
        return None
    try:
        url = urljoin(page_url, action)
        parsed = urlsplit(url)
        if (parsed.query or parsed.fragment or _strict_url_reason(url) is not None
                or not _STATIC_FORM_PATH.fullmatch(parsed.path or "/")
                or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
            return None
        names = tuple((name, kind) for name, kind in fields[:16]
                      if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name)
                      and not is_sensitive_key(name)
                      and kind in {"text", "search", "textarea", "select", "number", "checkbox"})
        return {"action": url, "method": method,
                "fields": [{"name": name, "type": kind} for name, kind in names]}
    except (ValueError, UnicodeError):
        return None


@dataclass(frozen=True, slots=True)
class MappingLimits:
    max_pages: int = 8
    max_requests_per_page: int = 24
    max_links: int = 80

    def __post_init__(self) -> None:
        if (type(self.max_pages) is not int or not 1 <= self.max_pages <= 32
                or type(self.max_requests_per_page) is not int
                or not 1 <= self.max_requests_per_page <= 96
                or type(self.max_links) is not int or not 1 <= self.max_links <= 320):
            raise ValueError("Invalid application mapping limits")


@dataclass(frozen=True, slots=True)
class MappingResult:
    session_id: str
    pages_attempted: int
    pages_observed: int
    links_discovered: int
    js_references: int
    forms_observed: int
    evidence_ids: tuple[str, ...]
    blocked: tuple[str, ...]


class ApplicationMapper:
    """Follow only observed safe GET routes; campaign owns any later mutation."""

    def __init__(self, *, browser: BrowserSessionManager, driver: object,
                 navigation: BrowserActionExecutor,
                 evidence: EvidenceFactStore) -> None:
        self.browser = browser
        self.driver = driver
        self.navigation = navigation
        self.evidence = evidence

    def map_session(self, package: TargetPackage, session_id: str, *,
                    experiment_id: str,
                    limits: MappingLimits = MappingLimits()) -> MappingResult:
        context = self.browser.session_context(session_id)
        if context.target_id != package.target.id or context.identity_id is None:
            raise BrowserNavigationError("Mapped browser session belongs to another target")
        roots = TargetBootstrapper.seed_urls(package)
        focus_roots = sorted(roots, key=lambda item: (
            urlsplit(item).hostname != package.primary_domain, item))
        seeds: list[str] = []
        current_host = current_scheme = None
        observe = getattr(self.driver, "observe_current_page", None)
        if callable(observe):
            current = observe(session_id)
            if isinstance(current, dict):
                value = current.get("url")
                safe = _safe_url(value, value, package) if isinstance(value, str) else None
                if safe:
                    seeds.append(safe)
                    current_host = urlsplit(safe).hostname
                    current_scheme = urlsplit(safe).scheme
        seeds.extend(root for root in focus_roots[:4]
                     if urlsplit(root).hostname != current_host
                     or urlsplit(root).scheme == current_scheme)
        queue = deque(dict.fromkeys(seeds))
        visited: set[str] = set()
        evidence_ids: list[str] = []
        blocked: list[str] = []
        pages_observed = links_discovered = js_references = forms_observed = 0
        total_budget = limits.max_pages * limits.max_requests_per_page
        while queue and len(visited) < limits.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                page = self.navigation.navigate(
                    package, session_id, url, experiment_id=experiment_id,
                    request_cap=limits.max_requests_per_page,
                    total_request_budget=total_budget)
            except BrowserNavigationBudgetReached:
                blocked.append("MAPPING_REQUEST_BUDGET")
                break
            except BrowserNavigationError:
                blocked.append("CAPTURE_OR_IDENTITY_LOST")
                break  # Capture or identity loss is a whole-session blocker.
            if page.error_code or page.status_code is None:
                blocked.append(page.error_code or "PAGE_NOT_OBSERVED")
                continue
            pages_observed += 1
            safe_links = []
            for link in page.links[:limits.max_links]:
                safe = _safe_url(page.url, link, package)
                if safe and safe not in visited and safe not in queue:
                    safe_links.append(safe)
            links_discovered += len(safe_links)
            js_references += sum(_safe_url(page.url, src, package) is not None
                                 for src in page.scripts)
            forms_observed += len(page.forms)
            form_schemas = tuple(schema for index, form in enumerate(page.forms[:16])
                                 if (schema := _form_schema(
                                     page.url, form,
                                     page.form_fields[index] if index < len(page.form_fields) else (),
                                     package)) is not None)
            structural = {
                "host": urlsplit(page.url).hostname,
                "route_shape": _shape(urlsplit(page.url).path or "/"),
                "url_sha256": hashlib.sha256(page.url.encode()).hexdigest(),
                "status": page.status_code,
                "links": len(safe_links), "js_references": len(page.scripts),
                "forms": len(page.forms), "buttons": len(page.buttons),
                "form_schemas": form_schemas,
                "requests": page.request_count, "denied": page.denied_count,
                "redirects": page.redirect_count,
            }
            record = self.evidence.create_evidence(
                EvidenceType.BROWSER_EVENT,
                json.dumps(structural, sort_keys=True, separators=(",", ":")).encode(),
                source="application_mapper",
                provenance=EvidenceProvenance(system="HACKBOT", entity="AUTHENTICATED_BROWSER",
                                              record_id=session_id),
                target_ref=package.target.id, sensitivity=Sensitivity.INTERNAL,
                metadata={"route_shape": structural["route_shape"],
                          "url_sha256": structural["url_sha256"]})
            evidence_ids.append(record.evidence_id)
            for next_url in sorted(safe_links, key=_navigation_priority):
                queue.append(next_url)
        return MappingResult(session_id, len(visited), pages_observed,
                             links_discovered, js_references, forms_observed,
                             tuple(evidence_ids), tuple(blocked[:8]))
