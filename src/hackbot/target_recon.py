"""Read-only recon identity and bounded host selection; scope stays package-owned."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .domain import normalize_hostname
from .recon import (ReconHost, ReconHostMembership, ReconHostSignals,
                    ReconRepository, ReconTarget, ReconWildcardCounts)
from .recon_postgres import ReconQueryError
from .target_package import TargetPackage
from .target_scope import ScopeResult


@dataclass(frozen=True)
class ReconDomainResolution:
    requested_host: str
    target: ReconTarget | None
    source: str
    subdomain_id: int | None = None
    host_id: int | None = None


@dataclass(frozen=True)
class RankedReconHost:
    host: ReconHost
    score: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"hostname": self.host.hostname, "url": self.host.url,
                "score": self.score, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class ReconHostSelection:
    resolution: ReconDomainResolution
    exact_hosts: tuple[ReconHost, ...]
    related_hosts: tuple[RankedReconHost, ...]
    wildcard_matches: int
    live_matches: int
    latest_scan_matches: int
    candidates_sampled: int
    rejected_count: int
    rejected: tuple[tuple[str, str], ...]
    truncated: bool

    @property
    def hosts(self) -> tuple[ReconHost, ...]:
        hosts = self.exact_hosts + tuple(item.host for item in self.related_hosts)
        return tuple(sorted(hosts, key=lambda host: (
            host.hostname != self.resolution.requested_host,
            host not in self.exact_hosts, host.hostname, host.host_id)))

    def to_dict(self) -> dict[str, object]:
        target = self.resolution.target
        return {
            "primary_focus": self.resolution.requested_host,
            "recon_root": target.root_domain if target else None,
            "recon_domain_id": target.domain_id if target else None,
            "resolution_source": self.resolution.source,
            "primary_subdomain_id": self.resolution.subdomain_id,
            "primary_live_host_id": self.resolution.host_id,
            "wildcard_recon_matches": self.wildcard_matches,
            "live_matches": self.live_matches,
            "latest_scan_matches": self.latest_scan_matches,
            "candidates_sampled": self.candidates_sampled,
            "selected_related_hosts": [item.to_dict() for item in self.related_hosts],
            "rejected_hosts": [{"hostname": host, "reason": reason}
                               for host, reason in self.rejected],
            "rejected_count": self.rejected_count,
            "sample_truncated": self.truncated,
            "selection_limit": ReconDomainResolver.MAX_RELATED_HOSTS,
            "active_requests_started": 0,
        }


class ReconDomainResolver:
    """Resolve a focus host via recon FKs, then rank already-authorized siblings."""

    MAX_WILDCARDS = 4
    MAX_CANDIDATES_PER_WILDCARD = 200
    MAX_SIGNAL_HOSTS = 32
    MAX_RELATED_HOSTS = 4

    def __init__(self, repository: ReconRepository) -> None:
        self.repository = repository

    def resolve(self, package: TargetPackage) -> ReconDomainResolution:
        name = normalize_hostname(package.primary_domain)
        direct = self.repository.resolve_target(name)
        if direct is not None:
            return ReconDomainResolution(name, direct, "DOMAINS_EXACT")
        membership_method = getattr(self.repository, "resolve_host_membership", None)
        membership: ReconHostMembership | None = (
            membership_method(name) if membership_method is not None else None)
        if membership is not None:
            return ReconDomainResolution(name, membership.target, "SUBDOMAIN_FK",
                                         membership.subdomain_id, membership.host_id)
        # Bounded fallback still requires an actual recon root row; never infer authority.
        labels = name.split(".")
        for offset in range(1, min(len(labels) - 1, 7)):
            root = self.repository.resolve_target(".".join(labels[offset:]))
            if root is not None:
                return ReconDomainResolution(name, root, "RECON_ROOT_SUFFIX")
        return ReconDomainResolution(name, None, "NOT_FOUND")

    @staticmethod
    def _allowed_host(package: TargetPackage, host: ReconHost) -> str | None:
        try:
            parsed = urlsplit(host.url)
            if (parsed.scheme not in {"http", "https"} or parsed.hostname is None
                    or normalize_hostname(parsed.hostname) != normalize_hostname(host.hostname)
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
                return "INVALID_RECON_ORIGIN"
            decision = package.scope.evaluate_url(host.url + ("" if host.url.endswith("/") else "/"))
            if decision.result is not ScopeResult.IN_SCOPE:
                return decision.reason.upper()
        except ValueError:
            return "INVALID_RECON_ORIGIN"
        return None

    def select_hosts(self, package: TargetPackage, *, resolution: ReconDomainResolution | None = None,
                     exact_urls: tuple[str, ...] = ()) -> ReconHostSelection:
        resolved = resolution or self.resolve(package)
        target = resolved.target
        if target is None:
            return ReconHostSelection(resolved, (), (), 0, 0, 0, 0, 0, (), False)
        exact: dict[int, ReconHost] = {}
        if not exact_urls:
            origins = []
            for rule in package.scope.include_hosts:
                if rule.pattern.startswith("*."):
                    continue
                schemes = rule.schemes or package.scope.default_schemes
                for scheme, default in (("https", 443), ("http", 80)):
                    if scheme not in schemes:
                        continue
                    ports = rule.ports or package.scope.default_ports or (default,)
                    port = default if default in ports else ports[0]
                    origin = f"{scheme}://{rule.pattern}" + (f":{port}" if port != default else "")
                    if package.scope.evaluate_url(origin + "/").result is ScopeResult.IN_SCOPE:
                        origins.append(origin)
                        break
            exact_urls = tuple(origins)
        for url in exact_urls[:8]:
            for origin in (url.rstrip("/"), url):
                host = self.repository.resolve_host(target.domain_id, origin)
                if host is not None:
                    if self._allowed_host(package, host) is None:
                        exact[host.host_id] = host
                    break

        rules = [rule.pattern[2:] for rule in package.scope.include_hosts
                 if rule.pattern.startswith("*.") and
                 (rule.pattern[2:] == target.root_domain or
                  rule.pattern[2:].endswith("." + target.root_domain))]
        rules = list(dict.fromkeys(rules))
        rules = [suffix for suffix in rules if not any(
            suffix != broader and suffix.endswith("." + broader) for broader in rules)]
        truncated = len(rules) > self.MAX_WILDCARDS
        matches = live = latest = sampled = rejected_count = 0
        rejected: list[tuple[str, str]] = []
        candidates: dict[str, ReconHost] = {}
        for suffix in rules[:self.MAX_WILDCARDS]:
            count_method = getattr(self.repository, "wildcard_counts", None)
            if count_method is not None:
                try:
                    counts: ReconWildcardCounts = count_method(target.domain_id, suffix)
                except ReconQueryError:
                    truncated = True
                else:
                    matches += counts.known
                    live += counts.live
                    latest += counts.latest_scan
            list_method = getattr(self.repository, "list_wildcard_hosts", None)
            if list_method is None:
                continue
            cursor = None
            for _ in range(self.MAX_CANDIDATES_PER_WILDCARD // 20):
                try:
                    page = list_method(target.domain_id, suffix, limit=20, cursor=cursor)
                except ReconQueryError:
                    truncated = True
                    break
                for host in page.items:
                    sampled += 1
                    if not host.hostname.endswith("." + suffix) or host.domain_id != target.domain_id:
                        reason = "WILDCARD_OR_ROOT_MISMATCH"
                    else:
                        reason = self._allowed_host(package, host)
                    if reason:
                        rejected_count += 1
                        if len(rejected) < 16:
                            rejected.append((host.hostname, reason))
                        continue
                    if host.host_id in exact:
                        continue
                    prior = candidates.get(host.hostname)
                    if prior is None or self._base_score(host, resolved.requested_host) > self._base_score(prior, resolved.requested_host):
                        candidates[host.hostname] = host
                if not page.next_cursor:
                    break
                cursor = page.next_cursor
            if cursor is not None:
                truncated = True

        shortlist = sorted(candidates.values(),
                           key=lambda host: (-self._base_score(host, resolved.requested_host),
                                             host.hostname, host.host_id))[:self.MAX_SIGNAL_HOSTS]
        signal_method = getattr(self.repository, "host_signals", None)
        try:
            signals: dict[int, ReconHostSignals] = (
                signal_method(target.domain_id, tuple(host.host_id for host in shortlist))
                if signal_method is not None and shortlist else {})
        except ReconQueryError:
            signals = {}
            truncated = True
        ranked = sorted((self._rank(host, resolved.requested_host,
                                    signals.get(host.host_id, ReconHostSignals()))
                         for host in shortlist),
                        key=lambda item: (-item.score, item.host.hostname, item.host.host_id))
        exact_hosts = tuple(sorted(exact.values(), key=lambda host: (
            host.hostname != resolved.requested_host, host.hostname, host.host_id)))
        return ReconHostSelection(resolved, exact_hosts,
                                  tuple(ranked[:self.MAX_RELATED_HOSTS]),
                                  matches, live, latest, sampled, rejected_count,
                                  tuple(rejected), truncated)

    @staticmethod
    def _base_score(host: ReconHost, primary: str) -> int:
        score = 0
        if host.hostname == primary:
            score += 1000
        elif host.hostname.endswith("." + primary) or primary.split(".")[0] in host.hostname.split(".")[0]:
            score += 45
        if host.status_code is not None:
            score += 20 if 200 <= host.status_code < 300 else 8 if host.status_code < 400 else 0
        seen = host.provenance.observed_at
        if seen is not None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            stamp = seen.replace(tzinfo=None)
            score += 20 if stamp >= now - timedelta(days=14) else 8 if stamp >= now - timedelta(days=60) else 0
        if any(word in host.hostname.split(".")[0] for word in ("api", "graphql", "app", "dashboard")):
            score += 8
        return score

    @classmethod
    def _rank(cls, host: ReconHost, primary: str, signals: ReconHostSignals) -> RankedReconHost:
        reasons = []
        if host.hostname == primary:
            reasons.append("primary_focus")
        elif host.hostname.endswith("." + primary) or primary.split(".")[0] in host.hostname.split(".")[0]:
            reasons.append("related_hostname")
        if host.status_code is not None and 200 <= host.status_code < 300:
            reasons.append("http_success")
        if signals.endpoint_count:
            reasons.append("endpoints")
        if signals.js_count:
            reasons.append("javascript")
        if signals.api_count:
            reasons.append("api_surfaces")
        score = (cls._base_score(host, primary)
                 + min(15, signals.endpoint_count // 10)
                 + min(12, signals.js_count // 5)
                 + min(15, signals.api_count * 3))
        return RankedReconHost(host, score, tuple(reasons or ["recent_recon_host"]))


def resolve_recon_target(package: TargetPackage, repository: ReconRepository) -> ReconTarget | None:
    """Compatibility helper for existing consumers of recon root identity."""
    return ReconDomainResolver(repository).resolve(package).target
