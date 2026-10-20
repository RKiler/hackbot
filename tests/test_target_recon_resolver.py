"""Synthetic-only coverage of recon identity and wildcard scope boundaries."""

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import unittest

from hackbot.recon import (Page, Provenance, ReconHost, ReconHostMembership,
                           ReconHostSignals, ReconTarget, ReconWildcardCounts)
from hackbot.target_loader import load_target_package
from hackbot.target_recon import ReconDomainResolver
from hackbot.target_scope import HostRule


EXAMPLE = Path(__file__).parent / "examples/targets/example"
NOW = datetime.now(timezone.utc)


def package_for(primary="app.example.test", *, wildcard=True, exclude=()):
    package = load_target_package(EXAMPLE)
    rules = (HostRule(primary), HostRule("*.example.test")) if wildcard else (HostRule(primary),)
    return replace(package, target=replace(package.target, root_domain=primary),
                   scope=replace(package.scope, include_hosts=rules,
                                 exclude_hosts=tuple(HostRule(name) for name in exclude)))


def host(name, number, *, status=200, root=7, observed=NOW):
    return ReconHost(number, root, name, f"https://{name}", status,
                     Provenance("live_hosts", number, observed, "fixture"))


class SyntheticRecon:
    def __init__(self, *, root="example.test", primary="app.example.test",
                 siblings=(), primary_live=True):
        self.target = ReconTarget(7, root, True, True,
                                  Provenance("domains", 7, NOW, "fixture"))
        self.primary = primary
        self.siblings = tuple(siblings)
        self.primary_host = host(primary, 1) if primary_live else None
        self.calls = []

    def resolve_target(self, identity):
        self.calls.append(("resolve_target", identity))
        return self.target if identity == self.target.root_domain else None

    def resolve_host_membership(self, name):
        self.calls.append(("membership", name))
        return (ReconHostMembership(self.target, name, 11,
                                    self.primary_host.host_id if self.primary_host else None)
                if name == self.primary else None)

    def resolve_host(self, domain_id, origin):
        self.calls.append(("resolve_host", domain_id, origin))
        return self.primary_host if self.primary_host and domain_id == 7 and origin.rstrip("/") == self.primary_host.url else None

    def wildcard_counts(self, domain_id, suffix):
        self.calls.append(("wildcard_counts", domain_id, suffix))
        known = sum(item.hostname.endswith("." + suffix) for item in self.siblings)
        return ReconWildcardCounts(known, known, known)

    def list_wildcard_hosts(self, domain_id, suffix, *, limit=20, cursor=None):
        self.calls.append(("wildcard_page", domain_id, suffix, limit, cursor))
        values = [item for item in self.siblings if item.hostname.endswith("." + suffix)]
        start = int(cursor) if cursor else 0
        subset = tuple(values[start:start + limit])
        next_cursor = str(start + limit) if start + limit < len(values) else None
        return Page(subset, next_cursor)

    def host_signals(self, domain_id, ids):
        self.calls.append(("signals", domain_id, ids))
        return {value: ReconHostSignals(endpoint_count=100 if value == 102 else 2,
                                        js_count=20 if value == 102 else 0,
                                        api_count=1 if value == 102 else 0) for value in ids}


class ResolverTests(unittest.TestCase):
    def test_primary_subdomain_fk_is_recon_backed_with_focus(self):
        package = package_for()
        repo = SyntheticRecon(siblings=(host("api.example.test", 102), host("other.example.test", 103)))
        resolution = ReconDomainResolver(repo).resolve(package)
        self.assertEqual((resolution.target.root_domain, resolution.source, resolution.subdomain_id,
                          resolution.host_id), ("example.test", "SUBDOMAIN_FK", 11, 1))
        selection = ReconDomainResolver(repo).select_hosts(package, resolution=resolution)
        self.assertEqual(selection.hosts[0].hostname, "app.example.test")
        self.assertEqual(selection.related_hosts[0].host.hostname, "api.example.test")
        self.assertEqual(selection.wildcard_matches, 2)

    def test_exclusion_and_unrelated_recon_records_never_selected(self):
        package = package_for(exclude=("admin.example.test",))
        repo = SyntheticRecon(siblings=(host("admin.example.test", 101),
                                        host("api.example.test", 102),
                                        host("other.attacker.test", 103)))
        selection = ReconDomainResolver(repo).select_hosts(package)
        self.assertEqual([item.host.hostname for item in selection.related_hosts],
                         ["api.example.test"])
        self.assertEqual(selection.rejected[0][1], "EXCLUDED_HOST")
        self.assertNotIn("other.attacker.test", [item.hostname for item in selection.hosts])

    def test_hundreds_of_siblings_are_bounded_and_ranked(self):
        values = tuple(host(f"host{i}.example.test", i + 100) for i in range(500))
        repo = SyntheticRecon(siblings=values)
        selection = ReconDomainResolver(repo).select_hosts(package_for())
        self.assertEqual(selection.wildcard_matches, 500)
        self.assertEqual(selection.candidates_sampled, 200)
        self.assertLessEqual(len(selection.related_hosts), 4)
        self.assertTrue(selection.truncated)
        self.assertLessEqual(len([call for call in repo.calls if call[0] == "wildcard_page"]), 10)
        self.assertLessEqual(len([call for call in repo.calls if call[0] == "signals"][0][2]), 32)

    def test_apex_exact_resolution_and_no_wildcard(self):
        package = package_for("example.test", wildcard=False)
        repo = SyntheticRecon(primary="example.test", siblings=(host("api.example.test", 102),))
        result = ReconDomainResolver(repo).select_hosts(package)
        self.assertEqual(result.resolution.source, "DOMAINS_EXACT")
        self.assertEqual(result.related_hosts, ())
        self.assertFalse(any(call[0] == "wildcard_page" for call in repo.calls))

    def test_multilevel_suffix_uses_membership_not_public_suffix_guess(self):
        package = package_for("api.foo.example.co.uk", wildcard=False)
        repo = SyntheticRecon(root="example.co.uk", primary="api.foo.example.co.uk")
        result = ReconDomainResolver(repo).resolve(package)
        self.assertEqual(result.target.root_domain, "example.co.uk")
        self.assertEqual(result.source, "SUBDOMAIN_FK")

    def test_subdomain_without_live_host_is_still_resolved(self):
        package = package_for()
        repo = SyntheticRecon(primary_live=False)
        result = ReconDomainResolver(repo).select_hosts(package)
        self.assertEqual(result.resolution.source, "SUBDOMAIN_FK")
        self.assertIsNone(result.resolution.host_id)
        self.assertEqual(result.hosts, ())

    def test_empty_wildcard_inventory_and_restricted_scheme(self):
        package = package_for()
        repo = SyntheticRecon(siblings=())
        self.assertEqual(ReconDomainResolver(repo).select_hosts(package).related_hosts, ())
        restricted = replace(package, scope=replace(package.scope,
                             include_hosts=(HostRule("app.example.test"),
                                            HostRule("*.example.test", schemes=("http",)))))
        repo.siblings = (host("api.example.test", 102),)
        result = ReconDomainResolver(repo).select_hosts(restricted)
        self.assertEqual(result.related_hosts, ())
        self.assertEqual(result.rejected[0][1], "SCHEME_OR_PORT_RESTRICTED")


if __name__ == "__main__":
    unittest.main()
