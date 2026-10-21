"""Local self-response attribution and registry promotion checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.domain import ObservationState, Principal, TrafficSource
from hackbot.evidence import EvidenceProvenance, EvidenceType
from hackbot.identity_registry import IdentityRegistry
from hackbot.identity_observation import CapturedSelfObserver, IdentityObservationConflict
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.target_scope import ScopeResult
from hackbot.traffic import AuthState, ExchangeState


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class CapturedSelfObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = EvidenceFactStore(
            root / "state.sqlite3", ArtifactStore(root / "artifacts"),
            StoreSettings(root / "artifacts"))
        self.registry = IdentityRegistry(self.store)
        self.registry.initialize()
        self.package = load_target_package(EXAMPLE)
        self.registry.import_package_accounts(self.package)
        self.account = next(item for item in self.package.accounts
                            if item.alias == "org1_admin")
        self.identity = self.registry.get_identity(self.package.target.id, "org1_admin")
        assert self.identity is not None
        self.observer = CapturedSelfObserver(registry=self.registry, evidence=self.store)

    def exchange(self, *, alias: str = "org1_admin", tenant: str = "org1",
                 role: str = "admin", verified: bool = True):
        url = "https://example.test/api/me"
        body = json.dumps({"id": alias, "tenant": tenant, "role": role}).encode()
        request = self.store.create_evidence(
            EvidenceType.HTTP_REQUEST, json.dumps({"url": url}).encode(),
            source="FIXTURE", provenance=EvidenceProvenance(system="FIXTURE"),
            target_ref=self.package.target.id)
        response = self.store.create_evidence(
            EvidenceType.HTTP_RESPONSE, body, source="FIXTURE",
            provenance=EvidenceProvenance(system="FIXTURE"),
            target_ref=self.package.target.id)
        record = SimpleNamespace(
            target_id=self.package.target.id, package_id=self.package.id,
            source=TrafficSource.BURP, capture_provider="MONTOYA_V1",
            scope_result=ScopeResult.IN_SCOPE, state=ExchangeState.COMPLETE,
            attribution=SimpleNamespace(
                browser_session_id="BSESSION-" + "1" * 32,
                auth_state=AuthState.VERIFIED,
                verified_identity_id=(self.identity.id if verified else None)),
            request=SimpleNamespace(
                record=SimpleNamespace(method="GET"),
                observation_evidence_id=request.evidence_id),
            response=SimpleNamespace(
                record=SimpleNamespace(status_code=200,
                                       content_type="application/json",
                                       size_bytes=len(body)),
                body_evidence_id=response.evidence_id,
                body_hash=hashlib.sha256(body).hexdigest()))
        return url, record

    def observe(self, url: str, exchange) -> bool:
        return self.observer.observe(
            self.package, self.account, identity_id=self.identity.id,
            session_id="BSESSION-" + "1" * 32, url=url, exchange=exchange)

    def test_matching_self_response_promotes_principal_and_membership_once(self) -> None:
        url, exchange = self.exchange()
        self.assertTrue(self.observe(url, exchange))
        identity = self.registry.get_identity(self.package.target.id, self.identity.id)
        self.assertEqual(identity.principal_state, ObservationState.OBSERVED)
        memberships = self.registry.list_memberships(identity.id, limit=10).items
        observed = [item for item in memberships
                    if item.observation_state is ObservationState.OBSERVED]
        self.assertEqual(len(observed), 1)
        self.assertEqual(len(observed[0].role_ids), 1)
        self.assertTrue(self.observe(url, exchange))
        self.assertEqual(len([item for item in self.registry.list_memberships(
            identity.id, limit=10).items
            if item.observation_state is ObservationState.OBSERVED]), 1)

    def test_unverified_or_wrong_alias_never_promotes(self) -> None:
        url, exchange = self.exchange(verified=False)
        self.assertFalse(self.observe(url, exchange))
        url, exchange = self.exchange(alias="unrelated")
        self.assertFalse(self.observe(url, exchange))
        self.assertIsNone(self.registry.get_identity(
            self.package.target.id, self.identity.id).principal_id)

    def test_conflicting_tenant_is_manual_review_not_an_observed_fact(self) -> None:
        url, exchange = self.exchange(tenant="org2")
        with self.assertRaises(IdentityObservationConflict):
            self.observe(url, exchange)
        self.assertIsNone(self.registry.get_identity(
            self.package.target.id, self.identity.id).principal_id)

    def test_existing_observation_does_not_hide_principal_conflict(self) -> None:
        url, exchange = self.exchange()
        self.assertTrue(self.observe(url, exchange))
        other = self.registry.register_principal(
            Principal(target_id=self.package.target.id, label="another_account"))
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET principal_id=? WHERE identity_id=?",
                       (other.id, self.identity.id))
        with self.assertRaises(IdentityObservationConflict):
            self.observe(url, exchange)


if __name__ == "__main__":
    unittest.main()
