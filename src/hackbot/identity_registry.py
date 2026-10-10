"""BugHunter-owned identity registry. Metadata only; never authenticates."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from typing import Mapping

from .config import AppConfig
from .domain import ObservationState, Principal, Role, SourceRef, Target, Tenant, validate_entity_id
from .evidence import FactStatus
from .identity import (
    AccountSource, Identity, IdentityPair, IdentityStatus, MembershipStatus,
    PrincipalLink, TenantMembership, validate_alias, validate_secret_ref,
)
from .logging import SecretRedactor, is_sensitive_key
from .recon import Page
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .target_scope import validate_package_id


class RegistryConflict(ValueError):
    """The requested metadata conflicts with existing target-scoped state."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _source(ref: SourceRef | None) -> tuple[str | None, str | None]:
    if ref is not None:
        for value in (ref.entity, ref.record_id, ref.qualification):
            _reject_sensitive_text(value)
    return (ref.provider, ref.entity) if ref is not None else (None, None)


def _reject_sensitive_text(value: str | None) -> None:
    if value is not None and SecretRedactor().text(value) != value:
        raise ValueError("Credential-like identity value is forbidden")


def _restored_source(row: sqlite3.Row) -> SourceRef | None:
    return SourceRef(provider=row["source_provider"], entity=row["source_entity"]) if row["source_provider"] else None


def _safe_metadata(value: Mapping[str, object] | None) -> tuple[str | None, tuple[str, ...]]:
    if value is None:
        return None, ()
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError("Invalid identity metadata")
    if any(is_sensitive_key(key) for key in value):
        raise ValueError("Credential-like identity field is forbidden")
    if set(value) - {"purpose", "tags"}:
        raise ValueError("Unsupported identity metadata field")
    purpose = value.get("purpose")
    tags = value.get("tags", ())
    if not isinstance(tags, (list, tuple)):
        raise ValueError("Invalid identity tags")
    redactor = SecretRedactor()
    if purpose is not None and (not isinstance(purpose, str) or redactor.text(purpose) != purpose):
        raise ValueError("Credential-like identity value is forbidden")
    for tag in tags:
        if not isinstance(tag, str) or redactor.text(tag) != tag:
            raise ValueError("Credential-like identity value is forbidden")
    return purpose, tuple(tags)


def _identity_row(row: sqlite3.Row) -> Identity:
    meta = json.loads(row["metadata_json"])
    return Identity(
        id=row["identity_id"], target_id=row["target_id"], alias=row["alias"],
        status=IdentityStatus(row["status"]), account_source=AccountSource(row["account_source"]),
        principal_id=row["principal_id"],
        principal_state=ObservationState(row["principal_state"]) if row["principal_state"] else None,
        principal_fact_id=row["principal_fact_id"], secret_ref=row["secret_ref"],
        observation_state=ObservationState(row["observation_state"]),
        evidence_ids=tuple(json.loads(row["evidence_ids_json"])), source_ref=_restored_source(row),
        purpose=meta.get("purpose"), tags=tuple(meta.get("tags", [])),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


class IdentityRegistry:
    """Scoped metadata backed by the existing BugHunter SQLite file."""

    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @classmethod
    def from_config(cls, config: AppConfig) -> IdentityRegistry:
        return cls(EvidenceFactStore.from_config(config))

    def initialize(self) -> None:
        self.store.initialize()

    def _limit(self, limit: int) -> int:
        if type(limit) is not int or limit < 1:
            raise ValueError("Registry page size must be positive")
        return min(limit, self.store.settings.max_page_size)

    @staticmethod
    def _require_target(connection: sqlite3.Connection, target_id: str) -> None:
        validate_entity_id(target_id, "TARGET")
        if connection.execute("SELECT 1 FROM registry_targets WHERE target_id=? LIMIT 1", (target_id,)).fetchone() is None:
            raise ValueError("Target Package is not registered")

    @staticmethod
    def _require_entity(connection: sqlite3.Connection, table: str, id_column: str, entity_id: str, target_id: str) -> None:
        if connection.execute(f"SELECT 1 FROM {table} WHERE {id_column}=? AND target_id=? LIMIT 1",
                              (entity_id, target_id)).fetchone() is None:
            raise ValueError("Related registry entity is absent or belongs to another target")

    def _check_evidence(self, evidence_ids: tuple[str, ...], target_id: str) -> None:
        for evidence_id in evidence_ids:
            evidence = self.store.get_evidence(evidence_id)
            if evidence is None or evidence.target_ref != target_id:
                raise ValueError("Identity evidence is missing or belongs to another target")

    def _check_fact(self, fact_id: str, *, subjects: tuple[str, ...], predicate: str,
                    object_ref: str, target_id: str, evidence_ids: tuple[str, ...]) -> None:
        fact = self.store.get_fact(fact_id)
        if (fact is None or fact.subject not in subjects or fact.predicate != predicate
                or fact.object != object_ref or fact.target_ref != target_id
                or fact.source == "MANUAL" or fact.status is not FactStatus.ACTIVE or not fact.evidence_ids
                or not set(evidence_ids) <= set(fact.evidence_ids)):
            raise ValueError("Observed relationship requires a matching evidence-backed Fact")

    def register_target(self, package: TargetPackage) -> Target:
        if not isinstance(package, TargetPackage):
            raise ValueError("Target Package is required")
        with self.store._connection() as connection:
            row = connection.execute("SELECT target_id,package_id FROM registry_targets WHERE target_id=? OR package_id=? LIMIT 2",
                                     (package.target.id, package.id)).fetchall()
            if row:
                if len(row) != 1 or row[0]["target_id"] != package.target.id or row[0]["package_id"] != package.id:
                    raise RegistryConflict("Target Package ID conflicts with registered target")
            else:
                connection.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                                   (package.target.id, package.id, _now().isoformat()))
        return package.target

    def target_id_for_package(self, package_id: str) -> str | None:
        validate_package_id(package_id)
        with self.store._connection() as connection:
            row = connection.execute("SELECT target_id FROM registry_targets WHERE package_id=? LIMIT 1",
                                     (package_id,)).fetchone()
            return row["target_id"] if row else None

    def register_principal(self, principal: Principal) -> Principal:
        if not isinstance(principal, Principal):
            raise ValueError("Phase 4 Principal is required")
        _reject_sensitive_text(principal.label)
        _reject_sensitive_text(principal.external_user_id)
        self._check_evidence(principal.evidence_ids, principal.target_id)
        with self.store._connection() as connection:
            self._require_target(connection, principal.target_id)
            provider, entity = _source(principal.source_ref)
            try:
                connection.execute("""INSERT INTO registry_principals
                    (principal_id,target_id,label,external_user_id,observation_state,evidence_ids_json,
                     source_provider,source_entity,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (principal.id, principal.target_id, principal.label, principal.external_user_id,
                     principal.observation_state.value, _json(principal.evidence_ids), provider, entity,
                     principal.created_at.isoformat()))
            except sqlite3.IntegrityError:
                raise RegistryConflict("Principal already registered") from None
        return principal

    def get_principal(self, target_id: str, principal_id: str) -> Principal | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(principal_id, "PRINCIPAL")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_principals WHERE target_id=? AND principal_id=? LIMIT 1",
                                     (target_id, principal_id)).fetchone()
        if row is None:
            return None
        return Principal(id=row["principal_id"], target_id=row["target_id"], label=row["label"],
                         external_user_id=row["external_user_id"],
                         observation_state=ObservationState(row["observation_state"]),
                         evidence_ids=tuple(json.loads(row["evidence_ids_json"])), source_ref=_restored_source(row),
                         created_at=datetime.fromisoformat(row["created_at"]))

    def register_tenant(self, tenant: Tenant) -> Tenant:
        if not isinstance(tenant, Tenant):
            raise ValueError("Phase 4 Tenant is required")
        _reject_sensitive_text(tenant.label)
        _reject_sensitive_text(tenant.external_id)
        self._check_evidence(tenant.evidence_ids, tenant.target_id)
        with self.store._connection() as connection:
            self._require_target(connection, tenant.target_id)
            provider, entity = _source(tenant.source_ref)
            try:
                connection.execute("""INSERT INTO registry_tenants
                    (tenant_id,target_id,label,kind,observation_state,evidence_ids_json,
                     source_provider,source_entity,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (tenant.id, tenant.target_id, tenant.label, tenant.kind,
                     tenant.observation_state.value, _json(tenant.evidence_ids), provider, entity,
                     tenant.created_at.isoformat()))
            except sqlite3.IntegrityError:
                raise RegistryConflict("Tenant label or ID is already registered") from None
        return tenant

    def register_role(self, role: Role) -> Role:
        if not isinstance(role, Role):
            raise ValueError("Phase 4 Role is required")
        _reject_sensitive_text(role.name)
        _reject_sensitive_text(role.external_role_id)
        self._check_evidence(role.evidence_ids, role.target_id)
        with self.store._connection() as connection:
            self._require_target(connection, role.target_id)
            provider, entity = _source(role.source_ref)
            try:
                connection.execute("""INSERT INTO registry_roles
                    (role_id,target_id,name,observation_state,evidence_ids_json,
                     source_provider,source_entity,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                    (role.id, role.target_id, role.name, role.observation_state.value,
                     _json(role.evidence_ids), provider, entity, role.created_at.isoformat()))
            except sqlite3.IntegrityError:
                raise RegistryConflict("Role name or ID is already registered") from None
        return role

    def get_tenant(self, target_id: str, tenant_id: str) -> Tenant | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(tenant_id, "TENANT")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_tenants WHERE target_id=? AND tenant_id=? LIMIT 1",
                                     (target_id, tenant_id)).fetchone()
        if row is None:
            return None
        return Tenant(id=row["tenant_id"], target_id=row["target_id"], label=row["label"], kind=row["kind"],
                      observation_state=ObservationState(row["observation_state"]),
                      evidence_ids=tuple(json.loads(row["evidence_ids_json"])), source_ref=_restored_source(row),
                      created_at=datetime.fromisoformat(row["created_at"]))

    def get_role(self, target_id: str, role_id: str) -> Role | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(role_id, "ROLE")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_roles WHERE target_id=? AND role_id=? LIMIT 1",
                                     (target_id, role_id)).fetchone()
        if row is None:
            return None
        return Role(id=row["role_id"], target_id=row["target_id"], name=row["name"],
                    observation_state=ObservationState(row["observation_state"]),
                    evidence_ids=tuple(json.loads(row["evidence_ids_json"])), source_ref=_restored_source(row),
                    created_at=datetime.fromisoformat(row["created_at"]))

    def register_identity(
        self, target_id: str, alias: str, *, status: IdentityStatus = IdentityStatus.UNKNOWN,
        account_source: AccountSource = AccountSource.UNKNOWN,
        principal_id: str | None = None, secret_ref: str | None = None,
        metadata: Mapping[str, object] | None = None,
        observation_state: ObservationState = ObservationState.CONFIGURED,
        evidence_ids: tuple[str, ...] = (), source_ref: SourceRef | None = None,
    ) -> Identity:
        purpose, tags = _safe_metadata(metadata)
        now = _now()
        identity = Identity(target_id=target_id, alias=alias, status=status,
                            account_source=account_source, principal_id=principal_id,
                            principal_state=ObservationState.CONFIGURED if principal_id else None,
                            secret_ref=secret_ref, purpose=purpose, tags=tags,
                            observation_state=observation_state, evidence_ids=evidence_ids,
                            source_ref=source_ref, created_at=now, updated_at=now)
        self._check_evidence(identity.evidence_ids, target_id)
        with self.store._connection() as connection:
            self._require_target(connection, target_id)
            if principal_id is not None:
                self._require_entity(connection, "registry_principals", "principal_id", principal_id, target_id)
            provider, entity = _source(source_ref)
            try:
                connection.execute("""INSERT INTO registry_identities
                    (identity_id,target_id,alias,status,account_source,principal_id,principal_state,
                     principal_fact_id,secret_ref,observation_state,evidence_ids_json,source_provider,
                     source_entity,metadata_json,created_at,updated_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (identity.id, target_id, alias, status.value, account_source.value,
                     principal_id, identity.principal_state.value if identity.principal_state else None,
                     None, secret_ref, observation_state.value, _json(evidence_ids), provider,
                     entity, _json({"purpose": purpose, "tags": tags}), now.isoformat(), now.isoformat()))
                if principal_id is not None:
                    link = PrincipalLink(target_id=target_id, identity_id=identity.id,
                                         principal_id=principal_id, observation_state=ObservationState.CONFIGURED,
                                         created_at=now)
                    connection.execute("""INSERT INTO registry_principal_links
                        (link_id,target_id,identity_id,principal_id,observation_state,evidence_ids_json,fact_id,created_at)
                        VALUES (?,?,?,?,?,?,?,?)""",
                        (link.id, target_id, identity.id, principal_id, link.observation_state.value,
                         "[]", None, now.isoformat()))
            except sqlite3.IntegrityError:
                raise RegistryConflict("Identity alias or ID is already registered for target") from None
        return identity

    def get_identity(self, target_id: str, identity_id_or_alias: str) -> Identity | None:
        validate_entity_id(target_id, "TARGET")
        if identity_id_or_alias.startswith("IDENTITY-"):
            validate_entity_id(identity_id_or_alias, "IDENTITY")
            column = "identity_id"
        else:
            validate_alias(identity_id_or_alias)
            column = "alias"
        with self.store._connection() as connection:
            row = connection.execute(f"SELECT * FROM registry_identities WHERE target_id=? AND {column}=? LIMIT 1",
                                     (target_id, identity_id_or_alias)).fetchone()
        return _identity_row(row) if row else None

    def list_identities(self, target_id: str, *, limit: int = 20, cursor: str | None = None) -> Page[Identity]:
        validate_entity_id(target_id, "TARGET")
        maximum = self._limit(limit)
        if cursor is not None:
            validate_alias(cursor)
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT * FROM registry_identities
                WHERE target_id=? AND alias>? ORDER BY alias LIMIT ?""",
                (target_id, cursor or "", maximum + 1)).fetchall()
        return Page(tuple(_identity_row(row) for row in rows[:maximum]),
                    rows[maximum - 1]["alias"] if len(rows) > maximum else None)

    def list_identities_for_principal(self, target_id: str, principal_id: str, *,
                                      limit: int = 20, cursor: str | None = None) -> Page[Identity]:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(principal_id, "PRINCIPAL")
        maximum = self._limit(limit)
        if cursor is not None:
            validate_alias(cursor)
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT * FROM registry_identities
                WHERE target_id=? AND principal_id=? AND alias>?
                  AND NOT EXISTS (SELECT 1 FROM registry_principal_links pl
                    WHERE pl.identity_id=registry_identities.identity_id
                      AND pl.principal_id!=registry_identities.principal_id)
                ORDER BY alias LIMIT ?""",
                (target_id, principal_id, cursor or "", maximum + 1)).fetchall()
        return Page(tuple(_identity_row(row) for row in rows[:maximum]),
                    rows[maximum - 1]["alias"] if len(rows) > maximum else None)

    def _list_joined(self, target_id: str, clause: str, params: tuple[object, ...],
                     *, limit: int, cursor: str | None) -> Page[Identity]:
        validate_entity_id(target_id, "TARGET")
        maximum = self._limit(limit)
        if cursor is not None:
            validate_alias(cursor)
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT DISTINCT i.* FROM registry_identities i
                JOIN registry_memberships m ON m.identity_id=i.identity_id AND m.target_id=i.target_id
                LEFT JOIN registry_membership_roles mr ON mr.membership_id=m.membership_id
                WHERE i.target_id=? AND m.observation_state='CONFIGURED' AND m.status='ACTIVE'
                AND """ + clause + """ AND i.alias>? ORDER BY i.alias LIMIT ?""",
                (target_id, *params, cursor or "", maximum + 1)).fetchall()
        return Page(tuple(_identity_row(row) for row in rows[:maximum]),
                    rows[maximum - 1]["alias"] if len(rows) > maximum else None)

    def list_identities_for_tenant(self, target_id: str, tenant_id: str, *,
                                   limit: int = 20, cursor: str | None = None) -> Page[Identity]:
        validate_entity_id(tenant_id, "TENANT")
        return self._list_joined(target_id, "m.tenant_id=?", (tenant_id,), limit=limit, cursor=cursor)

    def list_identities_with_role(self, target_id: str, role_id: str, *, tenant_id: str | None = None,
                                  limit: int = 20, cursor: str | None = None) -> Page[Identity]:
        validate_entity_id(role_id, "ROLE")
        if tenant_id is not None:
            validate_entity_id(tenant_id, "TENANT")
        clause = "mr.role_id=?" + (" AND m.tenant_id=?" if tenant_id else "")
        params: tuple[object, ...] = (role_id, tenant_id) if tenant_id else (role_id,)
        return self._list_joined(target_id, clause, params, limit=limit, cursor=cursor)

    def update_identity(self, identity_id: str, changes: Mapping[str, object], *,
                        expected_updated_at: datetime | None = None) -> Identity:
        validate_entity_id(identity_id, "IDENTITY")
        if not isinstance(changes, Mapping) or not changes:
            raise ValueError("Identity changes must be a nonempty mapping")
        if any(not isinstance(key, str) or (is_sensitive_key(key) and key != "secret_ref") for key in changes):
            raise ValueError("Credential-like identity field is forbidden")
        if set(changes) - {"status", "secret_ref", "purpose", "tags"}:
            raise ValueError("Unsupported identity update field")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_identities WHERE identity_id=? LIMIT 1",
                                     (identity_id,)).fetchone()
            if row is None:
                raise ValueError("Identity not found")
            current = _identity_row(row)
            if expected_updated_at is not None and current.updated_at != expected_updated_at:
                raise RegistryConflict("Identity has changed since it was read")
            status = changes.get("status", current.status)
            source = current.account_source
            secret_ref = changes.get("secret_ref", current.secret_ref)
            if not isinstance(status, IdentityStatus) or not isinstance(source, AccountSource):
                raise ValueError("Invalid identity status or account source")
            validate_secret_ref(secret_ref)
            metadata = {"purpose": changes.get("purpose", current.purpose),
                        "tags": changes.get("tags", current.tags)}
            purpose, tags = _safe_metadata(metadata)
            changed_at = max(_now(), current.updated_at + timedelta(microseconds=1))
            updated = Identity(
                id=current.id, target_id=current.target_id, alias=current.alias,
                status=status, account_source=source, principal_id=current.principal_id,
                principal_state=current.principal_state, principal_fact_id=current.principal_fact_id,
                secret_ref=secret_ref, observation_state=current.observation_state,
                evidence_ids=current.evidence_ids, source_ref=current.source_ref,
                purpose=purpose, tags=tags, created_at=current.created_at, updated_at=changed_at,
            )
            updated_rows = connection.execute("""UPDATE registry_identities SET status=?,account_source=?,secret_ref=?,
                metadata_json=?,updated_at=? WHERE identity_id=? AND updated_at=?""",
                (updated.status.value, updated.account_source.value, updated.secret_ref,
                 _json({"purpose": purpose, "tags": tags}), changed_at.isoformat(),
                 identity_id, current.updated_at.isoformat())).rowcount
            if updated_rows != 1:
                raise RegistryConflict("Identity has changed since it was read")
            return updated

    def disable_identity(self, identity_id: str) -> Identity:
        return self.update_identity(identity_id, {"status": IdentityStatus.DISABLED})

    def enable_identity(self, identity_id: str) -> Identity:
        return self.update_identity(identity_id, {"status": IdentityStatus.ACTIVE})

    def link_principal(self, identity_id: str, principal_id: str, *,
                       observation_state: ObservationState = ObservationState.CONFIGURED,
                       evidence_ids: tuple[str, ...] = (), fact_id: str | None = None) -> PrincipalLink:
        validate_entity_id(identity_id, "IDENTITY")
        validate_entity_id(principal_id, "PRINCIPAL")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_identities WHERE identity_id=? LIMIT 1",
                                     (identity_id,)).fetchone()
            if row is None:
                raise ValueError("Identity not found")
            identity = _identity_row(row)
            self._require_entity(connection, "registry_principals", "principal_id", principal_id, identity.target_id)
        link = PrincipalLink(target_id=identity.target_id, identity_id=identity_id,
                             principal_id=principal_id, observation_state=observation_state,
                             evidence_ids=evidence_ids, fact_id=fact_id)
        self._check_evidence(link.evidence_ids, identity.target_id)
        if fact_id is not None:
            self._check_fact(fact_id, subjects=(identity_id,), predicate="resolves_to",
                             object_ref=principal_id, target_id=identity.target_id,
                             evidence_ids=evidence_ids)
        with self.store._connection() as connection:
            current = connection.execute("SELECT principal_id,principal_state FROM registry_identities WHERE identity_id=?",
                                         (identity_id,)).fetchone()
            try:
                connection.execute("""INSERT INTO registry_principal_links
                    (link_id,target_id,identity_id,principal_id,observation_state,evidence_ids_json,fact_id,created_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (link.id, link.target_id, link.identity_id, link.principal_id, link.observation_state.value,
                     _json(link.evidence_ids), link.fact_id, link.created_at.isoformat()))
            except sqlite3.IntegrityError:
                raise RegistryConflict("Principal link is already registered") from None
            if current["principal_id"] is None or (current["principal_id"] == principal_id
                                                      and current["principal_state"] == "CONFIGURED"
                                                      and observation_state is not ObservationState.CONFIGURED):
                connection.execute("""UPDATE registry_identities
                    SET principal_id=?,principal_state=?,principal_fact_id=?,updated_at=? WHERE identity_id=?""",
                    (principal_id, observation_state.value, fact_id, _now().isoformat(), identity_id))
        return link

    def list_principal_links(self, identity_id: str, *, limit: int = 20,
                             cursor: str | None = None) -> Page[PrincipalLink]:
        validate_entity_id(identity_id, "IDENTITY")
        maximum = self._limit(limit)
        if cursor is not None:
            validate_entity_id(cursor, "PRINCIPAL_LINK")
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT * FROM registry_principal_links
                WHERE identity_id=? AND link_id>? ORDER BY link_id LIMIT ?""",
                (identity_id, cursor or "", maximum + 1)).fetchall()
        return Page(tuple(PrincipalLink(
            id=row["link_id"], target_id=row["target_id"], identity_id=row["identity_id"],
            principal_id=row["principal_id"], observation_state=ObservationState(row["observation_state"]),
            evidence_ids=tuple(json.loads(row["evidence_ids_json"])), fact_id=row["fact_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
        ) for row in rows[:maximum]), rows[maximum - 1]["link_id"] if len(rows) > maximum else None)

    @staticmethod
    def _membership_row(connection: sqlite3.Connection, row: sqlite3.Row) -> TenantMembership:
        roles = tuple(item["role_id"] for item in connection.execute(
            "SELECT role_id FROM registry_membership_roles WHERE membership_id=? ORDER BY role_id LIMIT 17",
            (row["membership_id"],)))
        return TenantMembership(
            id=row["membership_id"], target_id=row["target_id"], identity_id=row["identity_id"],
            tenant_id=row["tenant_id"], role_ids=roles, status=MembershipStatus(row["status"]),
            is_primary=bool(row["is_primary"]), observation_state=ObservationState(row["observation_state"]),
            evidence_ids=tuple(json.loads(row["evidence_ids_json"])), fact_id=row["fact_id"],
            source_ref=_restored_source(row), created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def add_membership(
        self, identity_id: str, tenant_id: str, *, role_ids: tuple[str, ...] = (),
        status: MembershipStatus = MembershipStatus.UNKNOWN, is_primary: bool = False,
        observation_state: ObservationState = ObservationState.CONFIGURED,
        evidence_ids: tuple[str, ...] = (), fact_id: str | None = None,
        source_ref: SourceRef | None = None,
    ) -> TenantMembership:
        validate_entity_id(identity_id, "IDENTITY")
        validate_entity_id(tenant_id, "TENANT")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_identities WHERE identity_id=? LIMIT 1",
                                     (identity_id,)).fetchone()
            if row is None:
                raise ValueError("Identity not found")
            identity = _identity_row(row)
            self._require_entity(connection, "registry_tenants", "tenant_id", tenant_id, identity.target_id)
            for role_id in role_ids:
                validate_entity_id(role_id, "ROLE")
                self._require_entity(connection, "registry_roles", "role_id", role_id, identity.target_id)
        membership = TenantMembership(
            target_id=identity.target_id, identity_id=identity_id, tenant_id=tenant_id,
            role_ids=role_ids, status=status, is_primary=is_primary,
            observation_state=observation_state, evidence_ids=evidence_ids,
            fact_id=fact_id, source_ref=source_ref,
        )
        self._check_evidence(membership.evidence_ids, identity.target_id)
        if fact_id is not None:
            subjects = (identity.id, identity.principal_id) if identity.principal_id else (identity.id,)
            self._check_fact(fact_id, subjects=subjects, predicate="member_of",
                             object_ref=tenant_id, target_id=identity.target_id,
                             evidence_ids=evidence_ids)
        provider, entity = _source(source_ref)
        with self.store._connection() as connection:
            try:
                connection.execute("""INSERT INTO registry_memberships
                    (membership_id,target_id,identity_id,tenant_id,status,is_primary,observation_state,
                     evidence_ids_json,fact_id,source_provider,source_entity,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (membership.id, membership.target_id, membership.identity_id, membership.tenant_id,
                     membership.status.value, int(membership.is_primary), membership.observation_state.value,
                     _json(membership.evidence_ids), membership.fact_id, provider, entity,
                     membership.created_at.isoformat(), membership.updated_at.isoformat()))
                for role_id in role_ids:
                    connection.execute("""INSERT INTO registry_membership_roles
                        (target_id,membership_id,role_id) VALUES (?,?,?)""",
                        (identity.target_id, membership.id, role_id))
            except sqlite3.IntegrityError:
                raise RegistryConflict("Membership conflicts with existing target relationship") from None
        return membership

    def get_membership(self, membership_id: str) -> TenantMembership | None:
        validate_entity_id(membership_id, "MEMBERSHIP")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_memberships WHERE membership_id=? LIMIT 1",
                                     (membership_id,)).fetchone()
            return self._membership_row(connection, row) if row else None

    def list_memberships(self, identity_id: str, *, limit: int = 20,
                         cursor: str | None = None) -> Page[TenantMembership]:
        validate_entity_id(identity_id, "IDENTITY")
        maximum = self._limit(limit)
        if cursor is not None:
            validate_entity_id(cursor, "MEMBERSHIP")
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT * FROM registry_memberships
                WHERE identity_id=? AND membership_id>? ORDER BY membership_id LIMIT ?""",
                (identity_id, cursor or "", maximum + 1)).fetchall()
            items = tuple(self._membership_row(connection, row) for row in rows[:maximum])
        return Page(items, rows[maximum - 1]["membership_id"] if len(rows) > maximum else None)

    def set_membership_status(self, membership_id: str, status: MembershipStatus) -> TenantMembership:
        validate_entity_id(membership_id, "MEMBERSHIP")
        if not isinstance(status, MembershipStatus):
            raise ValueError("Invalid membership status")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_memberships WHERE membership_id=? LIMIT 1",
                                     (membership_id,)).fetchone()
            if row is None:
                raise ValueError("Membership not found")
            if row["observation_state"] != "CONFIGURED":
                raise RegistryConflict("Observed membership is immutable")
            primary = bool(row["is_primary"]) and status is MembershipStatus.ACTIVE
            connection.execute("""UPDATE registry_memberships SET status=?,is_primary=?,updated_at=?
                WHERE membership_id=?""", (status.value, int(primary), _now().isoformat(), membership_id))
        result = self.get_membership(membership_id)
        assert result is not None
        return result

    def set_membership_roles(self, membership_id: str, role_ids: tuple[str, ...]) -> TenantMembership:
        validate_entity_id(membership_id, "MEMBERSHIP")
        if not isinstance(role_ids, tuple) or len(role_ids) > 16 or len(set(role_ids)) != len(role_ids):
            raise ValueError("Invalid membership roles")
        with self.store._connection() as connection:
            row = connection.execute("SELECT * FROM registry_memberships WHERE membership_id=? LIMIT 1",
                                     (membership_id,)).fetchone()
            if row is None:
                raise ValueError("Membership not found")
            if row["observation_state"] != "CONFIGURED":
                raise RegistryConflict("Observed membership is immutable")
            for role_id in role_ids:
                validate_entity_id(role_id, "ROLE")
                self._require_entity(connection, "registry_roles", "role_id", role_id, row["target_id"])
            connection.execute("DELETE FROM registry_membership_roles WHERE membership_id=?", (membership_id,))
            for role_id in role_ids:
                connection.execute("INSERT INTO registry_membership_roles(target_id,membership_id,role_id) VALUES (?,?,?)",
                                   (row["target_id"], membership_id, role_id))
            connection.execute("UPDATE registry_memberships SET updated_at=? WHERE membership_id=?",
                               (_now().isoformat(), membership_id))
        result = self.get_membership(membership_id)
        assert result is not None
        return result

    def list_cross_tenant_identity_pairs(self, target_id: str, *, limit: int = 20) -> tuple[IdentityPair, ...]:
        """Configured active identities with no shared configured active tenant."""
        validate_entity_id(target_id, "TARGET")
        maximum = self._limit(limit)
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT i1.identity_id AS left_id,i2.identity_id AS right_id
                FROM registry_identities i1
                JOIN registry_identities i2 ON i2.target_id=i1.target_id AND i1.identity_id<i2.identity_id
                WHERE i1.target_id=? AND i1.status='ACTIVE' AND i2.status='ACTIVE'
                  AND (i1.principal_id IS NULL OR i2.principal_id IS NULL OR i1.principal_id!=i2.principal_id)
                  AND EXISTS (SELECT 1 FROM registry_memberships m
                    WHERE m.identity_id=i1.identity_id AND m.observation_state='CONFIGURED' AND m.status='ACTIVE')
                  AND EXISTS (SELECT 1 FROM registry_memberships m
                    WHERE m.identity_id=i2.identity_id AND m.observation_state='CONFIGURED' AND m.status='ACTIVE')
                  AND NOT EXISTS (SELECT 1 FROM registry_memberships a
                    JOIN registry_memberships b ON b.tenant_id=a.tenant_id
                    WHERE a.identity_id=i1.identity_id AND b.identity_id=i2.identity_id
                      AND a.observation_state='CONFIGURED' AND b.observation_state='CONFIGURED'
                      AND a.status='ACTIVE' AND b.status='ACTIVE')
                ORDER BY i1.identity_id,i2.identity_id LIMIT ?""", (target_id, maximum)).fetchall()
        return tuple(IdentityPair(row["left_id"], row["right_id"]) for row in rows)

    def list_same_tenant_different_role_pairs(self, target_id: str, *,
                                               limit: int = 20) -> tuple[IdentityPair, ...]:
        """Configured active pairs whose role sets differ in a shared tenant."""
        validate_entity_id(target_id, "TARGET")
        maximum = self._limit(limit)
        with self.store._connection() as connection:
            rows = connection.execute("""SELECT i1.identity_id AS left_id,i2.identity_id AS right_id,
                    a.tenant_id AS tenant_id
                FROM registry_memberships a
                JOIN registry_memberships b ON b.target_id=a.target_id AND b.tenant_id=a.tenant_id
                    AND a.identity_id<b.identity_id
                JOIN registry_identities i1 ON i1.identity_id=a.identity_id
                JOIN registry_identities i2 ON i2.identity_id=b.identity_id
                WHERE a.target_id=? AND a.observation_state='CONFIGURED' AND b.observation_state='CONFIGURED'
                    AND a.status='ACTIVE' AND b.status='ACTIVE'
                    AND i1.status='ACTIVE' AND i2.status='ACTIVE'
                    AND (
                      EXISTS (SELECT 1 FROM registry_membership_roles x WHERE x.membership_id=a.membership_id
                        AND NOT EXISTS (SELECT 1 FROM registry_membership_roles y
                          WHERE y.membership_id=b.membership_id AND y.role_id=x.role_id))
                      OR EXISTS (SELECT 1 FROM registry_membership_roles x WHERE x.membership_id=b.membership_id
                        AND NOT EXISTS (SELECT 1 FROM registry_membership_roles y
                          WHERE y.membership_id=a.membership_id AND y.role_id=x.role_id))
                    )
                ORDER BY a.tenant_id,i1.identity_id,i2.identity_id LIMIT ?""",
                (target_id, maximum)).fetchall()
        return tuple(IdentityPair(row["left_id"], row["right_id"], row["tenant_id"]) for row in rows)

    def import_package_accounts(self, package: TargetPackage) -> tuple[Identity, ...]:
        """Idempotently import non-secret Phase 5 aliases as configured metadata."""
        try:
            return self._import_package_accounts(package)
        except sqlite3.IntegrityError:
            raise RegistryConflict("Package account relationships conflict with registry state") from None

    def _import_package_accounts(self, package: TargetPackage) -> tuple[Identity, ...]:
        if not isinstance(package, TargetPackage):
            raise ValueError("Target Package is required")
        for account in package.accounts:
            if account.role_hint is not None and account.tenant_hint is None:
                raise ValueError("A package role hint requires a tenant hint")
            validate_secret_ref(account.secret_ref)
            _reject_sensitive_text(account.role_hint)
            _reject_sensitive_text(account.tenant_hint)
        self.register_target(package)
        target_id = package.target.id
        imported: list[Identity] = []
        with self.store._connection() as connection:
            for account in package.accounts:
                tenant_id = None
                role_id = None
                if account.tenant_hint is not None:
                    row = connection.execute("SELECT tenant_id FROM registry_tenants WHERE target_id=? AND label=? LIMIT 1",
                                             (target_id, account.tenant_hint)).fetchone()
                    if row is None:
                        tenant = Tenant(target_id=target_id, label=account.tenant_hint, kind="unknown",
                                        source_ref=SourceRef(provider="TARGET_PACKAGE", entity="account_metadata"))
                        connection.execute("""INSERT INTO registry_tenants
                            (tenant_id,target_id,label,kind,observation_state,evidence_ids_json,
                             source_provider,source_entity,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                            (tenant.id, target_id, tenant.label, tenant.kind, "CONFIGURED", "[]",
                             "TARGET_PACKAGE", "account_metadata", tenant.created_at.isoformat()))
                        tenant_id = tenant.id
                    else:
                        tenant_id = row["tenant_id"]
                if account.role_hint is not None:
                    row = connection.execute("SELECT role_id FROM registry_roles WHERE target_id=? AND name=? LIMIT 1",
                                             (target_id, account.role_hint)).fetchone()
                    if row is None:
                        role = Role(target_id=target_id, name=account.role_hint,
                                    source_ref=SourceRef(provider="TARGET_PACKAGE", entity="account_metadata"))
                        connection.execute("""INSERT INTO registry_roles
                            (role_id,target_id,name,observation_state,evidence_ids_json,
                             source_provider,source_entity,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                            (role.id, target_id, role.name, "CONFIGURED", "[]", "TARGET_PACKAGE",
                             "account_metadata", role.created_at.isoformat()))
                        role_id = role.id
                    else:
                        role_id = row["role_id"]
                row = connection.execute("SELECT * FROM registry_identities WHERE target_id=? AND alias=? LIMIT 1",
                                         (target_id, account.alias)).fetchone()
                if row is None:
                    now = _now()
                    identity = Identity(target_id=target_id, alias=account.alias,
                                        status=IdentityStatus.ACTIVE,
                                        account_source=AccountSource.RESEARCHER_PROVIDED,
                                        secret_ref=account.secret_ref,
                                        source_ref=SourceRef(provider="TARGET_PACKAGE", entity="account_metadata"),
                                        created_at=now, updated_at=now)
                    connection.execute("""INSERT INTO registry_identities
                        (identity_id,target_id,alias,status,account_source,principal_id,principal_state,
                         principal_fact_id,secret_ref,observation_state,evidence_ids_json,source_provider,
                         source_entity,metadata_json,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (identity.id, target_id, identity.alias, identity.status.value,
                         identity.account_source.value, None, None, None, identity.secret_ref,
                         "CONFIGURED", "[]", "TARGET_PACKAGE", "account_metadata",
                         _json({"purpose": None, "tags": []}), now.isoformat(), now.isoformat()))
                else:
                    identity = _identity_row(row)
                    if (identity.account_source is not AccountSource.RESEARCHER_PROVIDED
                            or identity.secret_ref != account.secret_ref):
                        raise RegistryConflict("Package account conflicts with registered identity")
                if tenant_id is not None:
                    row = connection.execute("""SELECT * FROM registry_memberships WHERE identity_id=?
                        AND tenant_id=? AND observation_state='CONFIGURED' LIMIT 1""",
                        (identity.id, tenant_id)).fetchone()
                    if row is None:
                        membership = TenantMembership(target_id=target_id, identity_id=identity.id,
                                                       tenant_id=tenant_id,
                                                       role_ids=(role_id,) if role_id else (),
                                                       status=MembershipStatus.ACTIVE, is_primary=True,
                                                       source_ref=SourceRef(provider="TARGET_PACKAGE",
                                                                            entity="account_metadata"))
                        connection.execute("""INSERT INTO registry_memberships
                            (membership_id,target_id,identity_id,tenant_id,status,is_primary,observation_state,
                             evidence_ids_json,fact_id,source_provider,source_entity,created_at,updated_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (membership.id, target_id, identity.id, tenant_id, "ACTIVE", 1, "CONFIGURED",
                             "[]", None, "TARGET_PACKAGE", "account_metadata",
                             membership.created_at.isoformat(), membership.updated_at.isoformat()))
                        if role_id:
                            connection.execute("""INSERT INTO registry_membership_roles
                                (target_id,membership_id,role_id) VALUES (?,?,?)""",
                                (target_id, membership.id, role_id))
                    else:
                        roles = {item["role_id"] for item in connection.execute(
                            "SELECT role_id FROM registry_membership_roles WHERE membership_id=?",
                            (row["membership_id"],))}
                        if roles != ({role_id} if role_id else set()):
                            raise RegistryConflict("Package membership conflicts with registered roles")
                imported.append(identity)
        return tuple(imported)
