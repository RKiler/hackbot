"""BugHunter-owned, secret-free cold-start run and observation ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import json
import sqlite3
import uuid

from .store import EvidenceFactStore


class DiscoveryState(StrEnum):
    COLD_START = "COLD_START"
    PARTIAL = "PARTIAL"
    BROWSER_PROFILED = "BROWSER_PROFILED"
    TRAFFIC_PROFILED = "TRAFFIC_PROFILED"
    RECON_BACKED = "RECON_BACKED"
    MATURE = "MATURE"


class BootstrapMode(StrEnum):
    COLD_START = "COLD_START"
    RECON_BACKED = "RECON_BACKED"


class BootstrapStatus(StrEnum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_LOGIN = "WAITING_LOGIN"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CANCELLED = "CANCELLED"


class BootstrapIdentityPolicy(StrEnum):
    ANONYMOUS_ONLY = "anonymous_only"
    PRIMARY_IDENTITY = "primary_identity"
    ANONYMOUS_PLUS_PRIMARY = "anonymous_plus_primary"


@dataclass(frozen=True, slots=True)
class BootstrapLimits:
    max_requests: int = 16
    max_pages: int = 5
    max_navigation_depth: int = 1
    max_js_assets: int = 6
    max_asset_bytes: int = 1_048_576
    max_redirects: int = 2
    max_bootstrap_duration: int = 120

    def __post_init__(self) -> None:
        caps = {"max_requests": 60, "max_pages": 12, "max_navigation_depth": 2,
                "max_js_assets": 20, "max_asset_bytes": 1_048_576,
                "max_redirects": 3, "max_bootstrap_duration": 600}
        for name, cap in caps.items():
            value = getattr(self, name)
            minimum = 0 if name in {"max_navigation_depth", "max_redirects"} else 1
            if type(value) is not int or not minimum <= value <= cap:
                raise ValueError("Invalid bounded bootstrap limits")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class BootstrapObservation:
    observation_id: str
    run_id: str
    target_id: str
    source: str
    code: str
    surface_key: str
    display: str
    evidence_id: str
    source_ref: str | None
    observed_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {"id": self.observation_id, "source": self.source, "code": self.code,
                "surface_key": self.surface_key, "display": self.display,
                "evidence_id": self.evidence_id, "observed_at": self.observed_at.isoformat()}


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    bootstrap_id: str
    target_id: str
    package_id: str
    mode: BootstrapMode
    status: BootstrapStatus
    started_at: datetime | None
    finished_at: datetime | None
    recon_domain_id: int | None
    identity_policy: BootstrapIdentityPolicy
    identity_id: str | None
    limits: BootstrapLimits
    counts: dict[str, int]
    limitations: tuple[str, ...]
    stop_reason: str | None
    cancel_requested: bool
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"bootstrap_id": self.bootstrap_id, "target_id": self.target_id,
                "package_id": self.package_id, "mode": self.mode.value,
                "status": self.status.value,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
                "recon_domain_id": self.recon_domain_id,
                "identity_policy": self.identity_policy.value,
                "identity_id": self.identity_id,
                "limits": self.limits.to_dict(), "coverage": dict(self.counts),
                "requests_used": self.counts["requests_used"],
                "pages_visited": self.counts["pages_visited"],
                "js_assets_discovered": self.counts["js_assets_discovered"],
                "js_assets_acquired": self.counts["js_assets_acquired"],
                "js_assets_changed": self.counts["js_assets_changed"],
                "api_surfaces_observed": self.counts["api_surfaces_observed"],
                "technologies_detected": self.counts["technologies_detected"],
                "features_detected": self.counts["features_detected"],
                "traffic_exchanges_recorded": self.counts["traffic_exchanges_recorded"],
                "facts_created": self.counts["facts_created"],
                "evidence_ids": list(self.evidence_ids),
                "limitations": list(self.limitations), "stop_reason": self.stop_reason,
                "cancel_requested": self.cancel_requested}


_COUNT_KEYS = ("requests_used", "pages_visited", "js_assets_discovered", "js_assets_acquired",
               "js_assets_changed",
               "api_surfaces_observed", "technologies_detected", "features_detected",
               "traffic_exchanges_recorded", "facts_created", "anonymous_pages",
               "authenticated_pages", "source_maps_acquired")
_ACTIVE = {BootstrapStatus.CREATED, BootstrapStatus.READY, BootstrapStatus.RUNNING}


class BootstrapStore:
    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    @staticmethod
    def _result(row, evidence_ids: tuple[str, ...] = ()) -> BootstrapResult:
        return BootstrapResult(
            row["run_id"], row["target_id"], row["package_id"], BootstrapMode(row["mode"]),
            BootstrapStatus(row["status"]),
            datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            row["recon_domain_id"], BootstrapIdentityPolicy(row["identity_policy"]),
            row["identity_id"], BootstrapLimits(**json.loads(row["limits_json"])),
            {**{key: 0 for key in _COUNT_KEYS}, **json.loads(row["counts_json"])},
            tuple(json.loads(row["limitations_json"])),
            row["stop_reason"], bool(row["cancel_requested"]), evidence_ids,
        )

    def create(self, target_id: str, package_id: str, mode: BootstrapMode,
               identity_policy: BootstrapIdentityPolicy, limits: BootstrapLimits,
               *, identity_id: str | None = None, session_id: str | None = None,
               recon_domain_id: int | None = None,
               campaign_work_id: str | None = None) -> BootstrapResult:
        run_id = "BOOT-" + uuid.uuid4().hex
        counts = {key: 0 for key in _COUNT_KEYS}
        try:
            with self.evidence._connection() as connection:
                connection.execute("""INSERT INTO bootstrap_runs
                    (run_id,target_id,package_id,mode,status,identity_policy,identity_id,session_id,
                     limits_json,counts_json,limitations_json,recon_domain_id,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (run_id, target_id, package_id, mode.value, BootstrapStatus.CREATED.value,
                     identity_policy.value, identity_id, session_id, json.dumps(limits.to_dict()),
                     json.dumps(counts), "[]", recon_domain_id, datetime.now(timezone.utc).isoformat()))
                if campaign_work_id is not None:
                    from .campaign_models import CampaignWorkKind
                    from .campaign_store import link_created_child
                    link_created_child(connection, campaign_work_id,
                                       kind=CampaignWorkKind.BOOTSTRAP,
                                       target_id=target_id, child_id=run_id)
        except sqlite3.IntegrityError as exc:
            with self.evidence._connection() as connection:
                active = connection.execute("SELECT 1 FROM bootstrap_runs WHERE target_id=? "
                                            "AND status IN ('CREATED','READY','RUNNING')", (target_id,)).fetchone()
            if active is None:
                raise
            raise ValueError("A bootstrap run is already active for this target") from exc
        result = self.get(run_id, target_id)
        assert result is not None
        return result

    def get(self, run_id: str, target_id: str) -> BootstrapResult | None:
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM bootstrap_runs WHERE run_id=? AND target_id=?",
                                     (run_id, target_id)).fetchone()
            if row is None:
                return None
            ids = tuple(item[0] for item in connection.execute(
                "SELECT DISTINCT evidence_id FROM bootstrap_observations WHERE run_id=? LIMIT 80", (run_id,)))
        return self._result(row, ids)

    def list_runs(self, target_id: str, *, limit: int = 20) -> tuple[BootstrapResult, ...]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid bootstrap page size")
        with self.evidence._connection() as connection:
            rows = connection.execute("SELECT * FROM bootstrap_runs WHERE target_id=? "
                                      "ORDER BY created_at DESC,run_id DESC LIMIT ?", (target_id, limit)).fetchall()
        return tuple(self._result(row) for row in rows)

    def list_observations(self, target_id: str, *, run_id: str | None = None,
                          limit: int = 80) -> tuple[BootstrapObservation, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid observation page size")
        sql = "SELECT * FROM bootstrap_observations WHERE target_id=?"
        params: list[object] = [target_id]
        if run_id is not None:
            sql += " AND run_id=?"
            params.append(run_id)
        sql += " ORDER BY observed_at DESC,observation_id DESC LIMIT ?"
        params.append(limit)
        with self.evidence._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        return tuple(BootstrapObservation(row["observation_id"], row["run_id"], row["target_id"],
                                          row["source"], row["code"], row["surface_key"], row["display"],
                                          row["evidence_id"], row["source_ref"],
                                          datetime.fromisoformat(row["observed_at"])) for row in rows)

    def add_observation(self, run_id: str, target_id: str, source: str, code: str,
                        surface_key: str, display: str, evidence_id: str,
                        source_ref: str | None) -> bool:
        if not all(isinstance(value, str) and 1 <= len(value) <= 180 and
                   all(32 <= ord(ch) < 127 for ch in value)
                   for value in (source, code, surface_key, display)):
            raise ValueError("Invalid bounded bootstrap observation")
        with self.evidence._connection() as connection:
            cursor = connection.execute("""INSERT OR IGNORE INTO bootstrap_observations
                (observation_id,run_id,target_id,source,code,surface_key,display,evidence_id,source_ref,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("BOBS-" + uuid.uuid4().hex, run_id, target_id, source, code, surface_key,
                 display, evidence_id, source_ref, datetime.now(timezone.utc).isoformat()))
            return bool(cursor.rowcount)

    def transition(self, run_id: str, target_id: str, status: BootstrapStatus, *,
                   counts: dict[str, int] | None = None, limitations: tuple[str, ...] | None = None,
                   stop_reason: str | None = None) -> BootstrapResult:
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM bootstrap_runs WHERE run_id=? AND target_id=?",
                                     (run_id, target_id)).fetchone()
            if row is None:
                raise LookupError("bootstrap run not found")
            old = BootstrapStatus(row["status"])
            if old not in _ACTIVE and old is not status:
                raise ValueError("bootstrap run is terminal")
            value = counts or json.loads(row["counts_json"])
            if set(value) != set(_COUNT_KEYS) or any(type(item) is not int or item < 0 for item in value.values()):
                raise ValueError("Invalid bootstrap counters")
            now = datetime.now(timezone.utc).isoformat()
            connection.execute("""UPDATE bootstrap_runs SET status=?,counts_json=?,limitations_json=?,
                stop_reason=?,started_at=COALESCE(started_at,?),finished_at=? WHERE run_id=?""",
                (status.value, json.dumps(value), json.dumps(sorted(set(limitations or ()))),
                 stop_reason, now, None if status in _ACTIVE else now, run_id))
        result = self.get(run_id, target_id)
        assert result is not None
        return result

    def reserve_request(self, run_id: str, target_id: str) -> bool:
        """Conservative pre-wire accounting for every executor dispatch, including redirects."""
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT status,cancel_requested,limits_json,counts_json FROM bootstrap_runs "
                                     "WHERE run_id=? AND target_id=?", (run_id, target_id)).fetchone()
            if row is None or row["status"] != BootstrapStatus.RUNNING.value or row["cancel_requested"]:
                return False
            counts = json.loads(row["counts_json"])
            if counts["requests_used"] >= json.loads(row["limits_json"])["max_requests"]:
                return False
            counts["requests_used"] += 1
            connection.execute("UPDATE bootstrap_runs SET counts_json=? WHERE run_id=?",
                               (json.dumps(counts), run_id))
            return True

    def request_cancel(self, run_id: str, target_id: str) -> bool:
        with self.evidence._connection() as connection:
            changed = connection.execute("UPDATE bootstrap_runs SET cancel_requested=1 "
                                         "WHERE run_id=? AND target_id=? AND status IN ('CREATED','READY','RUNNING')",
                                         (run_id, target_id)).rowcount
        return bool(changed)

    def cancelled(self, run_id: str, target_id: str) -> bool:
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT cancel_requested FROM bootstrap_runs "
                                     "WHERE run_id=? AND target_id=?", (run_id, target_id)).fetchone()
        return row is None or bool(row[0])

    def set_discovery_state(self, result: BootstrapResult, state: DiscoveryState) -> None:
        with self.evidence._connection() as connection:
            connection.execute("""INSERT INTO bootstrap_discovery_states
                (target_id,package_id,state,recon_domain_id,last_run_id,updated_at)
                VALUES (?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET
                package_id=excluded.package_id,state=excluded.state,
                recon_domain_id=excluded.recon_domain_id,last_run_id=excluded.last_run_id,
                updated_at=excluded.updated_at""",
                (result.target_id, result.package_id, state.value, result.recon_domain_id,
                 result.bootstrap_id, datetime.now(timezone.utc).isoformat()))

    def discovery_state(self, target_id: str) -> dict[str, object] | None:
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM bootstrap_discovery_states WHERE target_id=?",
                                     (target_id,)).fetchone()
        return dict(row) if row else None

    def reconcile(self) -> int:
        """Interrupted runs remain partial; never replay ambiguous browser or HTTP work."""
        now = datetime.now(timezone.utc).isoformat()
        with self.evidence._connection() as connection:
            cursor = connection.execute("""UPDATE bootstrap_runs SET status='PARTIAL',
                finished_at=?,stop_reason='SERVICE_RESTART',
                limitations_json='["INTERRUPTED_NO_REPLAY"]'
                WHERE status IN ('CREATED','READY','RUNNING')""", (now,))
            return cursor.rowcount
