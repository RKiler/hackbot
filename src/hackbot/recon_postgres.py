"""Bounded PostgreSQL reader for production recon observations."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
import json
import os
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .config import AppConfig, ConfigError, ReconSettings
from .recon import (
    Page, Provenance, ReconApiSurface, ReconAssetEvent, ReconEndpoint,
    ReconEndpointJsReference, ReconHost, ReconHostMembership, ReconHostSignals,
    ReconJsAnalysis, ReconJsAsset, ReconParameter, ReconScanSnapshot, ReconTarget,
    ReconWildcardCounts,
)


class ReconQueryError(RuntimeError):
    """Database read failed; never includes SQL parameters or credentials."""


class ReconScopeError(ValueError):
    """The selected child record does not belong to the selected root."""


def _id(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("A positive integer recon ID is required")
    return value


def _root_name(value: str) -> str:
    name = value.strip().lower().rstrip(".")
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Expected an exact root-domain name, not a URL or host")
    return name


def _cursor_encode(kind: str, scope: tuple[object, ...], key: tuple[object, int]) -> str:
    first = key[0].isoformat() if isinstance(key[0], datetime) else key[0]
    blob = json.dumps({"v": 1, "kind": kind, "scope": scope, "key": [first, key[1]]}, separators=(",", ":"))
    return base64.urlsafe_b64encode(blob.encode("utf-8")).decode("ascii").rstrip("=")


def _cursor_decode(
    token: str | None, kind: str, scope: tuple[object, ...], *, timestamp: bool = True
) -> tuple[datetime | str, int] | None:
    if token is None:
        return None
    if not isinstance(token, str) or not 1 <= len(token) <= 1024:
        raise ValueError("Invalid recon cursor")
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        data = json.loads(raw)
        if data["v"] != 1 or data["kind"] != kind or tuple(data["scope"]) != scope:
            raise ValueError
        first, row_id = data["key"]
        _id(row_id)
        if timestamp:
            first = datetime.fromisoformat(first)
            if first.tzinfo is not None:
                raise ValueError
        elif not isinstance(first, str) or len(first) > 253:
            raise ValueError
        return first, row_id
    except (ValueError, TypeError, KeyError, IndexError, UnicodeDecodeError, binascii.Error):
        raise ValueError("Invalid recon cursor") from None


def _prov(table: str, row: Mapping[str, Any], seen: str, qualification: str) -> Provenance:
    return Provenance(table, row["id"], row[seen], qualification)


_HOST_SCOPE = """
SELECT 1 FROM live_hosts lh JOIN subdomains s ON s.id=lh.subdomain_id
WHERE lh.id=%s AND s.domain_id=%s LIMIT 1
"""
_ENDPOINT_SCOPE = """
SELECT 1 FROM endpoints e JOIN live_hosts lh ON lh.id=e.live_host_id
JOIN subdomains s ON s.id=lh.subdomain_id
WHERE e.id=%s AND s.domain_id=%s LIMIT 1
"""
_ASSET_SCOPE = """
SELECT 1 FROM js_assets a JOIN live_hosts lh ON lh.id=a.live_host_id
JOIN subdomains s ON s.id=lh.subdomain_id
WHERE a.id=%s AND s.domain_id=%s LIMIT 1
"""
_ANALYSIS_COUNTS = (
    "endpoint_paths", "api_urls", "graphql_operations", "postmessage_usage",
    "dangerous_dom_sinks", "tokens_or_secret_like_strings",
)
_ANALYSIS_SQL = """
SELECT j.id,j.js_asset_id,j.analyzed_at,pg_column_size(j.extraction) AS extraction_bytes,
{counts}
FROM js_analysis_results j WHERE j.js_asset_id=%s LIMIT 1
""".format(counts=",\n".join(
    "CASE WHEN jsonb_typeof(j.extraction->'{key}')='array' "
    "THEN jsonb_array_length(j.extraction->'{key}') ELSE 0 END AS {key}_count".format(key=key)
    for key in _ANALYSIS_COUNTS
))


class PostgresReconRepository:
    """Each call uses a fresh, explicitly read-only transaction and closes it."""

    def __init__(self, connect: Callable[[], Any], settings: ReconSettings) -> None:
        self._connect = connect
        self._settings = settings

    @classmethod
    def from_config(
        cls, config: AppConfig, *, environ: Mapping[str, str] | None = None
    ) -> PostgresReconRepository:
        settings = config.recon
        if settings is None:
            raise ConfigError("Recon settings are unavailable")
        env = os.environ if environ is None else environ
        dsn = env.get(settings.dsn_env)
        if not dsn:
            raise ConfigError("Recon credential environment reference is not set")
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
        except ImportError:
            raise ConfigError("Install the optional recon PostgreSQL driver") from None

        def connect() -> Any:
            connection = psycopg2.connect(dsn, cursor_factory=RealDictCursor,
                                          connect_timeout=3)
            connection.autocommit = True
            return connection

        return cls(connect, settings)

    def _read(
        self,
        sql: str,
        params: tuple[object, ...],
        *,
        scope_sql: str | None = None,
        scope_params: tuple[object, ...] = (),
    ) -> list[Mapping[str, Any]]:
        connection: Any = None
        try:
            connection = self._connect()
            with connection.cursor() as cursor:
                cursor.execute("BEGIN READ ONLY")
                try:
                    cursor.execute(
                        "SELECT set_config('statement_timeout', %s, true)",
                        (str(self._settings.statement_timeout_ms),),
                    )
                    if scope_sql is not None:
                        cursor.execute(scope_sql, scope_params)
                        if cursor.fetchone() is None:
                            raise ReconScopeError("Recon record is outside the selected root")
                    cursor.execute(sql, params)
                    return list(cursor.fetchall())
                finally:
                    cursor.execute("ROLLBACK")
        except ReconScopeError:
            raise
        except Exception:
            raise ReconQueryError("Read-only recon query failed") from None
        finally:
            if connection is not None:
                connection.close()

    def probe(self) -> bool:
        """Check recon connectivity without reading target data or writing state."""
        rows = self._read(
            "SELECT current_setting('transaction_read_only') AS read_only LIMIT 1", ()
        )
        return len(rows) == 1 and rows[0].get("read_only") == "on"

    def _limit(self, limit: int) -> int:
        if type(limit) is not int or limit <= 0:
            raise ValueError("Recon page limit must be a positive integer")
        return min(limit, self._settings.max_page_size) + 1

    def _page(
        self, rows: list[Mapping[str, Any]], limit: int, kind: str,
        scope: tuple[object, ...], make: Callable[[Mapping[str, Any]], Any],
        key_field: str = "last_seen",
    ) -> Page[Any]:
        effective_limit = min(limit, self._settings.max_page_size)
        kept = rows[:effective_limit]
        next_cursor = None
        if len(rows) > effective_limit:
            last = kept[-1]
            next_cursor = _cursor_encode(kind, scope, (last[key_field], last["id"]))
        return Page(tuple(make(row) for row in kept), next_cursor)

    def resolve_target(self, identity: str | int) -> ReconTarget | None:
        if type(identity) is int:
            field, value = "id", _id(identity)
        elif isinstance(identity, str):
            field, value = "domain", _root_name(identity)
        else:
            raise ValueError("Expected a root domain or integer domain ID")
        # The field is selected from two fixed identifiers, never user SQL.
        rows = self._read(
            f"SELECT id,domain,active,include_subdomains,created_at FROM domains WHERE {field}=%s LIMIT 1",
            (value,),
        )
        if not rows:
            return None
        row = rows[0]
        return ReconTarget(
            row["id"], row["domain"], row["active"], row["include_subdomains"],
            _prov("domains", row, "created_at", "recon_inventory"),
        )

    def resolve_host(self, domain_id: int, exact_url: str) -> ReconHost | None:
        _id(domain_id)
        try:
            parsed = urlsplit(exact_url)
            valid = (parsed.scheme in {"http", "https"} and parsed.hostname is not None
                     and parsed.username is None and parsed.password is None
                     and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Expected an exact HTTP(S) host origin URL")
        rows = self._read("""
            SELECT lh.id,lh.url,lh.status_code,lh.last_seen,s.subdomain,s.domain_id
            FROM live_hosts lh JOIN subdomains s ON s.id=lh.subdomain_id
            WHERE lh.url=%s AND s.domain_id=%s LIMIT 1
        """, (exact_url, domain_id))
        return self._host(rows[0]) if rows else None

    def resolve_host_membership(self, hostname: str) -> ReconHostMembership | None:
        """Resolve an exact subdomain through its authoritative recon foreign key."""
        name = _root_name(hostname)
        rows = self._read("""
            SELECT s.id AS subdomain_id,s.subdomain,lh.id AS host_id,
                   d.id AS domain_id,d.domain,d.active,d.include_subdomains,d.created_at
            FROM subdomains s JOIN domains d ON d.id=s.domain_id
            LEFT JOIN LATERAL (
                SELECT id FROM live_hosts WHERE subdomain_id=s.id
                ORDER BY last_seen DESC,id DESC LIMIT 1
            ) lh ON true
            WHERE s.subdomain=%s
            ORDER BY length(d.domain) DESC,s.last_seen DESC,s.id DESC LIMIT 1
        """, (name,))
        if not rows:
            return None
        row = rows[0]
        target = ReconTarget(row["domain_id"], row["domain"], row["active"],
                             row["include_subdomains"],
                             Provenance("domains", row["domain_id"], row["created_at"],
                                        "recon_inventory"))
        return ReconHostMembership(target, name, row["subdomain_id"], row["host_id"])

    def list_wildcard_hosts(
        self, domain_id: int, suffix: str, *, limit: int = 20, cursor: str | None = None,
    ) -> Page[ReconHost]:
        """Recent recon origins below one already-authorized wildcard suffix."""
        _id(domain_id)
        name = _root_name(suffix)
        fetch_limit = self._limit(limit)
        scope = (domain_id, name)
        position = _cursor_decode(cursor, "wildcard_hosts", scope)
        condition = "AND (lh.last_seen,lh.id)<(%s,%s)" if position else ""
        params: tuple[object, ...] = ((domain_id, "%." + name, *position, fetch_limit)
                                      if position else (domain_id, "%." + name, fetch_limit))
        rows = self._read(f"""
            SELECT lh.id,lh.url,lh.status_code,lh.last_seen,s.subdomain,s.domain_id
            FROM subdomains s JOIN live_hosts lh ON lh.subdomain_id=s.id
            WHERE s.domain_id=%s AND s.subdomain LIKE %s {condition}
            ORDER BY lh.last_seen DESC,lh.id DESC LIMIT %s
        """, params)
        return self._page(rows, limit, "wildcard_hosts", scope, self._host)

    def wildcard_counts(self, domain_id: int, suffix: str) -> ReconWildcardCounts:
        _id(domain_id)
        name = _root_name(suffix)
        rows = self._read("""
            WITH latest AS (
                SELECT scan_started_at FROM scan_snapshots
                WHERE domain_id=%s AND scan_finished_at IS NOT NULL
                ORDER BY scan_finished_at DESC,id DESC LIMIT 1
            )
            SELECT count(DISTINCT s.id) AS known,
                   count(DISTINCT s.id) FILTER (WHERE lh.id IS NOT NULL) AS live,
                   count(DISTINCT s.id) FILTER (
                       WHERE latest.scan_started_at IS NOT NULL
                         AND s.last_seen>=latest.scan_started_at) AS latest_scan
            FROM subdomains s LEFT JOIN live_hosts lh ON lh.subdomain_id=s.id
            LEFT JOIN latest ON true
            WHERE s.domain_id=%s AND s.subdomain LIKE %s
        """, (domain_id, domain_id, "%." + name))
        row = rows[0]
        return ReconWildcardCounts(int(row["known"]), int(row["live"]), int(row["latest_scan"]))

    def host_signals(self, domain_id: int, host_ids: tuple[int, ...]) -> dict[int, ReconHostSignals]:
        _id(domain_id)
        if not isinstance(host_ids, tuple) or len(host_ids) > 32:
            raise ValueError("Host signal shortlist must contain at most 32 IDs")
        if not host_ids:
            return {}
        ids = tuple(_id(item) for item in host_ids)
        rows = self._read("""
            SELECT lh.id,
                   (SELECT count(*) FROM endpoints e WHERE e.live_host_id=lh.id) AS endpoint_count,
                   (SELECT count(*) FROM js_assets a WHERE a.live_host_id=lh.id) AS js_count,
                   (SELECT count(*) FROM api_surfaces p WHERE p.live_host_id=lh.id) AS api_count
            FROM live_hosts lh JOIN subdomains s ON s.id=lh.subdomain_id
            WHERE s.domain_id=%s AND lh.id=ANY(%s)
        """, (domain_id, list(ids)))
        return {row["id"]: ReconHostSignals(int(row["endpoint_count"]),
                                             int(row["js_count"]), int(row["api_count"]))
                for row in rows}

    @staticmethod
    def _host(row: Mapping[str, Any]) -> ReconHost:
        return ReconHost(
            row["id"], row["domain_id"], row["subdomain"], row["url"],
            row["status_code"], _prov("live_hosts", row, "last_seen", "latest_recon_row"),
        )

    def list_hosts(self, domain_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconHost]:
        _id(domain_id)
        fetch_limit = self._limit(limit)
        scope = (domain_id,)
        position = _cursor_decode(cursor, "hosts", scope, timestamp=False)
        condition = "AND (s.subdomain,lh.id)>(%s,%s)" if position else ""
        params: tuple[object, ...] = (domain_id, *position, fetch_limit) if position else (domain_id, fetch_limit)
        rows = self._read(f"""
            SELECT lh.id,lh.url,lh.status_code,lh.last_seen,s.subdomain,s.domain_id
            FROM subdomains s JOIN live_hosts lh ON lh.subdomain_id=s.id
            WHERE s.domain_id=%s {condition}
            ORDER BY s.subdomain ASC,lh.id ASC LIMIT %s
        """, params)
        return self._page(rows, limit, "hosts", scope, self._host, "subdomain")

    def list_endpoints(self, domain_id: int, host_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconEndpoint]:
        _id(domain_id)
        _id(host_id)
        fetch_limit = self._limit(limit)
        scope = (domain_id, host_id)
        position = _cursor_decode(cursor, "endpoints", scope)
        condition = "AND (last_seen,id)<(%s,%s)" if position else ""
        params = (host_id, *position, fetch_limit) if position else (host_id, fetch_limit)
        rows = self._read(f"""
            SELECT id,live_host_id,path,method,status_code,source,last_seen FROM endpoints
            WHERE live_host_id=%s {condition}
            ORDER BY last_seen DESC,id DESC LIMIT %s
        """, params, scope_sql=_HOST_SCOPE, scope_params=(host_id, domain_id))
        return self._page(rows, limit, "endpoints", scope, lambda r: ReconEndpoint(
            r["id"], r["live_host_id"], r["path"], r["method"], r["status_code"],
            r["source"], _prov("endpoints", r, "last_seen", "latest_recon_row"),
        ))

    def list_parameters(self, domain_id: int, endpoint_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconParameter]:
        _id(domain_id)
        _id(endpoint_id)
        fetch_limit = self._limit(limit)
        scope = (domain_id, endpoint_id)
        position = _cursor_decode(cursor, "parameters", scope)
        condition = "AND (last_seen,id)<(%s,%s)" if position else ""
        params = (endpoint_id, *position, fetch_limit) if position else (endpoint_id, fetch_limit)
        rows = self._read(f"""
            SELECT id,endpoint_id,param_name,risk_tags,last_seen FROM url_parameters
            WHERE endpoint_id=%s {condition}
            ORDER BY last_seen DESC,id DESC LIMIT %s
        """, params, scope_sql=_ENDPOINT_SCOPE, scope_params=(endpoint_id, domain_id))
        return self._page(rows, limit, "parameters", scope, lambda r: ReconParameter(
            r["id"], r["endpoint_id"], r["param_name"], tuple(r["risk_tags"] or ()),
            _prov("url_parameters", r, "last_seen", "latest_recon_row"),
        ))

    def list_js_assets(self, domain_id: int, host_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconJsAsset]:
        _id(domain_id)
        _id(host_id)
        fetch_limit = self._limit(limit)
        scope = (domain_id, host_id)
        position = _cursor_decode(cursor, "js_assets", scope)
        condition = "AND (last_seen,id)<(%s,%s)" if position else ""
        params = (host_id, *position, fetch_limit) if position else (host_id, fetch_limit)
        rows = self._read(f"""
            SELECT id,live_host_id,asset_url,sha256,size_bytes,http_status,last_seen
            FROM js_assets WHERE live_host_id=%s {condition}
            ORDER BY last_seen DESC,id DESC LIMIT %s
        """, params, scope_sql=_HOST_SCOPE, scope_params=(host_id, domain_id))
        return self._page(rows, limit, "js_assets", scope, lambda r: ReconJsAsset(
            r["id"], r["live_host_id"], r["asset_url"], r["sha256"], r["size_bytes"],
            r["http_status"], _prov("js_assets", r, "last_seen", "latest_recon_row"),
        ))

    def get_js_asset(self, domain_id: int, asset_id: int) -> ReconJsAsset | None:
        _id(domain_id)
        _id(asset_id)
        rows = self._read("""
            SELECT a.id,a.live_host_id,a.asset_url,a.sha256,a.size_bytes,a.http_status,a.last_seen
            FROM js_assets a JOIN live_hosts lh ON lh.id=a.live_host_id
            JOIN subdomains s ON s.id=lh.subdomain_id
            WHERE a.id=%s AND s.domain_id=%s LIMIT 1
        """, (asset_id, domain_id))
        if not rows:
            return None
        row = rows[0]
        return ReconJsAsset(row["id"], row["live_host_id"], row["asset_url"], row["sha256"],
                            row["size_bytes"], row["http_status"],
                            _prov("js_assets", row, "last_seen", "latest_recon_row"))

    def get_js_analysis(self, domain_id: int, asset_id: int) -> ReconJsAnalysis | None:
        _id(domain_id)
        _id(asset_id)
        rows = self._read(_ANALYSIS_SQL, (asset_id,), scope_sql=_ASSET_SCOPE, scope_params=(asset_id, domain_id))
        if not rows:
            return None
        row = rows[0]
        return ReconJsAnalysis(
            row["id"], row["js_asset_id"], row["extraction_bytes"],
            {key: row[key + "_count"] for key in _ANALYSIS_COUNTS},
            _prov("js_analysis_results", row, "analyzed_at", "extraction_metadata"),
        )

    def list_endpoint_js_references(self, domain_id: int, endpoint_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconEndpointJsReference]:
        _id(domain_id)
        _id(endpoint_id)
        fetch_limit = self._limit(limit)
        scope = (domain_id, endpoint_id)
        position = _cursor_decode(cursor, "endpoint_js_references", scope)
        condition = "AND (last_seen,id)<(%s,%s)" if position else ""
        params = (endpoint_id, *position, fetch_limit) if position else (endpoint_id, fetch_limit)
        rows = self._read(f"""
            SELECT id,endpoint_id,js_asset_id,last_seen FROM endpoint_js_references
            WHERE endpoint_id=%s {condition}
            ORDER BY last_seen DESC,id DESC LIMIT %s
        """, params, scope_sql=_ENDPOINT_SCOPE, scope_params=(endpoint_id, domain_id))
        return self._page(rows, limit, "endpoint_js_references", scope, lambda r: ReconEndpointJsReference(
            r["id"], r["endpoint_id"], r["js_asset_id"],
            _prov("endpoint_js_references", r, "last_seen", "latest_recon_row"),
        ))

    def list_api_surfaces(self, domain_id: int, surface_type: str, *, host_id: int | None = None, limit: int = 20, cursor: str | None = None) -> Page[ReconApiSurface]:
        _id(domain_id)
        if host_id is not None:
            _id(host_id)
        if not isinstance(surface_type, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", surface_type):
            raise ValueError("An exact API surface type is required")
        fetch_limit = self._limit(limit)
        scope = (domain_id, surface_type) if host_id is None else (domain_id, surface_type, host_id)
        position = _cursor_decode(cursor, "api_surfaces", scope)
        condition = "AND (last_seen,id)<(%s,%s)" if position else ""
        host_condition = "AND live_host_id=%s" if host_id is not None else ""
        params = (domain_id, surface_type, *((host_id,) if host_id is not None else ()),
                  *(position or ()), fetch_limit)
        rows = self._read(f"""
            SELECT id,domain_id,live_host_id,surface_type,location,status_code,operations_count,last_seen
            FROM api_surfaces WHERE domain_id=%s AND surface_type=%s {host_condition} {condition}
            ORDER BY last_seen DESC,id DESC LIMIT %s
        """, params)
        return self._page(rows, limit, "api_surfaces", scope, lambda r: ReconApiSurface(
            r["id"], r["domain_id"], r["live_host_id"], r["surface_type"],
            r["location"], r["status_code"], r["operations_count"],
            _prov("api_surfaces", r, "last_seen", "recon_hint"),
        ))

    def list_scan_snapshots(self, domain_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconScanSnapshot]:
        _id(domain_id)
        fetch_limit = self._limit(limit)
        scope = (domain_id,)
        position = _cursor_decode(cursor, "scan_snapshots", scope)
        condition = "AND (scan_finished_at,id)<(%s,%s)" if position else ""
        params = (domain_id, *position, fetch_limit) if position else (domain_id, fetch_limit)
        rows = self._read(f"""
            SELECT id,domain_id,scan_started_at,scan_finished_at,first_run
            FROM scan_snapshots WHERE domain_id=%s AND scan_finished_at IS NOT NULL {condition}
            ORDER BY scan_finished_at DESC,id DESC LIMIT %s
        """, params)
        return self._page(rows, limit, "scan_snapshots", scope, lambda r: ReconScanSnapshot(
            r["id"], r["domain_id"], r["scan_started_at"], r["scan_finished_at"],
            r["first_run"], _prov("scan_snapshots", r, "scan_finished_at", "completed_scan"),
        ), "scan_finished_at")

    @staticmethod
    def _asset_event(row: Mapping[str, Any]) -> ReconAssetEvent:
        return ReconAssetEvent(
            row["id"], row["domain_id"], row["event_type"], row["entity_type"],
            row["entity_id"], row["location"], row["severity"],
            _prov("asset_events", row, "last_seen", "recon_event"),
            row.get("first_seen"), row.get("content_sha256"),
        )

    def get_asset_event(self, domain_id: int, event_id: int) -> ReconAssetEvent | None:
        _id(domain_id)
        _id(event_id)
        rows = self._read("""
            SELECT id,domain_id,event_type,entity_type,entity_id,location,severity,
                   first_seen,last_seen,payload->>'sha256' AS content_sha256
            FROM asset_events WHERE id=%s AND domain_id=%s LIMIT 1
        """, (event_id, domain_id))
        return self._asset_event(rows[0]) if rows else None

    def list_asset_events(self, domain_id: int, window_start: datetime, window_end: datetime, *, limit: int = 20, cursor: str | None = None) -> Page[ReconAssetEvent]:
        _id(domain_id)
        if (not isinstance(window_start, datetime) or not isinstance(window_end, datetime)
            or window_start.tzinfo is not None or window_end.tzinfo is not None
            or not window_start < window_end or window_end - window_start > timedelta(days=31)):
            raise ValueError("A naive, positive recon event window of at most 31 days is required")
        fetch_limit = self._limit(limit)
        scope = (domain_id, window_start.isoformat(), window_end.isoformat())
        position = _cursor_decode(cursor, "asset_events", scope)
        condition = "AND (last_seen,id)<(%s,%s)" if position else ""
        params = ((domain_id, window_start, window_end, *position, fetch_limit)
                  if position else (domain_id, window_start, window_end, fetch_limit))
        rows = self._read(f"""
            SELECT id,domain_id,event_type,entity_type,entity_id,location,severity,
                   first_seen,last_seen,payload->>'sha256' AS content_sha256
            FROM asset_events WHERE domain_id=%s AND last_seen>=%s AND last_seen<%s {condition}
            ORDER BY last_seen DESC,id DESC LIMIT %s
        """, params)
        return self._page(rows, limit, "asset_events", scope, self._asset_event)
