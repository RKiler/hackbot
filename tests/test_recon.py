from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.config import ConfigError, ReconSettings, load_config
from hackbot.recon import ReconRepository
from hackbot.recon_postgres import PostgresReconRepository, ReconQueryError, ReconScopeError


NOW = datetime(2026, 10, 10, 12, 0, 0)


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.connection.calls.append((sql, tuple(params)))
        if sql.lstrip().startswith("SELECT 1 FROM"):
            self.rows = [] if self.connection.outside_scope else [{"one": 1}]
        elif sql.lstrip().startswith("SELECT set_config"):
            self.rows = [{"set_config": "3000"}]
        elif sql.lstrip().startswith("SELECT"):
            self.rows = self.connection.result(sql, tuple(params))
        else:
            self.rows = []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, result):
        self.result = result
        self.calls = []
        self.outside_scope = False
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


class ReconTests(unittest.TestCase):
    def setUp(self):
        self.connection = FakeConnection(lambda _sql, _params: [])
        self.repo = PostgresReconRepository(lambda: self.connection, ReconSettings(max_page_size=2))

    def test_contract_has_no_write_methods(self):
        self.assertIsInstance(self.repo, ReconRepository)
        self.assertFalse(any(name.startswith(("create_", "update_", "delete_", "save_"))
                             for name in ReconRepository.__dict__))

    def test_target_resolution_is_exact_and_parameterized(self):
        self.connection.result = lambda _sql, _params: [{
            "id": 5, "domain": "zapier.com", "active": True,
            "include_subdomains": True, "created_at": NOW,
        }]
        target = self.repo.resolve_target("ZAPIER.COM.")
        self.assertEqual(target.domain_id, 5)
        self.assertTrue(target.recon_present)
        self.assertEqual(target.provenance.source_table, "domains")
        query, params = self.connection.calls[-2]
        self.assertIn("WHERE domain=%s LIMIT 1", query)
        self.assertEqual(params, ("zapier.com",))
        self.assertEqual(self.repo.resolve_target(5).root_domain, "zapier.com")
        with self.assertRaises(ValueError):
            self.repo.resolve_target("https://app.zapier.com")

    def test_host_resolution_requires_exact_url_and_domain(self):
        self.connection.result = lambda _sql, _params: [{
            "id": 12, "url": "https://app.zapier.com", "status_code": 200,
            "last_seen": NOW, "subdomain": "app.zapier.com", "domain_id": 5,
        }]
        host = self.repo.resolve_host(5, "https://app.zapier.com")
        self.assertEqual(host.hostname, "app.zapier.com")
        self.assertEqual(host.provenance.source_id, 12)
        self.assertNotIn("https://app.zapier.com", repr(host))
        query, params = self.connection.calls[-2]
        self.assertEqual(params, ("https://app.zapier.com", 5))
        self.assertIn("lh.url=%s AND s.domain_id=%s", query)
        with self.assertRaises(ValueError):
            self.repo.resolve_host(5, "https://app.zapier.com/private")

    def test_host_cursor_paginates_without_offset(self):
        rows = [
            {"id": i, "url": "https://a.example.com", "status_code": 200,
             "last_seen": NOW, "subdomain": "a.example.com", "domain_id": 5}
            for i in (10, 11, 12)
        ]
        self.connection.result = lambda _sql, params: rows if len(params) == 2 else rows[2:]
        first = self.repo.list_hosts(5, limit=2)
        self.assertEqual([item.host_id for item in first.items], [10, 11])
        self.assertIsNotNone(first.next_cursor)
        second = self.repo.list_hosts(5, limit=2, cursor=first.next_cursor)
        self.assertEqual([item.host_id for item in second.items], [12])
        query, params = self.connection.calls[-2]
        self.assertIn("(s.subdomain,lh.id)>(%s,%s)", query)
        self.assertEqual(params, (5, "a.example.com", 11, 3))
        self.assertNotIn("OFFSET", query.upper())

    def test_endpoint_cursor_and_scope(self):
        rows = [
            {"id": i, "live_host_id": 12, "path": "/api/item", "method": "GET",
             "status_code": 200, "source": "js", "last_seen": NOW - timedelta(seconds=i)}
            for i in (1, 2, 3)
        ]
        self.connection.result = lambda _sql, params: rows if len(params) == 2 else rows[2:]
        first = self.repo.list_endpoints(5, 12, limit=2)
        self.assertEqual(len(first.items), 2)
        self.assertEqual(first.items[0].provenance.source_table, "endpoints")
        self.assertEqual(first.items[0].provenance.observed_at, NOW - timedelta(seconds=1))
        self.repo.list_endpoints(5, 12, limit=2, cursor=first.next_cursor)
        query, params = self.connection.calls[-2]
        self.assertIn("(last_seen,id)<(%s,%s)", query)
        self.assertEqual(params, (12, NOW - timedelta(seconds=2), 2, 3))
        self.assertTrue(self.connection.closed)

    def test_cursor_cannot_cross_scope_or_kind(self):
        self.connection.result = lambda _sql, _params: [
            {"id": i, "url": "https://a.example.com", "status_code": 200,
             "last_seen": NOW, "subdomain": "a.example.com", "domain_id": 5}
            for i in (1, 2, 3)
        ]
        token = self.repo.list_hosts(5, limit=2).next_cursor
        with self.assertRaises(ValueError):
            self.repo.list_hosts(6, cursor=token)
        with self.assertRaises(ValueError):
            self.repo.list_endpoints(5, 12, cursor=token)
        with self.assertRaises(ValueError):
            self.repo.list_hosts(5, cursor="not-a-cursor")

    def test_limit_is_bounded_before_connection(self):
        with self.assertRaises(ValueError):
            self.repo.list_hosts(5, limit=0)
        self.assertEqual(self.connection.calls, [])
        self.repo.list_endpoints(5, 12, limit=1000)
        query, params = self.connection.calls[-2]
        self.assertEqual(params[-1], 3)
        self.assertIn("LIMIT %s", query)

    def test_child_ownership_checked_before_read(self):
        self.connection.outside_scope = True
        with self.assertRaises(ReconScopeError):
            self.repo.list_endpoints(5, 12)
        calls = [sql for sql, _ in self.connection.calls]
        self.assertIn("BEGIN READ ONLY", calls)
        self.assertIn("ROLLBACK", calls)
        self.assertFalse(any("FROM endpoints\n" in sql for sql in calls))

    def test_parameter_example_and_reference_found_value_not_selected(self):
        self.connection.result = lambda sql, _params: ([{
            "id": 8, "endpoint_id": 7, "param_name": "token", "risk_tags": ["auth"],
            "last_seen": NOW, "example_value": "PRIVATE_VALUE",
        }] if "FROM url_parameters" in sql else [{
            "id": 9, "endpoint_id": 7, "js_asset_id": 3, "last_seen": NOW,
            "found_value": "PRIVATE_VALUE",
        }])
        parameter = self.repo.list_parameters(5, 7).items[0]
        reference = self.repo.list_endpoint_js_references(5, 7).items[0]
        self.assertNotIn("PRIVATE_VALUE", repr(parameter) + repr(reference))
        sql = " ".join(query for query, _ in self.connection.calls)
        self.assertNotIn("example_value", sql)
        self.assertNotIn("found_value", sql)

    def test_js_asset_and_analysis_are_metadata_only(self):
        self.connection.result = lambda sql, _params: ([{
            "id": 3, "live_host_id": 12, "asset_url": "https://app.example.com/a.js",
            "sha256": "abc", "size_bytes": 123, "http_status": 200, "last_seen": NOW,
        }] if "FROM js_assets" in sql else [{
            "id": 4, "js_asset_id": 3, "analyzed_at": NOW, "extraction_bytes": 432,
            **{key + "_count": 1 for key in (
                "endpoint_paths", "api_urls", "graphql_operations", "postmessage_usage",
                "dangerous_dom_sinks", "tokens_or_secret_like_strings")},
            "extraction": {"secret": "PRIVATE_VALUE"},
        }])
        asset = self.repo.list_js_assets(5, 12).items[0]
        delta_asset = self.repo.get_js_asset(5, 3)
        analysis = self.repo.get_js_analysis(5, 3)
        self.assertEqual(asset.latest_sha256, "abc")
        self.assertEqual(delta_asset, asset)
        self.assertIn((3, 5), [params for sql, params in self.connection.calls
                              if "FROM js_assets a JOIN live_hosts" in sql])
        self.assertEqual(analysis.signal_counts["endpoint_paths"], 1)
        self.assertNotIn("PRIVATE_VALUE", repr(analysis))
        sql = " ".join(query for query, _ in self.connection.calls)
        self.assertNotIn("SELECT j.extraction", sql)

    def test_surface_snapshot_and_bounded_events(self):
        def result(sql, _params):
            if "FROM api_surfaces" in sql:
                return [{"id": 1, "domain_id": 5, "live_host_id": 12,
                         "surface_type": "graphql", "location": "/graphql",
                         "status_code": 200, "operations_count": 2, "last_seen": NOW}]
            if "FROM scan_snapshots" in sql:
                return [{"id": 2, "domain_id": 5, "scan_started_at": NOW - timedelta(hours=1),
                         "scan_finished_at": NOW, "first_run": False}]
            return [{"id": 3, "domain_id": 5, "event_type": "endpoint_new",
                     "entity_type": "endpoint", "entity_id": 7, "location": "/api",
                     "severity": "low", "last_seen": NOW}]
        self.connection.result = result
        surface = self.repo.list_api_surfaces(5, "graphql").items[0]
        snapshot = self.repo.list_scan_snapshots(5).items[0]
        event = self.repo.list_asset_events(5, NOW - timedelta(days=1), NOW + timedelta(days=1)).items[0]
        self.assertEqual(surface.provenance.qualification, "recon_hint")
        self.assertEqual(snapshot.provenance.qualification, "completed_scan")
        self.assertEqual(event.provenance.source_table, "asset_events")
        with self.assertRaises(ValueError):
            self.repo.list_asset_events(5, NOW - timedelta(days=32), NOW)

    def test_read_only_transaction_parameterized_timeout_and_no_writes(self):
        self.repo.resolve_target(5)
        calls = self.connection.calls
        self.assertEqual(calls[0][0], "BEGIN READ ONLY")
        self.assertEqual(calls[1][1], ("3000",))
        self.assertEqual(calls[-1][0], "ROLLBACK")
        self.assertTrue(all(sql.lstrip().startswith(("SELECT", "BEGIN READ ONLY", "ROLLBACK"))
                            for sql, _ in calls))

    def test_all_read_shapes_are_bounded_and_parameterized(self):
        self.repo.resolve_target(5)
        self.repo.resolve_host(5, "https://app.example.com")
        self.repo.list_hosts(5)
        self.repo.list_endpoints(5, 12)
        self.repo.list_parameters(5, 7)
        self.repo.list_js_assets(5, 12)
        self.repo.get_js_asset(5, 3)
        self.repo.get_js_analysis(5, 3)
        self.repo.list_endpoint_js_references(5, 7)
        self.repo.list_api_surfaces(5, "graphql")
        self.repo.list_scan_snapshots(5)
        self.repo.list_asset_events(5, NOW - timedelta(days=1), NOW)
        for sql, params in self.connection.calls:
            if not sql.lstrip().startswith("SELECT") or "set_config" in sql:
                continue
            with self.subTest(sql=sql.strip().splitlines()[0]):
                self.assertIn("LIMIT", sql.upper())
                self.assertIn("%s", sql)
                self.assertNotIn("SELECT *", sql.upper())
                self.assertNotIn("OFFSET", sql.upper())
                self.assertTrue(params)

    def test_database_error_never_exposes_secret(self):
        def fail(_sql, _params):
            raise RuntimeError("password=PRIVATE_VALUE")

        self.connection.result = fail
        with self.assertRaises(ReconQueryError) as captured:
            self.repo.resolve_target(5)
        self.assertNotIn("PRIVATE_VALUE", str(captured.exception))
        self.assertTrue(self.connection.closed)
        self.assertEqual(self.connection.calls[-1][0], "ROLLBACK")

    def test_probe_requires_read_only_transaction_and_closes_connection(self):
        self.connection.result = lambda _sql, _params: [{"read_only": "on"}]
        self.assertTrue(self.repo.probe())
        self.assertEqual(self.connection.calls[0][0], "BEGIN READ ONLY")
        self.assertEqual(self.connection.calls[-1][0], "ROLLBACK")
        self.assertIn("transaction_read_only", self.connection.calls[-2][0])
        self.assertTrue(self.connection.closed)

    def test_probe_rejects_non_read_only_or_empty_result(self):
        self.connection.result = lambda _sql, _params: [{"read_only": "off"}]
        self.assertFalse(self.repo.probe())
        self.connection.result = lambda _sql, _params: []
        self.assertFalse(self.repo.probe())

    def test_config_reference_and_failure_do_not_expose_dsn(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[recon]\ndsn_env = "MY_RECON_DSN"\nmax_page_size = 9\n')
            config = load_config(path, environ={"HOME": directory})
            self.assertEqual(config.recon.max_page_size, 9)
            self.assertNotIn("password", repr(config))
            with self.assertRaises(ConfigError) as captured:
                PostgresReconRepository.from_config(config, environ={})
            self.assertNotIn("MY_RECON_DSN", str(captured.exception))
            path.write_text('[recon]\nmax_page_size = 101\n')
            with self.assertRaises(ConfigError):
                load_config(path, environ={"HOME": directory})
            path.write_text('[recon]\nstatement_timeout_ms = 6000\n')
            with self.assertRaises(ConfigError):
                load_config(path, environ={"HOME": directory})
            path.write_text('[recon]\ndsn_env = "not-an-env-name"\n')
            with self.assertRaises(ConfigError):
                load_config(path, environ={"HOME": directory})
