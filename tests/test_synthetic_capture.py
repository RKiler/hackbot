"""Local capture fixture tests; only the loopback synthetic SaaS is reachable."""

from dataclasses import replace
from contextlib import closing
import http.client
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from hackbot.browser import IdentityObservation
from hackbot.config import BurpSettings, TargetSettings, load_config
from hackbot.domain import TrafficSource
from hackbot.service import BugHunterRuntime

from tests.synthetic_capture import SyntheticCaptureProxy
from tests.synthetic_saas import APP_JS, SyntheticSaaS


class _Driver:
    name = "FIXTURE"

    def __init__(self) -> None:
        self.running: set[str] = set()

    def start(self, session_id, _profile, *, display, proxy) -> None:
        self.running.add(session_id)

    def stop(self, session_id) -> None:
        self.running.discard(session_id)

    def is_running(self, session_id) -> bool:
        return session_id in self.running

    def observe_identity(self, _session_id, _rule) -> IdentityObservation:
        return IdentityObservation()


class SyntheticCaptureTests(unittest.TestCase):
    def test_proxy_records_through_burp_adapter_and_denies_other_origins(self) -> None:
        with TemporaryDirectory() as directory, SyntheticSaaS() as fixture, \
             SyntheticCaptureProxy(fixture.base_url) as proxy:
            root = Path(directory)
            base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                        "XDG_STATE_HOME": str(root)})
            bridge_port = 38777 if proxy.port != 38777 else 38778
            config = replace(base, targets=TargetSettings(root / "targets"),
                             burp=BurpSettings(True, root / "burp",
                                               listener_start=proxy.port,
                                               listener_end=proxy.port,
                                               bridge_port=bridge_port))
            runtime = BugHunterRuntime(config, driver=_Driver())
            package = runtime.target_operator.create({
                "name": "Synthetic SaaS", "id": "synthetic-local",
                "primary_domain": "127.0.0.1", "confirmed": True,
                "scope": {"include": ["127.0.0.1"], "exclude": [],
                          "schemes": ["http"], "ports": [urlsplit(fixture.base_url).port]},
                "source": {"kind": "RESEARCHER", "reference": "local fixture",
                           "operator": "test-operator"},
                "rules": {"automated_testing_allowed": True,
                          "account_creation_allowed": False,
                          "forbidden_actions": []},
                "autonomy": {"passive": "ALLOW", "safe_read": "ALLOW",
                             "bounded_active": "DENY", "state_changing": "DENY",
                             "destructive": "DENY"},
                "rate": {"requests_per_second": 1, "requests_per_minute": 30,
                         "max_concurrency": 1, "burst": 1},
            })
            runtime.registry.register_target(package)
            proxy.attach(package, runtime)
            session, binding = runtime.burp.provision_session(package)
            with patch.object(runtime.burp, "ready", return_value=True):
                runtime.burp.start_browser(session.id, package=package)
            self.assertEqual(binding.proxy_port, proxy.port)
            with closing(http.client.HTTPConnection("127.0.0.1", proxy.port,
                                                    timeout=5)) as connection:
                connection.request("GET", fixture.base_url + "/assets/app.js",
                                   headers={"Host": proxy.fixture_netloc})
                response = connection.getresponse()
                self.assertEqual((response.status, response.read()), (200, APP_JS.encode()))
            with closing(http.client.HTTPConnection("127.0.0.1", proxy.port,
                                                    timeout=5)) as connection:
                connection.set_tunnel("127.0.0.1", proxy.fixture_port)
                connection.request("GET", "/assets/app.js",
                                   headers={"Host": proxy.fixture_netloc})
                response = connection.getresponse()
                self.assertEqual((response.status, response.read()), (200, APP_JS.encode()))
            captured = runtime.traffic.list_exchanges_for_session(
                package.target.id, session.id, limit=10).items
            self.assertEqual(len(captured), 2)
            self.assertEqual((captured[0].source, captured[0].capture_provider),
                             (TrafficSource.BURP, "MONTOYA_V1"))
            previous = len(fixture.requests)
            with closing(http.client.HTTPConnection("127.0.0.1", proxy.port,
                                                    timeout=5)) as connection:
                connection.request("GET", "http://127.0.0.1:1/private",
                                   headers={"Host": "127.0.0.1:1"})
                self.assertEqual(connection.getresponse().status, 403)
            self.assertEqual(len(fixture.requests), previous)
            self.assertEqual(len(runtime.traffic.list_exchanges_for_session(
                package.target.id, session.id, limit=10).items), 2)
            runtime.browser.stop(session.id)
            runtime.burp.release(session.id)


if __name__ == "__main__":
    unittest.main()
