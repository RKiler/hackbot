"""Local-only checks for the Playwright thread-affinity boundary."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import os
import unittest
from unittest.mock import patch

from hackbot.browser import BrowserError, BrowserProxyConfig
from hackbot.browser_actor import PlaywrightBrowserActor


CHROMIUM = os.environ.get("HACKBOT_TEST_CHROMIUM")


class PlaywrightBrowserActorConcurrencyTests(unittest.TestCase):
    def test_capture_can_check_running_session_while_browser_worker_is_busy(self):
        class FakeDriver:
            def __init__(self, _executable):
                self.sessions = set()

            def start(self, session_id, _profile, *, display, proxy):
                self.sessions.add(session_id)

            def stop(self, session_id):
                self.sessions.remove(session_id)

            def active_session_count(self):
                return len(self.sessions)

        started, release = Event(), Event()
        with patch("hackbot.browser_actor.PlaywrightBrowserDriver", FakeDriver):
            actor = PlaywrightBrowserActor()
            actor.start("local", Path("/tmp/local-fixture"), display=None,
                        proxy=BrowserProxyConfig())
            try:
                def occupy_worker():
                    started.set()
                    release.wait(3)

                work = actor._worker.submit(occupy_worker)
                self.assertTrue(started.wait(1))
                with ThreadPoolExecutor(max_workers=1) as capture:
                    self.assertTrue(capture.submit(actor.is_running, "local").result(timeout=0.5))
                release.set()
                work.result(timeout=1)
            finally:
                release.set()
                actor.stop("local")
                self.assertFalse(actor.is_running("local"))
                actor.close()


@unittest.skipUnless(CHROMIUM and Path(CHROMIUM).is_file(),
                     "Explicit local Chromium test binary is unavailable")
class PlaywrightBrowserActorTests(unittest.TestCase):
    def test_browser_started_on_worker_is_observable_from_another_thread(self):
        with TemporaryDirectory() as directory:
            actor = PlaywrightBrowserActor(Path(CHROMIUM))
            with ThreadPoolExecutor(max_workers=1) as caller:
                caller.submit(actor.start, "local", Path(directory) / "profile",
                              display=None, proxy=BrowserProxyConfig()).result()
                try:
                    self.assertTrue(actor.is_running("local"))
                    observed = actor.observe_current_page("local")
                    self.assertIsNotNone(observed)
                    self.assertEqual(observed["url"], "about:blank")
                    self.assertEqual(caller.submit(actor.active_session_count).result(), 1)
                    self.assertTrue(actor._worker.submit(actor.is_running, "local").result(timeout=5))
                    with self.assertRaises(BrowserError):
                        actor.close()
                finally:
                    actor.stop("local")
                    actor.close()
