from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.adaptive_hunt import (AdaptiveSignals,
                                   TARGET_THROTTLE_COOLDOWN_SECONDS,
                                   choose_cycle_budget)
from hackbot.resources import ResourceSnapshot, _swap_used_percent


def snapshot(*, state: str = "OK", memory: int = 2_147_483_648,
             swap: int = 0, load: float = 0.2) -> ResourceSnapshot:
    return ResourceSnapshot(100, 50, 50, memory, state, (),
                            load_per_cpu=load, swap_used_percent=swap)


class AdaptiveHuntTests(unittest.TestCase):
    def test_healthy_signals_keep_bounded_cycle_budget(self) -> None:
        result = choose_cycle_budget(AdaptiveSignals(snapshot(),
                                                      browser_limit=4,
                                                      burp_listener_capacity=4),
                                     requests=20, browser_actions=12, candidates=8)
        self.assertEqual((result.requests, result.browser_actions,
                          result.candidates, result.pause_reason),
                         (20, 12, 8, None))
        self.assertEqual(result.reasons, ())

    def test_pressure_reduces_work_without_raising_rate_or_budget(self) -> None:
        result = choose_cycle_budget(AdaptiveSignals(
            snapshot(swap=95, memory=800_000_000), browsers_active=3,
            browser_limit=4, burp_listeners_active=4,
            burp_listener_capacity=4, burp_dropped_events=2,
            duplicate_candidates=8, candidates_considered=10),
            requests=20, browser_actions=12, candidates=8)
        self.assertEqual((result.requests, result.browser_actions,
                          result.candidates), (10, 6, 4))
        self.assertIn("HOST_PRESSURE", result.reasons)
        self.assertIn("HIGH_DUPLICATE_RATE", result.reasons)

    def test_high_latency_uses_smallest_tranche(self) -> None:
        result = choose_cycle_budget(AdaptiveSignals(
            snapshot(), median_latency_ms=10_000),
            requests=20, browser_actions=12, candidates=8)
        self.assertEqual((result.requests, result.browser_actions,
                          result.candidates), (5, 3, 2))

    def test_recent_429_pauses_and_cooldown_expires(self) -> None:
        recent = choose_cycle_budget(AdaptiveSignals(
            snapshot(), latest_429_age_seconds=119),
            requests=20, browser_actions=12, candidates=8)
        self.assertEqual(recent.pause_reason, "TARGET_THROTTLED")
        self.assertEqual(recent.requests, 0)
        old = choose_cycle_budget(AdaptiveSignals(
            snapshot(), latest_429_age_seconds=TARGET_THROTTLE_COOLDOWN_SECONDS),
            requests=20, browser_actions=12, candidates=8)
        self.assertIsNone(old.pause_reason)
        self.assertEqual(old.requests, 20)

    def test_swap_metric_is_bounded_and_handles_no_swap(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "meminfo"
            path.write_text("SwapTotal: 100 kB\nSwapFree: 10 kB\n", encoding="ascii")
            self.assertEqual(_swap_used_percent(path), 90)
            path.write_text("SwapTotal: 0 kB\nSwapFree: 0 kB\n", encoding="ascii")
            self.assertEqual(_swap_used_percent(path), 0)
            path.write_text("SwapTotal: 100 kB\nSwapFree: 110 kB\n", encoding="ascii")
            self.assertIsNone(_swap_used_percent(path))
