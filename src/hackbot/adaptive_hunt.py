"""Bounded campaign pacing from local resource and traffic observations."""

from __future__ import annotations

from dataclasses import dataclass

from .resources import ResourceSnapshot


TARGET_THROTTLE_COOLDOWN_SECONDS = 120


@dataclass(frozen=True, slots=True)
class AdaptiveSignals:
    resource: ResourceSnapshot
    browsers_active: int = 0
    browser_limit: int = 1
    burp_listeners_active: int = 0
    burp_listener_capacity: int = 1
    burp_dropped_events: int = 0
    median_latency_ms: int | None = None
    latest_429_age_seconds: int | None = None
    duplicate_candidates: int = 0
    candidates_considered: int = 0


@dataclass(frozen=True, slots=True)
class AdaptiveDecision:
    requests: int
    browser_actions: int
    candidates: int
    pause_reason: str | None
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"requests": self.requests, "browser_actions": self.browser_actions,
                "candidates": self.candidates, "pause_reason": self.pause_reason,
                "reasons": list(self.reasons)}


def choose_cycle_budget(signals: AdaptiveSignals, *, requests: int,
                        browser_actions: int, candidates: int) -> AdaptiveDecision:
    if any(type(value) is not int or value < 0 for value in
           (requests, browser_actions, candidates)):
        raise ValueError("Invalid adaptive campaign budget")
    if (signals.latest_429_age_seconds is not None and
            0 <= signals.latest_429_age_seconds < TARGET_THROTTLE_COOLDOWN_SECONDS):
        return AdaptiveDecision(0, 0, 0, "TARGET_THROTTLED", ("RECENT_TARGET_429",))

    reasons: list[str] = []
    factor = 1.0
    resource = signals.resource
    if (resource.state == "DEGRADED" or
            resource.swap_used_percent is not None and
            resource.swap_used_percent >= 90 or
            resource.memory_available_bytes is not None and
            resource.memory_available_bytes < 1_073_741_824 or
            resource.load_per_cpu is not None and resource.load_per_cpu >= 0.85):
        factor = min(factor, 0.5)
        reasons.append("HOST_PRESSURE")
    if (signals.browser_limit > 0 and signals.browsers_active > 0 and
            signals.browsers_active >= signals.browser_limit - 1):
        factor = min(factor, 0.5)
        reasons.append("BROWSER_CAPACITY_NEAR_LIMIT")
    if (signals.burp_listener_capacity > 0 and
            signals.burp_listeners_active * 5 >= signals.burp_listener_capacity * 4):
        factor = min(factor, 0.5)
        reasons.append("BURP_CAPACITY_NEAR_LIMIT")
    if signals.burp_dropped_events > 0:
        factor = min(factor, 0.5)
        reasons.append("BURP_CAPTURE_DROPS_OBSERVED")
    if signals.median_latency_ms is not None:
        if signals.median_latency_ms >= 10_000:
            factor = min(factor, 0.25)
            reasons.append("HIGH_TARGET_LATENCY")
        elif signals.median_latency_ms >= 5_000:
            factor = min(factor, 0.5)
            reasons.append("ELEVATED_TARGET_LATENCY")
    if (signals.candidates_considered >= 4 and
            signals.duplicate_candidates * 4 >= signals.candidates_considered * 3):
        factor = min(factor, 0.5)
        reasons.append("HIGH_DUPLICATE_RATE")

    def scaled(value: int) -> int:
        return max(1, int(value * factor)) if value else 0

    return AdaptiveDecision(scaled(requests), scaled(browser_actions),
                            scaled(candidates), None, tuple(reasons))
