"""Deterministic fixture advisor for testing model-lane plumbing, not model quality."""

from __future__ import annotations

from dataclasses import dataclass

from .benchmark_advice import AdvicePacket, ModelAdviceResult


@dataclass(frozen=True, slots=True)
class FixtureOrderingProvider:
    reverse: bool = False
    name: str = "fixture"

    def advise(self, packet: AdvicePacket) -> ModelAdviceResult:
        ordered = tuple(item["candidate_id"] for item in packet.candidates)
        return ModelAdviceResult(ordered[::-1] if self.reverse else ordered)
