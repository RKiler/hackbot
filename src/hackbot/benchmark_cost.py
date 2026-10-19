"""Operator-priced benchmark estimates; unknown prices remain unknown."""

from __future__ import annotations

from dataclasses import dataclass

from .benchmark_eval import CaseEvaluation
from .benchmark_models import BenchmarkRunConfig


@dataclass(frozen=True, slots=True)
class BenchmarkCost:
    vps_usd: float | None
    model_usd: float | None
    known_total_usd: float
    total_usd: float | None
    cost_per_detection_usd: float | None
    unpriced_model_calls: int
    is_estimate: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "vps_usd": self.vps_usd, "model_usd": self.model_usd,
            "known_total_usd": self.known_total_usd,
            "total_usd": self.total_usd,
            "cost_per_detection_usd": self.cost_per_detection_usd,
            "unpriced_model_calls": self.unpriced_model_calls,
            "is_estimate": self.is_estimate,
        }


def estimate_cost(cases: tuple[CaseEvaluation, ...],
                  config: BenchmarkRunConfig) -> BenchmarkCost:
    """No hardcoded provider prices or invented zero-cost assumptions."""
    vps = (None if config.vps_usd_per_hour is None else
           sum(item.duration_seconds for item in cases) *
           config.vps_usd_per_hour / 3600)
    prices = {(item.role, item.lane, item.provider, item.model): item
              for item in config.models}
    model = 0.0
    unpriced = 0
    for case in cases:
        for call in case.model_calls:
            selected = prices.get((call.role, call.lane, call.provider, call.model))
            if (selected is None or selected.input_usd_per_million is None or
                    selected.output_usd_per_million is None):
                unpriced += 1
                continue
            model += (call.input_tokens * selected.input_usd_per_million +
                      call.output_tokens * selected.output_usd_per_million) / 1_000_000
    model_total = None if unpriced else model
    total = vps + model if vps is not None and not unpriced else None
    detected = sum(item.detected_vulnerabilities for item in cases)
    return BenchmarkCost(
        vps_usd=round(vps, 6) if vps is not None else None,
        model_usd=round(model_total, 6) if model_total is not None else None,
        known_total_usd=round((vps or 0) + model, 6),
        total_usd=round(total, 6) if total is not None else None,
        cost_per_detection_usd=round(total / detected, 6)
        if total is not None and detected else None,
        unpriced_model_calls=unpriced,
    )
