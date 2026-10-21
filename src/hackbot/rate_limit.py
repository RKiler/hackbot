"""Deterministic local rate-accounting primitives; no requests are sent."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import threading
import time
import uuid
from typing import Callable

from .target_policy import RatePolicy


@dataclass(frozen=True, slots=True)
class ExperimentBudget:
    max_requests: int = 100
    max_mutations: int = 10
    max_creations: int = 5
    max_retries: int = 2

    def __post_init__(self) -> None:
        for value in (self.max_requests, self.max_mutations, self.max_creations, self.max_retries):
            if type(value) is not int or not 0 <= value <= 10000:
                raise ValueError("Invalid experiment budget")


@dataclass(frozen=True, slots=True)
class RateOutcome:
    allowed: bool
    reason_code: str
    reservation_id: str | None = None


@dataclass(slots=True)
class _Counters:
    requests: int = 0
    mutations: int = 0
    creations: int = 0
    retries: int = 0


@dataclass(slots=True)
class _TargetState:
    tokens: float
    updated_at: float
    minute: deque[float] = field(default_factory=deque)
    active: set[str] = field(default_factory=set)
    experiments: dict[str, _Counters] = field(default_factory=dict)


class RateLimiter:
    """One trusted process owns reservations; callers release after future execution."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 max_targets: int = 256, max_experiments_per_target: int = 256) -> None:
        self._clock = clock
        self._max_targets = max_targets
        self._max_experiments = max_experiments_per_target
        self._states: dict[str, _TargetState] = {}
        self._reservation_targets: dict[str, str] = {}
        self._lock = threading.Lock()

    def _state(self, target_id: str, policy: RatePolicy, now: float) -> _TargetState | None:
        state = self._states.get(target_id)
        if state is None:
            if len(self._states) >= self._max_targets:
                for key, existing in tuple(self._states.items()):
                    if not existing.active and now - existing.updated_at > 900:
                        del self._states[key]
                if len(self._states) >= self._max_targets:
                    return None
            state = _TargetState(float(policy.burst), now)
            self._states[target_id] = state
        elapsed = max(0.0, now - state.updated_at)
        state.tokens = min(float(policy.burst), state.tokens + elapsed * policy.requests_per_second)
        state.updated_at = now
        while state.minute and now - state.minute[0] >= 60:
            state.minute.popleft()
        return state

    @staticmethod
    def _check(state: _TargetState, policy: RatePolicy, counters: _Counters | None,
               budget: ExperimentBudget, *, mutation: bool, creation: bool, retry: bool) -> str:
        if len(state.active) >= policy.max_concurrency:
            return "CONCURRENCY_LIMIT"
        if state.tokens < 1:
            return "RATE_PER_SECOND"
        if policy.requests_per_minute is not None and len(state.minute) >= policy.requests_per_minute:
            return "RATE_PER_MINUTE"
        if counters is not None:
            if counters.requests >= budget.max_requests:
                return "EXPERIMENT_REQUEST_BUDGET"
            if mutation and counters.mutations >= budget.max_mutations:
                return "EXPERIMENT_MUTATION_BUDGET"
            if creation and counters.creations >= budget.max_creations:
                return "EXPERIMENT_CREATION_BUDGET"
            if retry and counters.retries >= budget.max_retries:
                return "EXPERIMENT_RETRY_BUDGET"
        return "WITHIN_RATE_POLICY"

    def check(self, target_id: str, policy: RatePolicy, *, experiment_id: str | None = None,
              budget: ExperimentBudget = ExperimentBudget(), mutation: bool = False,
              creation: bool = False, retry: bool = False) -> RateOutcome:
        with self._lock:
            state = self._state(target_id, policy, self._clock())
            if state is None:
                return RateOutcome(False, "RATE_STATE_CAPACITY")
            counters = state.experiments.get(experiment_id) if experiment_id else None
            if experiment_id and counters is None and len(state.experiments) >= self._max_experiments:
                return RateOutcome(False, "EXPERIMENT_STATE_CAPACITY")
            reason = self._check(state, policy, counters or (_Counters() if experiment_id else None),
                                 budget, mutation=mutation, creation=creation, retry=retry)
            return RateOutcome(reason == "WITHIN_RATE_POLICY", reason)

    def retry_after_seconds(self, target_id: str, policy: RatePolicy, *,
                            experiment_id: str | None = None,
                            budget: ExperimentBudget = ExperimentBudget()) -> float | None:
        """Return the next rate-policy slot, or None for a non-temporary denial.

        This is advisory only. Callers must still reserve immediately before work.
        """
        with self._lock:
            now = self._clock()
            state = self._state(target_id, policy, now)
            if state is None:
                return None
            if len(state.active) >= policy.max_concurrency:
                return 0.1
            counters = state.experiments.get(experiment_id) if experiment_id else None
            if (experiment_id and counters is None
                    and len(state.experiments) >= self._max_experiments):
                return None
            if counters is not None and counters.requests >= budget.max_requests:
                return None
            per_second = max(0.0, (1.0 - state.tokens) / policy.requests_per_second)
            per_minute = 0.0
            if (policy.requests_per_minute is not None
                    and len(state.minute) >= policy.requests_per_minute):
                per_minute = max(0.0, state.minute[0] + 60.0 - now)
            return max(per_second, per_minute)

    def reserve(self, target_id: str, policy: RatePolicy, *, experiment_id: str | None = None,
                budget: ExperimentBudget = ExperimentBudget(), mutation: bool = False,
                creation: bool = False, retry: bool = False) -> RateOutcome:
        with self._lock:
            now = self._clock()
            state = self._state(target_id, policy, now)
            if state is None:
                return RateOutcome(False, "RATE_STATE_CAPACITY")
            counters = state.experiments.get(experiment_id) if experiment_id else None
            if experiment_id and counters is None:
                if len(state.experiments) >= self._max_experiments:
                    return RateOutcome(False, "EXPERIMENT_STATE_CAPACITY")
                counters = _Counters()
            reason = self._check(state, policy, counters, budget,
                                 mutation=mutation, creation=creation, retry=retry)
            if reason != "WITHIN_RATE_POLICY":
                return RateOutcome(False, reason)
            reservation_id = "RATE-" + uuid.uuid4().hex
            state.tokens -= 1
            state.minute.append(now)
            state.active.add(reservation_id)
            self._reservation_targets[reservation_id] = target_id
            if experiment_id:
                assert counters is not None
                state.experiments[experiment_id] = counters
                counters.requests += 1
                counters.mutations += int(mutation)
                counters.creations += int(creation)
                counters.retries += int(retry)
            return RateOutcome(True, reason, reservation_id)

    def release(self, reservation_id: str) -> bool:
        with self._lock:
            target_id = self._reservation_targets.pop(reservation_id, None)
            if target_id is None:
                return False
            self._states[target_id].active.discard(reservation_id)
            return True
