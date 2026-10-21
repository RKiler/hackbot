"""Single-process, persisted-cadence scheduler for explicitly enabled targets."""

from __future__ import annotations

from threading import Event, Lock, Thread
from typing import TYPE_CHECKING

from .delta_coordinator import DeltaCoordinator

if TYPE_CHECKING:
    from .service import BugHunterRuntime


class DeltaScheduler:
    def __init__(self, runtime: BugHunterRuntime, coordinator: DeltaCoordinator) -> None:
        self.runtime = runtime
        self.coordinator = coordinator
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self.coordinator.deltas.reconcile_interrupted()
            self._stop.clear()
            self._thread = Thread(target=self._work, daemon=True,
                                  name="bughunter-delta-scheduler")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=65)

    def tick(self) -> tuple[dict[str, object], ...]:
        results = []
        for target_id in self.coordinator.deltas.due_targets(limit=8):
            state = self.coordinator.deltas.get(target_id)
            if state is None:
                continue
            try:
                package = self.runtime.package(str(state["package_id"]))
                if package.target.id != target_id:
                    raise ValueError("Target Package identity changed")
                result = self.coordinator.check(package, trigger="SCHEDULED")
                results.append({"target_id": target_id, **result})
            except (LookupError, ValueError) as exc:
                current = self.coordinator.deltas.get(target_id)
                if current is not None and current["status"] == "RUNNING":
                    results.append({"target_id": target_id, "status": "WATCH_IN_PROGRESS"})
                    continue
                self.coordinator.deltas.defer_target(target_id, "PACKAGE_UNAVAILABLE")
                results.append({"target_id": target_id, "error_code": "PACKAGE_UNAVAILABLE"})
            except Exception:
                current = self.coordinator.deltas.get(target_id)
                if current is not None and current["status"] == "RUNNING":
                    results.append({"target_id": target_id, "status": "WATCH_IN_PROGRESS"})
                    continue
                self.coordinator.deltas.defer_target(target_id, "SCHEDULER_FAILED")
                results.append({"target_id": target_id, "error_code": "SCHEDULER_FAILED"})
        return tuple(results)

    def _work(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                self.runtime.logger.error("delta_scheduler_tick_failed")
            try:
                self.runtime.retry_resource_paused_hunts()
            except Exception:
                self.runtime.logger.error("hunt_resource_retry_failed")
            self._stop.wait(60)
