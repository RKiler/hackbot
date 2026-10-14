"""Helpers for constructing historical SQLite schemas in migration tests."""

import sqlite3


def drop_phase28_schema(connection: sqlite3.Connection) -> None:
    """Remove only tables introduced after schema version 34."""
    for table in (
        "planner_candidate_assessments", "planner_events",
        "planner_task_dependencies", "planner_budget_reservations",
        "planner_tasks", "planner_candidate_relationships",
        "planner_candidates", "planner_branch_memory", "planner_runs",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
