"""Helpers for constructing historical SQLite schemas in migration tests."""

import sqlite3


def drop_phase29_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct version 36 before exercising an older migration path."""
    for table in ("report_attempts", "report_drafts", "notification_attempts",
                  "notification_deliveries", "notification_events",
                  "finding_submission_metadata"):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
    for column in ("workflow_version", "actor_alias", "details_json"):
        connection.execute(f"ALTER TABLE finding_status_events DROP COLUMN {column}")


def drop_phase28_schema(connection: sqlite3.Connection) -> None:
    """Remove only tables introduced after schema version 34."""
    drop_phase29_schema(connection)
    for table in (
        "planner_candidate_assessments", "planner_events",
        "planner_task_dependencies", "planner_budget_reservations",
        "planner_tasks", "planner_candidate_relationships",
        "planner_candidates", "planner_branch_memory", "planner_runs",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
