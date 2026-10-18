"""Helpers for constructing historical SQLite schemas in migration tests."""

import sqlite3


def drop_phase32_schema(connection: sqlite3.Connection) -> None:
    """Remove continuous-delta tables before a schema-47 fixture."""
    connection.execute("DROP TRIGGER IF EXISTS delta_candidate_evidence_no_retirement")
    for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND "
        "(name LIKE 'retired_dom_link_delta_%' OR "
        "name LIKE 'retired_dom_link_continuous_%')"
    ).fetchall():
        connection.execute(f'DROP TRIGGER "{name}"')
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='dom_retirement_guard_sources'"
    ).fetchone():
        connection.execute("DELETE FROM dom_retirement_guard_sources WHERE "
                           "source_table LIKE 'delta_%' OR "
                           "source_table LIKE 'continuous_%'")
    for table in (
        "delta_asset_refresh", "delta_campaign_focus_specialists",
        "delta_campaign_focus_hypotheses", "delta_campaign_focus_deltas",
        "delta_campaign_focus", "delta_cooldowns", "delta_candidate_events",
        "delta_candidate_hypotheses", "delta_candidate_tags",
        "delta_candidate_hints", "delta_candidates", "delta_observations",
        "delta_watch_runs", "continuous_target_events",
        "continuous_target_specialists", "continuous_targets",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")


def drop_phase31_schema(connection: sqlite3.Connection) -> None:
    """Remove campaign tables before constructing a historical schema."""
    drop_phase32_schema(connection)
    for table in (
        "campaign_objects", "campaign_suppressions", "campaign_events",
        "campaign_task_claims", "campaign_work", "campaign_cycles", "campaigns",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")


def drop_dom_retirement_guards(connection: sqlite3.Connection) -> None:
    """Reconstruct schema 45 before a DOM guard upgrade fixture."""
    drop_phase31_schema(connection)
    for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND name LIKE 'retired_dom_link_%'"
    ).fetchall():
        quoted = '"' + name.replace('"', '""') + '"'
        connection.execute(f"DROP TRIGGER {quoted}")
    connection.execute("DROP TABLE IF EXISTS dom_retirement_guard_sources")


def drop_research_retirement_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct schema 44 before a ResearchBrief-retirement upgrade fixture."""
    drop_dom_retirement_guards(connection)
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND "
        "(name LIKE 'research_ref_%' OR name LIKE 'research_retirement_%' "
        "OR name='research_payload_no_rewrite')"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {row[0]}")
    connection.execute("DROP TABLE IF EXISTS planner_candidate_research_refs")
    connection.execute("DROP TABLE IF EXISTS planner_event_research_refs")
    connection.execute("DROP TABLE IF EXISTS research_brief_payload_retirements")
    connection.execute("DROP INDEX IF EXISTS research_briefs_expiry_lookup")
    connection.execute("DROP INDEX IF EXISTS research_requests_brief_status")
    connection.execute("DROP INDEX IF EXISTS planner_tasks_research_result")


def drop_evidence_json_index_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct schema 43 before an Evidence-index upgrade fixture."""
    drop_research_retirement_schema(connection)
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND name LIKE 'evidence_json_ref_%'"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {row[0]}")
    connection.execute("DROP TABLE IF EXISTS evidence_json_reference_counts")
    connection.execute("DROP TABLE IF EXISTS evidence_json_reference_sources")


def drop_traffic_json_index_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct schema 42 before a JSON-reference-index upgrade fixture."""
    drop_evidence_json_index_schema(connection)
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND name LIKE 'traffic_json_ref_%'"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {row[0]}")
    connection.execute("DROP TABLE IF EXISTS traffic_json_reference_counts")
    connection.execute("DROP TABLE IF EXISTS traffic_json_reference_sources")


def drop_traffic_retirement_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct schema 41 before a traffic-retirement upgrade fixture."""
    drop_traffic_json_index_schema(connection)
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND (name LIKE 'retired_traffic_link_%' "
        "OR name LIKE 'traffic_payload_retirement_%')"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {row[0]}")
    connection.execute("DROP TABLE IF EXISTS traffic_payload_retirements")


def drop_phase30_schema(connection: sqlite3.Connection) -> None:
    """Remove Phase 30 holds before an older upgrade fixture."""
    drop_traffic_retirement_schema(connection)
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND (name LIKE 'retired_link_%' OR name LIKE 'retired_json_%')"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {row[0]}")
    for trigger in (
        "evidence_payload_retirement_no_update", "evidence_payload_retirement_no_delete",
        "evidence_payload_retirement_guard", "finding_evidence_no_retired_payload",
        "finding_validation_hold_no_retired_payload",
        "evidence_policy_no_retain_retired_payload",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP TABLE IF EXISTS evidence_payload_retirements")
    for trigger in (
        "finding_validation_hold_no_update", "finding_validation_hold_no_delete",
        "finding_validation_hold_policy", "finding_validation_hold_pin",
        "finding_validation_hold_primary", "finding_validation_hold_location",
        "finding_validation_hold_duplicate", "finding_validation_hold_late_check",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP VIEW IF EXISTS validation_evidence_refs")
    connection.execute("DROP TABLE IF EXISTS finding_validation_evidence_holds")
    connection.execute("DROP TRIGGER IF EXISTS finding_evidence_pin")
    connection.execute("DROP TRIGGER IF EXISTS evidence_finding_hold")


def drop_phase29_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct version 36 before exercising an older migration path."""
    drop_phase30_schema(connection)
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
