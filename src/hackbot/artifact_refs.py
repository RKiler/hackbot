"""Digest columns that point into the BugHunter evidence artifact store."""

from __future__ import annotations

import sqlite3

EVIDENCE_ARTIFACT_REFERENCES: tuple[tuple[str, str], ...] = (
    ("evidence", "artifact_hash"),
    ("traffic_requests", "artifact_hash"),
    ("traffic_responses", "artifact_hash"),
    ("plan_step_results", "artifact_hash"),
    ("dom_js_artifacts", "artifact_sha256"),
    ("dom_source_maps", "map_sha256"),
    ("exposure_candidate_sources", "artifact_sha256"),
)


def verify_artifact_reference_schema(db: sqlite3.Connection) -> None:
    """Fail closed if a migration adds a digest column outside the GC inventory."""
    declared = set(EVIDENCE_ARTIFACT_REFERENCES)
    found: set[tuple[str, str]] = set()
    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name NOT LIKE 'sqlite_%'").fetchall()
    for row in tables:
        table = row[0]
        quoted = '"' + table.replace('"', '""') + '"'
        for column in db.execute(f"PRAGMA table_xinfo({quoted})"):
            name = column[1]
            if (name.endswith("artifact_hash") or name.endswith("artifact_sha256") or
                    name.endswith("map_sha256")):
                found.add((table, name))
    if found - declared:
        raise ValueError("Artifact reference schema is not fully declared")
