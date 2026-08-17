"""Reads the queue view's rows out of SQLite.

The HTTP layer only ever reads from SQLite, never from a port directly - the
inventory-and-scan and telemetry-and-detection loops (later tickets) are
what write into it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from aidevops.candidates import SEVERITY_SCORE


@dataclass(frozen=True)
class AffectedWorkload:
    namespace: str
    name: str


@dataclass(frozen=True)
class QueueRow:
    cve_id: str
    severity: str
    base_priority: int
    affected_workloads: list[AffectedWorkload]


def get_queue_rows(connection: sqlite3.Connection) -> list[QueueRow]:
    """One row per Candidate Set member - see aidevops.candidates - ranked
    by base Contextual Priority, with Severity displayed alongside it per
    the spec. A Vulnerability the pre-filter did not select never reaches
    this query, by the inner join against candidate_priorities.
    """
    cursor = connection.execute(
        """
        SELECT
            v.cve_id AS cve_id,
            v.severity AS severity,
            cp.base_priority AS base_priority,
            w.namespace AS workload_namespace,
            w.name AS workload_name
        FROM candidate_priorities cp
        JOIN vulnerabilities v ON v.cve_id = cp.cve_id
        JOIN workload_images wi ON wi.image_digest = v.image_digest
        JOIN workloads w ON w.id = wi.workload_id
        ORDER BY cp.base_priority DESC, v.cve_id
        """
    )

    workloads_by_cve: dict[str, QueueRow] = {}
    for row in cursor.fetchall():
        workload = AffectedWorkload(namespace=row["workload_namespace"], name=row["workload_name"])
        existing = workloads_by_cve.get(row["cve_id"])
        if existing is None:
            workloads_by_cve[row["cve_id"]] = QueueRow(
                cve_id=row["cve_id"],
                severity=row["severity"],
                base_priority=row["base_priority"],
                affected_workloads=[workload],
            )
        else:
            # The base_priority in candidate_priorities was scored off the
            # worst Severity seen across this CVE's images - see
            # aidevops.candidates._dedupe_by_cve - so the displayed
            # Severity is kept consistent with it the same way, rather
            # than showing whichever image's row this join happened to
            # visit first.
            if SEVERITY_SCORE.get(row["severity"].upper(), 0) > SEVERITY_SCORE.get(existing.severity.upper(), 0):
                workloads_by_cve[row["cve_id"]] = QueueRow(
                    cve_id=existing.cve_id,
                    severity=row["severity"],
                    base_priority=existing.base_priority,
                    affected_workloads=existing.affected_workloads,
                )
                existing = workloads_by_cve[row["cve_id"]]
            if workload not in existing.affected_workloads:
                existing.affected_workloads.append(workload)

    # The join above is keyed for insertion order, not display order - the
    # dict groups a CVE's Workloads together but does not preserve the
    # SQL ORDER BY once duplicate cve_id rows collapse into one entry.
    rows = sorted(workloads_by_cve.values(), key=lambda row: (-row.base_priority, row.cve_id))
    for row in rows:
        row.affected_workloads.sort(key=lambda workload: (workload.namespace, workload.name))
    return rows


def has_pending_scans(connection: sqlite3.Connection) -> bool:
    """True while at least one discovered image has not finished its first
    scan - lets the interface say a scan is in progress instead of showing
    an empty queue, per the spec.
    """
    return connection.execute("SELECT 1 FROM images WHERE scanned_at IS NULL LIMIT 1").fetchone() is not None
