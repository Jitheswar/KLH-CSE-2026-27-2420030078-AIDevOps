"""Reads the queue view's rows out of SQLite.

The HTTP layer only ever reads from SQLite, never from a port directly - the
inventory-and-scan and telemetry-and-detection loops (later tickets) are
what write into it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class AffectedWorkload:
    namespace: str
    name: str


@dataclass(frozen=True)
class QueueRow:
    cve_id: str
    severity: str
    affected_workloads: list[AffectedWorkload]


def get_queue_rows(connection: sqlite3.Connection) -> list[QueueRow]:
    cursor = connection.execute(
        """
        SELECT
            v.cve_id AS cve_id,
            v.severity AS severity,
            w.namespace AS workload_namespace,
            w.name AS workload_name
        FROM vulnerabilities v
        JOIN workload_images wi ON wi.image_digest = v.image_digest
        JOIN workloads w ON w.id = wi.workload_id
        ORDER BY v.cve_id
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
                affected_workloads=[workload],
            )
        elif workload not in existing.affected_workloads:
            existing.affected_workloads.append(workload)

    rows = list(workloads_by_cve.values())
    for row in rows:
        row.affected_workloads.sort(key=lambda workload: (workload.namespace, workload.name))
    return rows


def has_pending_scans(connection: sqlite3.Connection) -> bool:
    """True while at least one discovered image has not finished its first
    scan - lets the interface say a scan is in progress instead of showing
    an empty queue, per the spec.
    """
    return connection.execute("SELECT 1 FROM images WHERE scanned_at IS NULL LIMIT 1").fetchone() is not None
