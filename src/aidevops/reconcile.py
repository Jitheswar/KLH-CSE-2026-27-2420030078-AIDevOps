"""Reconciles the cluster inventory port's Workloads into SQLite.

This is the loop body the spec requires to be shared: the periodic
inventory loop and the manual rescan control both call `reconcile`
directly rather than each having their own copy of this logic.

Scanning is keyed on image digest, which is immutable, so a digest already
recorded as scanned is never re-scanned.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aidevops.app import Ports
    from aidevops.domain import ContainerImage, Workload


def reconcile(connection: sqlite3.Connection, ports: "Ports") -> None:
    workloads = ports.cluster_inventory.list_workloads()
    reconcile_workloads(connection, ports, workloads)


def reconcile_workloads(connection: sqlite3.Connection, ports: "Ports", workloads: list["Workload"]) -> None:
    """The DB-writing half of `reconcile`, split out so callers holding a
    lock around SQLite access (see aidevops.app) can fetch `workloads` from
    the cluster inventory port - a real network call once it talks to
    Kubernetes - before acquiring that lock rather than while holding it.
    """
    seen_keys = {(workload.namespace, workload.name) for workload in workloads}

    existing = connection.execute("SELECT id, namespace, name FROM workloads").fetchall()
    for row in existing:
        if (row["namespace"], row["name"]) not in seen_keys:
            connection.execute("DELETE FROM workload_pods WHERE workload_id = ?", (row["id"],))
            connection.execute("DELETE FROM workload_images WHERE workload_id = ?", (row["id"],))
            connection.execute("DELETE FROM workloads WHERE id = ?", (row["id"],))

    for workload in workloads:
        _reconcile_workload(connection, ports, workload)

    connection.commit()


def _reconcile_workload(connection: sqlite3.Connection, ports: "Ports", workload: "Workload") -> None:
    connection.execute(
        """
        INSERT INTO workloads (namespace, name, externally_reachable)
        VALUES (?, ?, ?)
        ON CONFLICT (namespace, name)
        DO UPDATE SET externally_reachable = excluded.externally_reachable
        """,
        (workload.namespace, workload.name, int(workload.externally_reachable)),
    )
    workload_id = connection.execute(
        "SELECT id FROM workloads WHERE namespace = ? AND name = ?",
        (workload.namespace, workload.name),
    ).fetchone()["id"]

    connection.execute("DELETE FROM workload_pods WHERE workload_id = ?", (workload_id,))
    for pod_name in workload.replica_pod_names:
        connection.execute(
            "INSERT INTO workload_pods (workload_id, pod_name) VALUES (?, ?)",
            (workload_id, pod_name),
        )

    connection.execute("DELETE FROM workload_images WHERE workload_id = ?", (workload_id,))
    for image in workload.images:
        _ensure_image_scanned(connection, ports, image)
        connection.execute(
            "INSERT OR IGNORE INTO workload_images (workload_id, image_digest) VALUES (?, ?)",
            (workload_id, image.digest),
        )


def _ensure_image_scanned(connection: sqlite3.Connection, ports: "Ports", image: "ContainerImage") -> None:
    row = connection.execute(
        "SELECT scanned_at FROM images WHERE digest = ?", (image.digest,)
    ).fetchone()
    if row is not None and row["scanned_at"] is not None:
        return

    connection.execute(
        "INSERT OR IGNORE INTO images (digest, repository, scanned_at) VALUES (?, ?, NULL)",
        (image.digest, image.repository),
    )

    for vulnerability in ports.image_scanner.scan(image.digest):
        connection.execute(
            """
            INSERT OR IGNORE INTO vulnerabilities
                (cve_id, image_digest, package, installed_version, fixed_version, severity, cvss_vector, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vulnerability.cve_id,
                image.digest,
                vulnerability.package,
                vulnerability.installed_version,
                vulnerability.fixed_version,
                vulnerability.severity,
                vulnerability.cvss_vector,
                vulnerability.description,
            ),
        )

    connection.execute(
        "UPDATE images SET scanned_at = datetime('now') WHERE digest = ?",
        (image.digest,),
    )
