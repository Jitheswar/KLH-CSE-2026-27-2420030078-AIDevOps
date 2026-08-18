"""Reconciles the cluster inventory port's Workloads into SQLite.

This is the loop body the spec requires to be shared: the periodic
inventory loop and the manual rescan control both go through
`reconcile_workloads` and `scan_pending_images`, rather than each having
their own copy of this logic. `reconcile` composes the two for a caller with
no locking to worry about; `aidevops.app` calls them separately because it
does.

Scanning is keyed on image digest, which is immutable, so a digest already
recorded as scanned is never re-scanned - see `_mark_image_discovered`. That
decision is logged rather than left implicit, per the spec's requirement
that the cache behaviour be observable.

Discovering Workloads and scanning their images are split into two steps
rather than one, so that a caller holding a lock around SQLite access (see
aidevops.app) only holds it across the cheap step. A real Trivy scan is a
slow subprocess call and must not happen while that lock is held, or every
request for the queue page blocks behind it.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import TYPE_CHECKING, Callable

from aidevops.candidates import fetch_vulnerability_rows, score_candidate_set, store_candidate_set
from aidevops.triage import enrich_with_threat_intel, fetch_pending_triage_candidates, run_triage_model, store_triage_outcomes

if TYPE_CHECKING:
    from aidevops.app import Ports
    from aidevops.domain import ContainerImage, Vulnerability, Workload

logger = logging.getLogger(__name__)


def reconcile(connection: sqlite3.Connection, ports: "Ports") -> None:
    """Composes every reconcile step for a caller with no lock to worry
    about. `aidevops.app` does not call this directly - it has its own
    locked composition of the same steps, for the reasons the module
    docstring above gives - so this is the reference shape that
    composition follows, not a second, drifting code path in its own
    right.
    """
    workloads = ports.cluster_inventory.list_workloads()
    pending = reconcile_workloads(connection, ports, workloads)
    scan_pending_images(connection, ports, pending)
    # Re-run on every pass, not only when a scan wrote something new - the
    # threat intel snapshot itself does not change mid-process, but this
    # is the loop body the periodic loop and the manual rescan share.
    rows = fetch_vulnerability_rows(connection)
    candidates = score_candidate_set(rows, ports.threat_intel)
    store_candidate_set(connection, candidates)

    # Triages every Candidate Set member still missing one, per the spec's
    # per-CVE-per-image cache - see aidevops.triage.
    triage_candidates = fetch_pending_triage_candidates(connection)
    triage_candidates = enrich_with_threat_intel(triage_candidates, ports.threat_intel)
    outcomes = run_triage_model(ports.triage_model, triage_candidates)
    store_triage_outcomes(connection, outcomes)


def retriage_workload(connection: sqlite3.Connection, ports: "Ports", workload_id: int) -> None:
    """Re-runs Triage for exactly one Workload's Vulnerabilities - the
    surgical re-Triage an Exposure Signal transition triggers (see
    aidevops.detection.run_detection and the spec), rather than
    re-checking the whole Candidate Set the way `reconcile` does.

    Same unlocked, no-lock-to-worry-about shape as `reconcile` above;
    `aidevops.app` has its own locked composition of the same steps for the
    reasons the module docstring gives.
    """
    triage_candidates = fetch_pending_triage_candidates(connection, workload_id=workload_id)
    triage_candidates = enrich_with_threat_intel(triage_candidates, ports.threat_intel)
    outcomes = run_triage_model(ports.triage_model, triage_candidates)
    store_triage_outcomes(connection, outcomes)


def reconcile_workloads(
    connection: sqlite3.Connection, ports: "Ports", workloads: list["Workload"]
) -> list["ContainerImage"]:
    """The DB-writing half of `reconcile`, split out so callers holding a
    lock around SQLite access (see aidevops.app) can fetch `workloads` from
    the cluster inventory port - a real network call once it talks to
    Kubernetes - before acquiring that lock rather than while holding it.

    Returns the images that still need scanning. Scanning itself does not
    happen here - see `scan_pending_images` and the module docstring.
    """
    seen_keys = {(workload.namespace, workload.name) for workload in workloads}

    existing = connection.execute("SELECT id, namespace, name FROM workloads").fetchall()
    for row in existing:
        if (row["namespace"], row["name"]) not in seen_keys:
            connection.execute("DELETE FROM workload_pods WHERE workload_id = ?", (row["id"],))
            connection.execute("DELETE FROM workload_images WHERE workload_id = ?", (row["id"],))
            connection.execute("DELETE FROM workloads WHERE id = ?", (row["id"],))

    pending: list["ContainerImage"] = []
    seen_digests: set[str] = set()
    for workload in workloads:
        for image in _reconcile_workload(connection, workload):
            # Two Workloads can share a newly discovered digest within the
            # same pass - _mark_image_discovered reports each of them as
            # needing a scan, since neither has been scanned yet, so the
            # aggregate list is deduplicated here rather than scanning the
            # same digest twice.
            if image.digest not in seen_digests:
                seen_digests.add(image.digest)
                pending.append(image)

    connection.commit()
    return pending


def _reconcile_workload(connection: sqlite3.Connection, workload: "Workload") -> list["ContainerImage"]:
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
    pending: list["ContainerImage"] = []
    for image in workload.images:
        if _mark_image_discovered(connection, image):
            pending.append(image)
        connection.execute(
            "INSERT OR IGNORE INTO workload_images (workload_id, image_digest) VALUES (?, ?)",
            (workload_id, image.digest),
        )
    return pending


def _mark_image_discovered(connection: sqlite3.Connection, image: "ContainerImage") -> bool:
    """Records that this digest is known, and reports whether it still needs
    scanning - claiming it for scanning, under the caller's lock, if so.

    The claim is what keeps two reconcile passes racing each other - e.g.
    the periodic loop's immediate first tick overlapping a manual rescan -
    from both deciding the same digest is pending and scanning it twice:
    `scanned_at` alone does not distinguish "pending" from "another pass is
    already scanning this," since a real Trivy scan can run for minutes
    outside this lock. `scan_pending_images` releases the claim if the scan
    fails, so a transient failure is still retried on the next reconcile.
    """
    row = connection.execute("SELECT scanned_at, scanning FROM images WHERE digest = ?", (image.digest,)).fetchone()
    if row is not None:
        if row["scanned_at"] is not None:
            logger.info("image %s already scanned, skipping", image.digest)
            return False
        if row["scanning"]:
            logger.info("image %s already claimed by another in-flight scan, skipping", image.digest)
            return False
        connection.execute("UPDATE images SET scanning = 1 WHERE digest = ?", (image.digest,))
        logger.info("image %s discovered previously but not yet scanned, claiming", image.digest)
        return True

    connection.execute(
        "INSERT INTO images (digest, repository, scanned_at, scanning) VALUES (?, ?, NULL, 1)",
        (image.digest, image.repository),
    )
    logger.info("image %s newly discovered, claiming for scanning", image.digest)
    return True


def scan_pending_images(
    connection: sqlite3.Connection,
    ports: "Ports",
    images: list["ContainerImage"],
    store: "Callable[[sqlite3.Connection, str, list[Vulnerability]], None] | None" = None,
    release: "Callable[[sqlite3.Connection, str], None] | None" = None,
) -> None:
    """Scans each pending image and stores its result. A failed scan is
    logged and skipped rather than raised, so one bad image does not stop
    the rest; its scan claim is released so it is retried on the next
    reconcile, rather than being stuck claimed forever.

    `store` and `release` are seams for callers that hold a lock around
    `connection` (see aidevops.app): scanning itself must not happen while
    that lock is held - a real Trivy scan is a slow subprocess call - only
    the writes they perform need it. Default to `store_scan_result` and
    `release_scan_claim`.
    """
    store = store or store_scan_result
    release = release or release_scan_claim
    for image in images:
        try:
            vulnerabilities = ports.image_scanner.scan(image)
        except Exception:
            logger.exception("scan failed for image %s, will retry next reconcile", image.digest)
            release(connection, image.digest)
            continue
        store(connection, image.digest, vulnerabilities)


def release_scan_claim(connection: sqlite3.Connection, digest: str) -> None:
    connection.execute("UPDATE images SET scanning = 0 WHERE digest = ?", (digest,))
    connection.commit()


def store_scan_result(connection: sqlite3.Connection, digest: str, vulnerabilities: list["Vulnerability"]) -> None:
    for vulnerability in vulnerabilities:
        connection.execute(
            """
            INSERT OR IGNORE INTO vulnerabilities
                (cve_id, image_digest, package, installed_version, fixed_version, severity, cvss_vector, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vulnerability.cve_id,
                digest,
                vulnerability.package,
                vulnerability.installed_version,
                vulnerability.fixed_version,
                vulnerability.severity,
                vulnerability.cvss_vector,
                vulnerability.description,
            ),
        )

    connection.execute(
        "UPDATE images SET scanned_at = datetime('now'), scanning = 0 WHERE digest = ?",
        (digest,),
    )
    connection.commit()
