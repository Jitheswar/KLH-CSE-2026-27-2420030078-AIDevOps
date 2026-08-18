"""Reads the queue view's rows out of SQLite.

The HTTP layer only ever reads from SQLite, never from a port directly - the
inventory-and-scan and telemetry-and-detection loops (see aidevops.app) are
what write into it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace

from aidevops.candidates import SEVERITY_SCORE
from aidevops.domain import ExposureSignalState
from aidevops.ports.triage_model import clamp_adjustment


@dataclass(frozen=True)
class AffectedWorkload:
    namespace: str
    name: str
    has_exposure_signal: bool = False


@dataclass(frozen=True)
class QueueRow:
    cve_id: str
    severity: str
    base_priority: int
    contextual_priority: int
    rationale: str | None
    triage_failed: bool
    affected_workloads: list[AffectedWorkload]

    @property
    def severity_score(self) -> int:
        """Severity mapped onto the same 0-100 scale as Contextual Priority
        (see aidevops.candidates.SEVERITY_SCORE), purely so the queue can
        draw the two side by side and let their divergence read visually -
        per the spec, without the operator doing arithmetic.
        """
        return SEVERITY_SCORE.get(self.severity.upper(), SEVERITY_SCORE["UNKNOWN"])


@dataclass(frozen=True)
class _TriageInfo:
    adjustment: int
    rationale: str
    failed: bool


def get_queue_rows(
    connection: sqlite3.Connection, *, apply_adjustment: bool = True, workload_id: int | None = None
) -> list[QueueRow]:
    """One row per Candidate Set member - see aidevops.candidates - ranked
    by Contextual Priority, with Severity displayed alongside it per the
    spec. A Vulnerability the pre-filter did not select never reaches this
    query, by the inner join against candidate_priorities.

    `apply_adjustment` is the model-adjustment toggle from the spec: with
    it off, every row falls back to its base score, unchanged, and the
    ranking re-renders without touching anything already stored - see
    aidevops.triage and ADR-0004.

    `workload_id` scopes the result to one Workload's own Vulnerabilities -
    see aidevops.app.workload_detail - rather than the whole Candidate Set.
    """
    triage_by_cve = _fetch_triage_by_cve(connection)
    cursor = connection.execute(
        """
        SELECT
            v.cve_id AS cve_id,
            v.severity AS severity,
            cp.base_priority AS base_priority,
            w.namespace AS workload_namespace,
            w.name AS workload_name,
            COALESCE(es.active, 0) AS has_exposure_signal
        FROM candidate_priorities cp
        JOIN vulnerabilities v ON v.cve_id = cp.cve_id
        JOIN workload_images wi ON wi.image_digest = v.image_digest
        JOIN workloads w ON w.id = wi.workload_id
        LEFT JOIN exposure_signals es ON es.workload_id = w.id
        WHERE (:workload_id IS NULL OR w.id = :workload_id)
        ORDER BY cp.base_priority DESC, v.cve_id
        """,
        {"workload_id": workload_id},
    )

    workloads_by_cve: dict[str, QueueRow] = {}
    for row in cursor.fetchall():
        workload = AffectedWorkload(
            namespace=row["workload_namespace"],
            name=row["workload_name"],
            has_exposure_signal=bool(row["has_exposure_signal"]),
        )
        existing = workloads_by_cve.get(row["cve_id"])
        if existing is None:
            base_priority = row["base_priority"]
            contextual_priority, rationale, triage_failed = _resolve_priority(
                base_priority, triage_by_cve.get(row["cve_id"]), apply_adjustment=apply_adjustment
            )
            workloads_by_cve[row["cve_id"]] = QueueRow(
                cve_id=row["cve_id"],
                severity=row["severity"],
                base_priority=base_priority,
                contextual_priority=contextual_priority,
                rationale=rationale,
                triage_failed=triage_failed,
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
                existing = replace(existing, severity=row["severity"])
                workloads_by_cve[row["cve_id"]] = existing
            if workload not in existing.affected_workloads:
                workloads_by_cve[row["cve_id"]] = replace(
                    existing, affected_workloads=[*existing.affected_workloads, workload]
                )

    # The join above is keyed for insertion order, not display order - the
    # dict groups a CVE's Workloads together but does not preserve the
    # SQL ORDER BY once duplicate cve_id rows collapse into one entry.
    rows = sorted(workloads_by_cve.values(), key=lambda row: (-row.contextual_priority, row.cve_id))
    return [
        replace(row, affected_workloads=sorted(row.affected_workloads, key=lambda workload: (workload.namespace, workload.name)))
        for row in rows
    ]


def _resolve_priority(
    base_priority: int, triage: "_TriageInfo | None", *, apply_adjustment: bool
) -> tuple[int, str | None, bool]:
    if triage is None:
        return base_priority, None, False
    if triage.failed:
        return base_priority, triage.rationale, True
    if not apply_adjustment:
        return base_priority, triage.rationale, False
    contextual_priority = max(0, min(base_priority + triage.adjustment, 100))
    return contextual_priority, triage.rationale, False


def _fetch_triage_by_cve(connection: sqlite3.Connection) -> dict[str, _TriageInfo]:
    """Every candidate's Triage, read at whichever Exposure Signal key its
    representative Workload (see aidevops.triage.fetch_pending_triage_candidates)
    currently carries live in `exposure_signals` - not a fixed key -
    so a row this CVE was cached at before a signal transition is
    transparently skipped in favour of whatever `retriage_workload` (see
    aidevops.detection and aidevops.reconcile) has since written at the new
    key, without anything needing to delete the stale row. Ordered by
    image_digest so that if more than one row ever matches for a CVE, the
    choice of which one wins is at least deterministic.

    `claimed = 0` excludes a row an in-flight reconcile pass has claimed
    but not yet resolved (see aidevops.triage) - its placeholder
    `adjustment = 0, failed = 0` would otherwise render as a considered
    "no adjustment" result rather than "not triaged yet".
    """
    rows = connection.execute(
        """
        SELECT
            tr.cve_id AS cve_id,
            tr.image_digest AS image_digest,
            tr.adjustment AS adjustment,
            tr.rationale AS rationale,
            tr.failed AS failed,
            tr.exposure_signal_state AS exposure_signal_state,
            COALESCE(es.active, 0) AS signal_active,
            COALESCE(es.magnitude, 0.0) AS signal_magnitude
        FROM triage_results tr
        JOIN workload_images wi ON wi.image_digest = tr.image_digest
        JOIN workloads w ON w.id = wi.workload_id
        LEFT JOIN exposure_signals es ON es.workload_id = w.id
        WHERE tr.claimed = 0
        ORDER BY tr.cve_id, tr.image_digest
        """
    ).fetchall()
    triage_by_cve: dict[str, _TriageInfo] = {}
    for row in rows:
        if row["cve_id"] in triage_by_cve:
            continue
        current_state = ExposureSignalState(active=bool(row["signal_active"]), magnitude=row["signal_magnitude"])
        if row["exposure_signal_state"] != current_state.cache_key():
            continue
        triage_by_cve[row["cve_id"]] = _TriageInfo(
            adjustment=clamp_adjustment(row["adjustment"]), rationale=row["rationale"], failed=bool(row["failed"])
        )
    return triage_by_cve


def has_pending_scans(connection: sqlite3.Connection) -> bool:
    """True while at least one discovered image has not finished its first
    scan - lets the interface say a scan is in progress instead of showing
    an empty queue, per the spec.
    """
    return connection.execute("SELECT 1 FROM images WHERE scanned_at IS NULL LIMIT 1").fetchone() is not None
