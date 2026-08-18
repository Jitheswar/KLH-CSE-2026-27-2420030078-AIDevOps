"""Runs Exposure Signal detection for every known Workload and persists the
result, so the queue and Workload detail views can read it from SQLite
without querying telemetry themselves - same split as aidevops.reconcile.

Split into a DB-reading step, a network-and-CPU step, and a DB-writing
step, same reasoning as aidevops.reconcile: a caller holding a lock around
SQLite access (see aidevops.app) must not hold it across the middle step -
querying Prometheus per pod is a real network call, and a detection pass
across every Workload must not block the queue page or the inventory loop
behind however long Prometheus takes to answer. `run_detection` composes
all three with no lock to worry about, for tests and any manual trigger;
aidevops.app has its own locked composition of the same steps.

A Prometheus outage for one Workload's pods is logged and skipped, leaving
its last known signal state in place, rather than raised - same degrade
philosophy as aidevops.workload_detail.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from aidevops.baseline import TRAINING_LOOKBACK
from aidevops.exposure_signal import ExposureSignal, detect_workload_exposure_signal
from aidevops.ports.telemetry import TelemetryUnavailable
from aidevops.reconcile import retriage_workload
from aidevops.workload_detail import get_workload_pods

if TYPE_CHECKING:
    from aidevops.app import Ports

logger = logging.getLogger(__name__)

# Wide enough to comfortably contain the Baseline's own rolling training
# window plus a tail of recent windows to detect against.
DETECTION_LOOKBACK = TRAINING_LOOKBACK + timedelta(hours=1)


@dataclass(frozen=True)
class KnownWorkload:
    id: int
    namespace: str
    name: str
    pod_names: list[str]


def list_workloads_with_pods(connection: sqlite3.Connection) -> list[KnownWorkload]:
    """The DB-reading step - see the module docstring."""
    workloads = connection.execute("SELECT id, namespace, name FROM workloads").fetchall()
    known = []
    for row in workloads:
        pod_names = get_workload_pods(connection, row["namespace"], row["name"]) or []
        if pod_names:
            known.append(KnownWorkload(id=row["id"], namespace=row["namespace"], name=row["name"], pod_names=pod_names))
    return known


def detect_signal_for_workload(
    ports: "Ports",
    pod_names: list[str],
    now: datetime,
    fetch_lookback: timedelta = DETECTION_LOOKBACK,
    training_lookback: timedelta = TRAINING_LOOKBACK,
) -> ExposureSignal | None:
    """The network-and-CPU step - see the module docstring. Queries every
    replica pod's telemetry and folds it through the hysteresis and
    Baseline-freeze rules. Returns None, rather than raising, if telemetry
    is unavailable for this Workload right now.

    `fetch_lookback` is how far back telemetry is queried for - wide enough
    to comfortably contain `training_lookback`, the width of the Baseline's
    own rolling training window (see aidevops.exposure_signal), plus a tail
    of recent windows to detect against. The two are separate parameters
    because a caller overriding one - a test standing in a short refit
    interval, say - has no reason to also change the other.
    """
    start = now - fetch_lookback
    try:
        series_by_pod = {pod_name: ports.telemetry.query(pod_name, start, now).samples for pod_name in pod_names}
    except TelemetryUnavailable:
        return None
    return detect_workload_exposure_signal(series_by_pod, end=now, lookback=training_lookback)


def store_exposure_signal(
    connection: sqlite3.Connection,
    workload_id: int,
    active: bool,
    magnitude: float = 0.0,
    window_start: datetime | None = None,
    fired_at: datetime | None = None,
) -> bool:
    """The DB-writing step - see the module docstring. Committed on its
    own per Workload, same reasoning as aidevops.reconcile.store_scan_result:
    a Workload's result that's ready is visible immediately rather than
    waiting for the slowest one in the pass.

    Returns whether `active` just flipped from what was stored before -
    the fire or clear transition that drives signal-driven re-Triage (see
    `run_detection` and aidevops.app). A Workload with no prior row is
    treated as having been inactive, so a Workload firing on its very
    first ever detection pass still counts as a transition.

    While a Workload stays continuously active, `magnitude`, `window_start`
    and `fired_at` are all pinned to whatever they were the moment it fired
    rather than overwritten with each detection pass's freshly recomputed
    value - the same freeze reasoning ADR-0003 already applies to the
    Baseline training window while active. `magnitude` feeds
    `ExposureSignalState.cache_key()` (see aidevops.domain), and a live
    value that drifts by real telemetry noise on every tick would otherwise
    hand every periodic reconcile pass a fresh cache key for an
    already-Triaged CVE, re-billing the model for it every pass rather than
    only on the transition that actually happened. `window_start` and
    `fired_at` feed the Workload detail chart's shaded triggering window
    and fire-moment marker (see aidevops.charts) and would otherwise slide
    forward on every tick a still-active signal is recomputed.
    """
    previous = connection.execute(
        "SELECT active, magnitude, window_start, fired_at FROM exposure_signals WHERE workload_id = ?", (workload_id,)
    ).fetchone()
    was_active = bool(previous["active"]) if previous is not None else False
    transitioned = active != was_active

    if active and not transitioned:
        magnitude = previous["magnitude"]
        window_start = _parse_iso(previous["window_start"])
        fired_at = _parse_iso(previous["fired_at"])
    elif not active:
        window_start = None
        fired_at = None

    connection.execute(
        """
        INSERT INTO exposure_signals (workload_id, active, magnitude, window_start, fired_at) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (workload_id) DO UPDATE SET
            active = excluded.active, magnitude = excluded.magnitude,
            window_start = excluded.window_start, fired_at = excluded.fired_at
        """,
        (workload_id, int(active), magnitude, _to_iso(window_start), _to_iso(fired_at)),
    )
    connection.commit()
    return transitioned


def _to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


@dataclass(frozen=True)
class ExposureSignalWindow:
    """The triggering window and fire moment for an active Exposure Signal,
    for the Workload detail chart - see aidevops.charts. Both None when the
    Workload has no active signal.
    """

    window_start: datetime | None
    fired_at: datetime | None


def get_workload_exposure_signal_window(connection: sqlite3.Connection, namespace: str, name: str) -> ExposureSignalWindow:
    row = connection.execute(
        """
        SELECT es.window_start AS window_start, es.fired_at AS fired_at
        FROM exposure_signals es
        JOIN workloads w ON w.id = es.workload_id
        WHERE w.namespace = ? AND w.name = ? AND es.active = 1
        """,
        (namespace, name),
    ).fetchone()
    if row is None:
        return ExposureSignalWindow(window_start=None, fired_at=None)
    return ExposureSignalWindow(window_start=_parse_iso(row["window_start"]), fired_at=_parse_iso(row["fired_at"]))


def run_detection(
    connection: sqlite3.Connection,
    ports: "Ports",
    now: datetime,
    fetch_lookback: timedelta = DETECTION_LOOKBACK,
    training_lookback: timedelta = TRAINING_LOOKBACK,
) -> None:
    """The reference, no-lock composition of the three steps above - see
    the module docstring. `aidevops.app` does not call this directly; it
    has its own locked composition for the same reasons `aidevops.reconcile`
    gives for `reconcile()`.

    A fire or clear transition (see `store_exposure_signal`) re-Triages
    that Workload's Vulnerabilities immediately, in the same pass - not
    deferred to the next periodic reconcile - via `retriage_workload`,
    scoped to exactly this Workload so no other Workload's cached Triages
    are touched.
    """
    for workload in list_workloads_with_pods(connection):
        signal = detect_signal_for_workload(ports, workload.pod_names, now, fetch_lookback, training_lookback)
        if signal is None:
            logger.warning("telemetry unavailable for workload %s/%s, skipping detection", workload.namespace, workload.name)
            continue
        transitioned = store_exposure_signal(
            connection, workload.id, signal.active, signal.magnitude, signal.window_start, signal.fired_at
        )
        if transitioned:
            retriage_workload(connection, ports, workload.id)


def get_active_exposure_signal_workload_ids(connection: sqlite3.Connection) -> set[int]:
    rows = connection.execute("SELECT workload_id FROM exposure_signals WHERE active = 1").fetchall()
    return {row["workload_id"] for row in rows}


def workload_has_active_exposure_signal(connection: sqlite3.Connection, namespace: str, name: str) -> bool:
    row = connection.execute(
        """
        SELECT es.active AS active
        FROM exposure_signals es
        JOIN workloads w ON w.id = es.workload_id
        WHERE w.namespace = ? AND w.name = ?
        """,
        (namespace, name),
    ).fetchone()
    return bool(row is not None and row["active"])
