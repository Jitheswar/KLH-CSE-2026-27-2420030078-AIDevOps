"""Assembles a Workload's telemetry for its detail view.

Unlike the queue, which only ever reads from SQLite, this view queries the
telemetry port live on every request - it shows the truth about what the
pods are doing right now, not something the inventory loop persists.
"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aidevops.domain import TelemetrySample
from aidevops.ports.telemetry import TelemetryPort, TelemetryUnavailable

DEFAULT_WINDOW = timedelta(minutes=15)


@dataclass(frozen=True)
class WorkloadTelemetry:
    available: bool
    samples: list[TelemetrySample] = field(default_factory=list)


def get_workload_pods(connection: sqlite3.Connection, namespace: str, name: str) -> list[str] | None:
    """Returns the Workload's pod names, or None if no such Workload is known."""
    workload = connection.execute(
        "SELECT id FROM workloads WHERE namespace = ? AND name = ?", (namespace, name)
    ).fetchone()
    if workload is None:
        return None

    pods = connection.execute(
        "SELECT pod_name FROM workload_pods WHERE workload_id = ? ORDER BY pod_name",
        (workload["id"],),
    ).fetchall()
    return [row["pod_name"] for row in pods]


def get_workload_telemetry(
    telemetry: TelemetryPort,
    pod_names: list[str],
    end: datetime,
    window: timedelta = DEFAULT_WINDOW,
) -> WorkloadTelemetry:
    """Fetches every replica pod's series for the window and sums them into
    one Workload-level series. A Prometheus outage degrades this to an
    unavailable result rather than raising - see aidevops.app.
    """
    if not pod_names:
        return WorkloadTelemetry(available=True, samples=[])

    start = end - window
    try:
        # One query per replica pod - run them concurrently so a Workload
        # with several replicas doesn't pay for each pod's Prometheus round
        # trip one after another.
        with ThreadPoolExecutor(max_workers=len(pod_names)) as executor:
            series = list(executor.map(lambda pod_name: telemetry.query(pod_name, start, end), pod_names))
    except TelemetryUnavailable:
        return WorkloadTelemetry(available=False)

    return WorkloadTelemetry(available=True, samples=_sum_pod_series(series))


def _sum_pod_series(series: list) -> list[TelemetrySample]:
    totals_by_timestamp: dict[datetime, list[float]] = {}
    for pod_series in series:
        for sample in pod_series.samples:
            totals = totals_by_timestamp.setdefault(sample.timestamp, [0.0, 0.0, 0.0])
            totals[0] += sample.cpu
            totals[1] += sample.network_transmit
            totals[2] += sample.network_receive

    return [
        TelemetrySample(timestamp=timestamp, cpu=cpu, network_transmit=tx, network_receive=rx)
        for timestamp, (cpu, tx, rx) in sorted(totals_by_timestamp.items())
    ]
