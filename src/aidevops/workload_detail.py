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

from aidevops.baseline import TRAINING_LOOKBACK, Baseline, BaselineBand, train_workload_baseline
from aidevops.domain import METRIC_NAMES, TelemetrySample, TelemetrySeries
from aidevops.ports.telemetry import TelemetryPort, TelemetryUnavailable


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


@dataclass(frozen=True)
class WorkloadSummary:
    id: int
    pod_names: list[str]
    externally_reachable: bool


def get_workload_summary(connection: sqlite3.Connection, namespace: str, name: str) -> WorkloadSummary | None:
    """The Workload detail view's own lookup - id and reachability on top of
    what `get_workload_pods` returns, so the view can scope its
    Vulnerabilities query (see aidevops.queue.get_queue_rows) and show
    external reachability without a second round trip to `workloads`.
    """
    workload = connection.execute(
        "SELECT id, externally_reachable FROM workloads WHERE namespace = ? AND name = ?", (namespace, name)
    ).fetchone()
    if workload is None:
        return None

    pods = connection.execute(
        "SELECT pod_name FROM workload_pods WHERE workload_id = ? ORDER BY pod_name",
        (workload["id"],),
    ).fetchall()
    return WorkloadSummary(
        id=workload["id"],
        pod_names=[row["pod_name"] for row in pods],
        externally_reachable=bool(workload["externally_reachable"]),
    )


def get_workload_telemetry_and_baseline(
    telemetry: TelemetryPort,
    pod_names: list[str],
    end: datetime,
    lookback: timedelta = TRAINING_LOOKBACK,
) -> tuple[WorkloadTelemetry, Baseline | None]:
    """Fetches every replica pod's series once, over the Baseline's rolling
    training lookback, and derives both the chart's telemetry and the
    Workload's Baseline from that single fetch - there is no reason to
    query Prometheus for the same pods twice per page view. The chart shows
    the same window the Baseline was trained on, so the band drawn behind
    it is directly comparable to what is plotted.

    A Prometheus outage degrades both to unavailable, rather than raising -
    see aidevops.app.
    """
    if not pod_names:
        return WorkloadTelemetry(available=True, samples=[]), train_workload_baseline({})

    start = end - lookback
    try:
        with ThreadPoolExecutor(max_workers=len(pod_names)) as executor:
            series_by_pod = dict(
                zip(pod_names, executor.map(lambda pod_name: telemetry.query(pod_name, start, end), pod_names), strict=True)
            )
    except TelemetryUnavailable:
        return WorkloadTelemetry(available=False), None

    telemetry_result = WorkloadTelemetry(available=True, samples=_sum_pod_series(series_by_pod.values()))
    baseline = train_workload_baseline({pod_name: series.samples for pod_name, series in series_by_pod.items()})
    return telemetry_result, baseline


def scaled_band(baseline: Baseline, metric: str, replica_count: int) -> BaselineBand | None:
    """Scales a Baseline's per-replica band up to the number of replicas
    being summed on the chart. The band is trained on pooled per-replica
    windows (ADR-0002), while the chart shows replicas summed together, so a
    scaled-out Workload's normal *total* is approximately its per-replica
    band times its replica count.
    """
    band = baseline.band(metric)
    if band is None or replica_count <= 0:
        return None
    return BaselineBand(low=band.low * replica_count, high=band.high * replica_count)


def _sum_pod_series(series: list[TelemetrySeries]) -> list[TelemetrySample]:
    totals_by_timestamp: dict[datetime, dict[str, float]] = {}
    for pod_series in series:
        for sample in pod_series.samples:
            totals = totals_by_timestamp.setdefault(sample.timestamp, dict.fromkeys(METRIC_NAMES, 0.0))
            for metric in METRIC_NAMES:
                totals[metric] += getattr(sample, metric)

    return [
        TelemetrySample(timestamp=timestamp, **totals)
        for timestamp, totals in sorted(totals_by_timestamp.items())
    ]
