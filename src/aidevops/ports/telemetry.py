"""Telemetry port.

Returns per-pod time series for a requested window. The real implementation
queries Prometheus, which scrapes the kubelet's cAdvisor endpoint; nothing
above this interface may know that.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Protocol

import httpx

from aidevops.domain import METRIC_NAMES, TelemetrySample, TelemetrySeries


class TelemetryPort(Protocol):
    def query(self, pod_name: str, start: datetime, end: datetime) -> TelemetrySeries: ...


class TelemetryUnavailable(Exception):
    """Raised when the real telemetry backend cannot answer a query.

    Callers degrade the Workload detail view's chart rather than the page -
    see aidevops.workload_detail.
    """


class FakeTelemetry:
    def __init__(
        self,
        series_by_pod: dict[str, TelemetrySeries] | None = None,
        *,
        available: bool = True,
    ) -> None:
        self._series_by_pod = series_by_pod or {}
        # Test seam: lets Seam A tests script Prometheus being briefly
        # unavailable, with no Prometheus running.
        self._available = available

    def query(self, pod_name: str, start: datetime, end: datetime) -> TelemetrySeries:
        if not self._available:
            raise TelemetryUnavailable(f"telemetry unavailable for pod {pod_name!r}")
        return self._series_by_pod.get(pod_name, TelemetrySeries(pod_name=pod_name))


# 4x the 15 second scrape interval, the usual Prometheus rule of thumb for a
# rate() window wide enough to always span at least two scrapes.
_RATE_WINDOW = "1m"
_STEP_SECONDS = 15

_QUERIES_BY_METRIC = dict(
    zip(
        METRIC_NAMES,
        (
            'sum(rate(container_cpu_usage_seconds_total{{pod="{pod}", container!="", container!="POD"}}[{window}]))',
            'sum(rate(container_network_transmit_bytes_total{{pod="{pod}", interface!=""}}[{window}]))',
            'sum(rate(container_network_receive_bytes_total{{pod="{pod}", interface!=""}}[{window}]))',
        ),
        strict=True,
    )
)


class PrometheusTelemetry:
    """Queries Prometheus's HTTP API for cAdvisor's per-pod counters.

    Nothing above the telemetry port may know Prometheus exists - see
    CONTEXT.md's port boundary decision.
    """

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def query(self, pod_name: str, start: datetime, end: datetime) -> TelemetrySeries:
        # The three metrics are independent Prometheus queries - run them
        # concurrently rather than one after another, since a Workload
        # detail page issues this once per replica pod and a sequential
        # wait would multiply page latency by 3x per pod.
        try:
            with ThreadPoolExecutor(max_workers=len(_QUERIES_BY_METRIC)) as executor:
                metrics = list(_QUERIES_BY_METRIC)
                results = executor.map(
                    lambda metric: self._range_query(
                        _QUERIES_BY_METRIC[metric].format(pod=pod_name, window=_RATE_WINDOW), start, end
                    ),
                    metrics,
                )
                series_by_metric = dict(zip(metrics, results, strict=True))
        except httpx.HTTPError as error:
            raise TelemetryUnavailable(f"Prometheus query failed for pod {pod_name!r}: {error}") from error

        return TelemetrySeries(pod_name=pod_name, samples=merge_metric_series(series_by_metric))

    def _range_query(self, promql: str, start: datetime, end: datetime) -> dict[datetime, float]:
        response = httpx.get(
            f"{self._base_url}/api/v1/query_range",
            params={
                "query": promql,
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": _STEP_SECONDS,
            },
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            raise TelemetryUnavailable(f"Prometheus returned an error for query {promql!r}: {payload}")

        results = payload["data"]["result"]
        if not results:
            return {}
        return {datetime.fromtimestamp(float(timestamp)): float(value) for timestamp, value in results[0]["values"]}


def merge_metric_series(series_by_metric: dict[str, dict[datetime, float]]) -> list[TelemetrySample]:
    """Zips three independently-fetched Prometheus range vectors - cpu,
    network transmit, network receive - into one TelemetrySample per
    timestamp. Kept separate from the HTTP call so it can be exercised with
    canned Prometheus responses, with no network - the same carve-out
    `aidevops.ports.cluster_inventory` uses for its parsing code.
    """
    all_timestamps = set()
    for values_by_timestamp in series_by_metric.values():
        all_timestamps.update(values_by_timestamp)

    return [
        TelemetrySample(
            timestamp=timestamp,
            **{metric: series_by_metric.get(metric, {}).get(timestamp, 0.0) for metric in METRIC_NAMES},
        )
        for timestamp in sorted(all_timestamps)
    ]
