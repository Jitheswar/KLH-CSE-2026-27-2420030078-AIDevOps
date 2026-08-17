"""Telemetry port.

Returns per-pod time series for a requested window. The real implementation
(a later ticket) queries Prometheus; nothing above this interface may know
that.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from aidevops.domain import TelemetrySeries


class TelemetryPort(Protocol):
    def query(self, pod_name: str, start: datetime, end: datetime) -> TelemetrySeries: ...


class FakeTelemetry:
    def __init__(self, series_by_pod: dict[str, TelemetrySeries] | None = None) -> None:
        self._series_by_pod = series_by_pod or {}

    def query(self, pod_name: str, start: datetime, end: datetime) -> TelemetrySeries:
        return self._series_by_pod.get(pod_name, TelemetrySeries(pod_name=pod_name))
