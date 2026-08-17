"""Unit tests for the real telemetry port's pure adapter logic.

These do not touch a live Prometheus - that is Seam B's job, for a later
ticket. What is tested here is deterministic merging code that has no HTTP
calls in it, the same carve-out `test_real_cluster_inventory.py` uses for
the cluster inventory port's parsing code.
"""

from __future__ import annotations

from datetime import datetime

from aidevops.domain import TelemetrySample
from aidevops.ports.telemetry import merge_metric_series

_T0 = datetime(2024, 1, 1, 12, 0, 0)
_T1 = datetime(2024, 1, 1, 12, 0, 15)


def test_merges_three_metrics_aligned_by_timestamp() -> None:
    samples = merge_metric_series(
        {
            "cpu": {_T0: 1.0, _T1: 2.0},
            "network_transmit": {_T0: 10.0, _T1: 20.0},
            "network_receive": {_T0: 100.0, _T1: 200.0},
        }
    )

    assert samples == [
        TelemetrySample(timestamp=_T0, cpu=1.0, network_transmit=10.0, network_receive=100.0),
        TelemetrySample(timestamp=_T1, cpu=2.0, network_transmit=20.0, network_receive=200.0),
    ]


def test_a_timestamp_missing_from_one_metric_defaults_to_zero() -> None:
    samples = merge_metric_series(
        {
            "cpu": {_T0: 1.0},
            "network_transmit": {},
            "network_receive": {_T0: 100.0},
        }
    )

    assert samples == [TelemetrySample(timestamp=_T0, cpu=1.0, network_transmit=0.0, network_receive=100.0)]


def test_no_metrics_returns_no_samples() -> None:
    assert merge_metric_series({}) == []
