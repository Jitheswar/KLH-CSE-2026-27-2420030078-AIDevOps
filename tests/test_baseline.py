"""Baseline training and cold start. Pure functions driven with synthetic
telemetry, no network - same carve-out `test_charts.py` uses for the chart
renderer.

The two Seam A requirements from ticket 08 live here as
`test_a_busy_workload_is_not_reported_abnormal_for_being_busy` and
`test_a_new_replica_inherits_its_workloads_trained_model`: both drive the
detection logic through synthetic time series exactly the way a Seam A test
drives the fake telemetry port, without needing an HTTP surface that does
not exist yet - the Exposure Signal badge that would consume this is
ticket 09's.
"""

from __future__ import annotations

import random
from dataclasses import replace
from datetime import datetime, timedelta

from aidevops.baseline import (
    MIN_WINDOWS_FOR_FOREST,
    WINDOW,
    compute_window_features,
    train_baseline,
    train_workload_baseline,
)
from aidevops.domain import TelemetrySample

_START = datetime(2024, 1, 1, 12, 0, 0)


def _busy_series(count: int, *, seed: int = 0, start: datetime = _START) -> list[TelemetrySample]:
    """A steadily busy pod: high but stable CPU and traffic, sampled every
    30 seconds like the fake telemetry port's other Seam A fixtures.
    """
    rng = random.Random(seed)
    return [
        TelemetrySample(
            timestamp=start + timedelta(seconds=30 * i),
            cpu=5.0 + rng.uniform(-0.2, 0.2),
            network_transmit=50.0 + rng.uniform(-2.0, 2.0),
            network_receive=25.0 + rng.uniform(-1.0, 1.0),
        )
        for i in range(count)
    ]


def _representative_window(series: list[TelemetrySample]):
    """A window with a full sample count - not one of the trailing partial
    windows at the very edge of the series, which are noisier because they
    average fewer samples.
    """
    windows = compute_window_features(series)
    return windows[len(windows) // 2]


def test_below_the_threshold_the_baseline_is_still_establishing() -> None:
    series = _busy_series(MIN_WINDOWS_FOR_FOREST - 5)
    windows = compute_window_features(series)

    baseline = train_baseline(windows)

    assert baseline.established is False


def test_at_the_threshold_the_baseline_is_established() -> None:
    series = _busy_series(200)
    windows = compute_window_features(series)

    baseline = train_baseline(windows)

    assert baseline.established is True
    assert baseline.training_window_count >= MIN_WINDOWS_FOR_FOREST


def test_cold_start_makes_no_claim_about_normal_or_abnormal() -> None:
    series = _busy_series(MIN_WINDOWS_FOR_FOREST - 5)
    windows = compute_window_features(series)
    baseline = train_baseline(windows)

    assert baseline.is_anomalous(windows[-1]) is False


def test_cold_start_magnitude_is_zero() -> None:
    series = _busy_series(MIN_WINDOWS_FOR_FOREST - 5)
    windows = compute_window_features(series)
    baseline = train_baseline(windows)

    assert baseline.anomaly_magnitude(windows[-1]) == 0.0


def test_anomaly_magnitude_is_higher_for_an_anomalous_window_than_a_normal_one() -> None:
    series = _busy_series(200)
    windows = compute_window_features(series)
    baseline = train_baseline(windows)
    normal_window = _representative_window(series)

    # Features pushed far outside the trained range, so this reads as
    # anomalous rather than merely a fresh, in-distribution sample.
    anomalous_window = replace(normal_window, cpu=500.0, network_transmit=5000.0, network_receive=1.0)

    assert baseline.anomaly_magnitude(anomalous_window) > baseline.anomaly_magnitude(normal_window)


def test_a_busy_workload_is_not_reported_abnormal_for_being_busy() -> None:
    series = _busy_series(200)
    windows = compute_window_features(series)
    baseline = train_baseline(windows)
    assert baseline.established

    assert baseline.is_anomalous(_representative_window(series)) is False


def test_a_new_replica_inherits_its_workloads_trained_model() -> None:
    veteran = _busy_series(200, seed=1)
    # A replica scheduled moments ago: only enough samples for a handful of
    # windows on its own, nowhere near MIN_WINDOWS_FOR_FOREST.
    freshly_scheduled = _busy_series(4, seed=2, start=_START + timedelta(hours=1))

    pooled = train_workload_baseline({"veteran-abc": veteran, "fresh-xyz": freshly_scheduled})

    # Pooling the veteran replica's history is what lets the Workload's
    # Baseline be established even though the new replica alone has almost
    # none - per ADR-0002, replicas of one Deployment share one Baseline.
    assert pooled.established is True

    new_replica_window = compute_window_features(freshly_scheduled)[0]
    assert pooled.is_anomalous(new_replica_window) is False


def test_pooling_no_replicas_yields_an_unestablished_baseline() -> None:
    baseline = train_workload_baseline({})

    assert baseline.established is False
    assert baseline.training_window_count == 0


def test_compute_window_features_steps_every_thirty_seconds() -> None:
    series = _busy_series(20)

    windows = compute_window_features(series)

    assert len(windows) > 1
    assert windows[1].start - windows[0].start == timedelta(seconds=30)
    assert windows[0].end - windows[0].start == WINDOW


def test_a_quiet_pod_with_no_receive_traffic_does_not_divide_by_zero() -> None:
    series = [
        TelemetrySample(timestamp=_START + timedelta(seconds=30 * i), cpu=0.1, network_transmit=0.0, network_receive=0.0)
        for i in range(10)
    ]

    windows = compute_window_features(series)

    assert all(window.transmit_receive_ratio == 0.0 for window in windows)
