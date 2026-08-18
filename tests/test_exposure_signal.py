"""Exposure Signal lifecycle: hysteresis, per-pod max attribution, and the
Baseline freeze. Pure functions driven with synthetic telemetry, no
network - same carve-out `test_baseline.py` uses.

The fire-after-2/clear-after-3 hysteresis is tested directly against
`SignalState`, independent of how "anomalous" gets decided for a given
window: with the Baseline's window stepped every 30 seconds over a 2 minute
span (ADR-0002, ticket 08), any two adjacent windows share 3 of their 4
samples, so a real spike's very first affected window and the one after it
are both drawn from an overlapping, highly correlated pair of feature
vectors - there is no way to manufacture a real telemetry series that trips
"exactly one anomalous window" without also tripping its neighbour. The
hysteresis rule itself has no opinion on where "anomalous" comes from, so
testing it against a synthetic boolean sequence is the correct level, the
same way `test_baseline.py` tests Baseline classification without needing
an HTTP surface.

The remaining Seam A requirements - per-pod max attribution and the
training freeze - do need real telemetry through the Baseline, and are
covered below with a sustained (many-window) spike rather than a
single-window one, so the assertion does not ride on the precise boundary
behaviour above.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from aidevops.domain import TelemetrySample
from aidevops.exposure_signal import CLEAR_AFTER, FIRE_AFTER, SignalState, detect_workload_exposure_signal

_START = datetime(2024, 1, 1, 12, 0, 0)
_STEP = timedelta(seconds=30)

# A seed/length verified (see ticket 09's implementation notes) to have no
# two adjacent windows misclassified by the Isolation Forest's own forced
# 5% contamination, and none within the last few windows - the boundary a
# later-appended spike's look-ahead windows would otherwise land on. This
# is what keeps the integration tests below from being flaky: they assert
# on a spike large enough to swamp that irreducible background rate, not
# on a single-window margin.
_QUIET_COUNT = 45
_QUIET_SEED = 3


def _steady_samples(
    count: int, *, seed: int, start: datetime, cpu: float = 5.0, transmit: float = 50.0, receive: float = 25.0
) -> list[TelemetrySample]:
    rng = random.Random(seed)
    return [
        TelemetrySample(
            timestamp=start + _STEP * i,
            cpu=cpu + rng.uniform(-1.0, 1.0),
            network_transmit=transmit + rng.uniform(-10.0, 10.0),
            network_receive=receive + rng.uniform(-5.0, 5.0),
        )
        for i in range(count)
    ]


def _spiking_samples(count: int, *, seed: int, start: datetime) -> list[TelemetrySample]:
    # Correlated CPU-and-traffic spike, per ADR-0005 - both features move
    # together, which is what the forest is meant to catch.
    return _steady_samples(count, seed=seed, start=start, cpu=40.0, transmit=400.0, receive=5.0)


def _quiet_history(pod: str, *, seed: int = _QUIET_SEED, count: int = _QUIET_COUNT, start: datetime = _START) -> dict[str, list[TelemetrySample]]:
    return {pod: _steady_samples(count, seed=seed, start=start)}


# --- Hysteresis, tested directly against SignalState ---


def test_fires_after_two_consecutive_anomalous_windows_not_one() -> None:
    state = SignalState()
    state = state.advance(True)
    assert state.active is False

    state = state.advance(True)
    assert state.active is True


def test_a_single_anomalous_window_surrounded_by_normal_raises_nothing() -> None:
    state = SignalState()
    for anomalous in [False, False, True, False, False, False, False]:
        state = state.advance(anomalous)
        assert state.active is False


def test_the_signal_persists_for_three_normal_windows_after_recovery() -> None:
    state = SignalState()
    for _ in range(FIRE_AFTER):
        state = state.advance(True)
    assert state.active is True

    for _ in range(CLEAR_AFTER - 1):
        state = state.advance(False)
        assert state.active is True

    state = state.advance(False)
    assert state.active is False


# --- Per-pod max attribution and the training freeze, through real telemetry ---


def test_a_correlated_spike_raises_an_exposure_signal() -> None:
    series_by_pod = _quiet_history("pod-a")
    quiet_end = series_by_pod["pod-a"][-1].timestamp
    spike = _spiking_samples(20, seed=1, start=quiet_end + _STEP)
    series_by_pod["pod-a"] = series_by_pod["pod-a"] + spike

    signal = detect_workload_exposure_signal(series_by_pod, end=spike[-1].timestamp)

    assert signal.active is True


def test_a_steady_workload_does_not_raise_a_signal() -> None:
    series_by_pod = _quiet_history("pod-a")
    end = series_by_pod["pod-a"][-1].timestamp

    signal = detect_workload_exposure_signal(series_by_pod, end=end)

    assert signal.active is False


def test_spiking_one_replica_of_three_raises_the_signal_on_the_workload() -> None:
    series_by_pod = {
        **_quiet_history("pod-quiet-1", seed=_QUIET_SEED),
        **_quiet_history("pod-quiet-2", seed=_QUIET_SEED + 1),
        **_quiet_history("pod-spiking", seed=_QUIET_SEED + 2),
    }
    quiet_end = series_by_pod["pod-spiking"][-1].timestamp
    spike = _spiking_samples(20, seed=1, start=quiet_end + _STEP)
    series_by_pod["pod-spiking"] = series_by_pod["pod-spiking"] + spike
    # The other two replicas carry on quietly - averaging them in would
    # dilute the spike below any threshold, per ADR-0002, which is exactly
    # what attributing by maximum must avoid.
    series_by_pod["pod-quiet-1"] = series_by_pod["pod-quiet-1"] + _steady_samples(20, seed=10, start=quiet_end + _STEP)
    series_by_pod["pod-quiet-2"] = series_by_pod["pod-quiet-2"] + _steady_samples(20, seed=11, start=quiet_end + _STEP)

    signal = detect_workload_exposure_signal(series_by_pod, end=spike[-1].timestamp)

    assert signal.active is True


def test_a_spike_that_outlives_the_refit_interval_leaves_the_signal_standing() -> None:
    """Per ADR-0003: without the freeze, a compromise that outlasts the
    Baseline's rolling training window would eventually be absorbed into
    "normal" and the signal would clear while the compromise is still
    live. A short `lookback` stands in for the refit interval, so this
    does not need hours of synthetic samples to exercise the same rule -
    just enough for the rolling window to comfortably clear
    MIN_WINDOWS_FOR_FOREST once established, and a spike that outlasts it.
    """
    lookback = timedelta(minutes=20)
    series_by_pod = _quiet_history("pod-a")
    quiet_end = series_by_pod["pod-a"][-1].timestamp
    # A spike twice as long as `lookback` - without the freeze, the
    # rolling training window would slide entirely past the quiet history
    # and start being trained on the spike itself.
    spike = _spiking_samples(80, seed=1, start=quiet_end + _STEP)
    series_by_pod["pod-a"] = series_by_pod["pod-a"] + spike

    signal = detect_workload_exposure_signal(series_by_pod, end=spike[-1].timestamp, lookback=lookback)

    assert signal.active is True
