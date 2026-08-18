"""Turns per-pod telemetry into a Workload's Exposure Signal.

Three rules from the ADRs, all asserted here:

- Detection runs per pod; attribution to the Workload aggregates by
  **maximum, not mean** (ADR-0002) - each replica's window is scored
  against the Workload's shared, pooled Baseline on its own, and the
  Workload is anomalous at a given moment if any one replica is, so a
  single compromised replica of three is never diluted below threshold by
  its quiet siblings.
- The signal fires after 2 consecutive anomalous windows and clears after 3
  consecutive normal ones. Asymmetric on purpose - a missed detection is
  worse than a slow all-clear, and a flapping signal would thrash the
  Triage cache.
- A Workload's Baseline training window freezes for as long as its
  Exposure Signal is active (ADR-0003), so a sustained compromise cannot be
  absorbed into its own Baseline and silently clear its own alert. The
  freeze point is the start of the window that began the firing streak, so
  none of the anomalous data ever enters training.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from aidevops.baseline import STEP, TRAINING_LOOKBACK, WINDOW, WindowFeatures, compute_window_features, train_baseline
from aidevops.domain import TelemetrySample

FIRE_AFTER = 2
CLEAR_AFTER = 3


@dataclass(frozen=True)
class SignalState:
    """The hysteresis state driving one Workload's Exposure Signal."""

    active: bool = False
    consecutive_anomalous: int = 0
    consecutive_normal: int = 0

    def advance(self, anomalous: bool) -> "SignalState":
        if anomalous:
            consecutive_anomalous = self.consecutive_anomalous + 1
            consecutive_normal = 0
        else:
            consecutive_anomalous = 0
            consecutive_normal = self.consecutive_normal + 1

        active = self.active
        if not active and consecutive_anomalous >= FIRE_AFTER:
            active = True
        elif active and consecutive_normal >= CLEAR_AFTER:
            active = False

        return SignalState(active=active, consecutive_anomalous=consecutive_anomalous, consecutive_normal=consecutive_normal)


@dataclass(frozen=True)
class ExposureSignal:
    active: bool
    # How far outside normal the most recently evaluated window sits, per
    # Baseline.anomaly_magnitude - 0.0 whenever inactive, so the Triage
    # prompt never carries a stale magnitude from a cleared incident.
    magnitude: float = 0.0
    # The triggering window and the moment the signal fired - the start of
    # the first of the FIRE_AFTER consecutive anomalous windows, and the end
    # of the last one, for the Workload detail chart to shade and mark (see
    # aidevops.charts). Both None whenever inactive, same "no stale value
    # from a cleared incident" reasoning as `magnitude`.
    window_start: datetime | None = None
    fired_at: datetime | None = None


def detect_workload_exposure_signal(
    series_by_pod: dict[str, list[TelemetrySample]],
    end: datetime,
    lookback: timedelta = TRAINING_LOOKBACK,
    window: timedelta = WINDOW,
    step: timedelta = STEP,
) -> ExposureSignal:
    """Walks every replica's windows in chronological order, folding them
    through the hysteresis state machine to the Workload's current Exposure
    Signal state.

    Recomputed from scratch on every call from the full series pooled
    per-replica - there is no incremental state to keep in sync, only the
    telemetry itself, same as `aidevops.baseline.train_workload_baseline`.
    `end` and `lookback` are the anchor and width of the Baseline's rolling
    training window before any freeze applies.
    """
    windows_by_pod: dict[str, list[WindowFeatures]] = {
        pod_name: compute_window_features(samples, window=window, step=step) for pod_name, samples in series_by_pod.items()
    }
    step_ends = sorted({w.end for pod_windows in windows_by_pod.values() for w in pod_windows})

    state = SignalState()
    frozen_training_end: datetime | None = None
    streak_start: datetime | None = None
    step_magnitude = 0.0
    fired_window_start: datetime | None = None
    fired_at: datetime | None = None

    for step_end in step_ends:
        training_end = frozen_training_end if state.active else step_end
        training_start = training_end - lookback
        pooled_training_windows = [
            w
            for pod_windows in windows_by_pod.values()
            for w in pod_windows
            if training_start <= w.start and w.end <= training_end
        ]
        baseline = train_baseline(pooled_training_windows)

        pod_windows_here = [w for pod_windows in windows_by_pod.values() for w in pod_windows if w.end == step_end]
        # Per ADR-0002: each replica's window is scored on its own against
        # the shared pooled Baseline, and the Workload is anomalous if any
        # one of them is - the maximum, not an average across replicas.
        step_anomalous = any(baseline.is_anomalous(w) for w in pod_windows_here)
        # Same per-pod maximum for magnitude, so one severely misbehaving
        # replica is never diluted by its quiet siblings here either.
        step_magnitude = max((baseline.anomaly_magnitude(w) for w in pod_windows_here), default=0.0)

        if not step_anomalous:
            streak_start = None
        elif streak_start is None:
            streak_start = step_end - window

        was_active = state.active
        state = state.advance(step_anomalous)

        if state.active and not was_active:
            frozen_training_end = streak_start
            fired_window_start = streak_start
            fired_at = step_end
        elif not state.active and was_active:
            frozen_training_end = None
            fired_window_start = None
            fired_at = None

    return ExposureSignal(
        active=state.active,
        magnitude=step_magnitude if state.active else 0.0,
        window_start=fired_window_start if state.active else None,
        fired_at=fired_at if state.active else None,
    )
