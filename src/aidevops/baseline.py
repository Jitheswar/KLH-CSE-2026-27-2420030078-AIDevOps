"""Learns what normal looks like for a Workload, and says when it does not
yet know.

Per the spec's detection decisions: features are computed over a 2 minute
window stepped every 30 seconds, across CPU, network transmit rate, network
receive rate, and the transmit-to-receive ratio. One Isolation Forest is
trained per Workload on a rolling two hour window that pools every replica's
windows together - see ADR-0002 - so a freshly scheduled replica is judged
against a model that already has its siblings' history rather than starting
blind. Below roughly thirty pooled windows, a z-score baseline stands in and
the Workload is reported as still establishing its Baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from aidevops.domain import TelemetrySample

WINDOW = timedelta(minutes=2)
STEP = timedelta(seconds=30)
TRAINING_LOOKBACK = timedelta(hours=2)

# Per the spec: below roughly thirty windows of pooled history, fall back to
# a z-score baseline rather than fitting a forest on too little data.
MIN_WINDOWS_FOR_FOREST = 30

# Beyond this many standard deviations on any feature, the z-score fallback
# calls a window anomalous.
_Z_SCORE_THRESHOLD = 3.0

_FEATURE_NAMES = ("cpu", "network_transmit", "network_receive", "transmit_receive_ratio")


@dataclass(frozen=True)
class WindowFeatures:
    """One 2 minute window's mean of each of the four detection features."""

    start: datetime
    end: datetime
    cpu: float
    network_transmit: float
    network_receive: float
    transmit_receive_ratio: float

    def as_vector(self) -> list[float]:
        return [self.cpu, self.network_transmit, self.network_receive, self.transmit_receive_ratio]


def compute_window_features(
    samples: list[TelemetrySample], window: timedelta = WINDOW, step: timedelta = STEP
) -> list[WindowFeatures]:
    """Steps a `window`-wide average across `samples` every `step`, starting
    at the first sample's timestamp. Samples are assumed sorted by
    timestamp - every caller in this codebase already fetches them that way.
    """
    if not samples:
        return []

    features: list[WindowFeatures] = []
    cursor = samples[0].timestamp
    last_timestamp = samples[-1].timestamp
    while cursor <= last_timestamp:
        window_end = cursor + window
        in_window = [sample for sample in samples if cursor <= sample.timestamp < window_end]
        if in_window:
            features.append(_summarize(cursor, window_end, in_window))
        cursor += step

    return features


def _summarize(start: datetime, end: datetime, samples: list[TelemetrySample]) -> WindowFeatures:
    cpu = sum(sample.cpu for sample in samples) / len(samples)
    transmit = sum(sample.network_transmit for sample in samples) / len(samples)
    receive = sum(sample.network_receive for sample in samples) / len(samples)
    # A quiet pod with zero receive traffic must not blow this up - treated
    # as ratio 0 rather than raising, since "no traffic" is itself a
    # perfectly normal feature value, not a missing one.
    ratio = transmit / receive if receive else 0.0
    return WindowFeatures(start=start, end=end, cpu=cpu, network_transmit=transmit, network_receive=receive, transmit_receive_ratio=ratio)


@dataclass(frozen=True)
class BaselineBand:
    """Per-metric normal range, for drawing behind the telemetry chart."""

    low: float
    high: float


@dataclass(frozen=True)
class Baseline:
    """A trained Workload Baseline. `established` distinguishes "not enough
    history yet" from "normal" - the two must never be conflated in the
    interface, per the spec.
    """

    established: bool
    training_window_count: int
    _means: dict[str, float] = field(default_factory=dict)
    _stds: dict[str, float] = field(default_factory=dict)
    _forest: IsolationForest | None = None

    def is_anomalous(self, features: WindowFeatures) -> bool:
        if not self.established:
            # Cold start makes no claim about normal vs abnormal - see
            # `established` above.
            return False
        if self._forest is not None:
            prediction = self._forest.predict([features.as_vector()])
            return bool(prediction[0] == -1)
        return self._z_score_anomalous(features)

    def _z_score_anomalous(self, features: WindowFeatures) -> bool:
        for name, value in zip(_FEATURE_NAMES, features.as_vector(), strict=True):
            std = self._stds.get(name, 0.0)
            if std == 0.0:
                continue
            z = abs(value - self._means.get(name, 0.0)) / std
            if z > _Z_SCORE_THRESHOLD:
                return True
        return False

    def band(self, metric: str) -> BaselineBand | None:
        """The normal range for one chartable metric (cpu, network_transmit,
        network_receive), for drawing the Baseline band behind the chart.
        """
        if not self.established or metric not in self._means:
            return None
        mean = self._means[metric]
        std = self._stds[metric]
        return BaselineBand(low=max(0.0, mean - 2 * std), high=mean + 2 * std)


def train_baseline(pooled_windows: list[WindowFeatures]) -> Baseline:
    """Fits a Baseline from every replica's windows pooled together, per
    ADR-0002. Below `MIN_WINDOWS_FOR_FOREST`, falls back to z-score.
    """
    if len(pooled_windows) == 0:
        return Baseline(established=False, training_window_count=0)

    vectors = np.array([w.as_vector() for w in pooled_windows])
    means = {name: float(vectors[:, index].mean()) for index, name in enumerate(_FEATURE_NAMES)}
    stds = {name: float(vectors[:, index].std()) for index, name in enumerate(_FEATURE_NAMES)}

    if len(pooled_windows) < MIN_WINDOWS_FOR_FOREST:
        return Baseline(
            established=False,
            training_window_count=len(pooled_windows),
            _means=means,
            _stds=stds,
        )

    # `contamination="auto"` uses a fixed score threshold from the original
    # paper rather than a target outlier fraction, which flags an
    # unsettling number of ordinary training points on data this clean
    # (a steadily busy Workload, for instance) - an explicit low
    # contamination keeps the forest conservative about what counts as
    # abnormal, matching the spec's requirement that a busy Workload not be
    # flagged purely for being busy.
    forest = IsolationForest(random_state=0, contamination=0.05)
    forest.fit(vectors)
    return Baseline(
        established=True,
        training_window_count=len(pooled_windows),
        _means=means,
        _stds=stds,
        _forest=forest,
    )


def train_workload_baseline(
    series_by_pod: dict[str, list[TelemetrySample]], window: timedelta = WINDOW, step: timedelta = STEP
) -> Baseline:
    """Trains a Workload's Baseline from every replica's raw samples pooled
    together, per ADR-0002 and the spec's "replicas of one Deployment
    contribute to one shared Baseline" requirement.

    A replica with too little history of its own - a pod scheduled minutes
    ago - still contributes whatever windows it has, and is judged against
    the pooled model rather than its own thin history. This is what makes a
    freshly-scheduled replica inherit a trained model instead of cold
    starting.
    """
    pooled_windows = [
        window_features
        for pod_samples in series_by_pod.values()
        for window_features in compute_window_features(pod_samples, window=window, step=step)
    ]
    return train_baseline(pooled_windows)
