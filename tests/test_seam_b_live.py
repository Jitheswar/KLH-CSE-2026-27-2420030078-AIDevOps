"""Seam B: the project's only two tests against a real cluster, and its
only two quantitative results.

Seam A's fakes agree with the code about what a pod, a scan, or a
Prometheus series look like - because both are written from the same
assumptions. These tests exist to catch what that agreement cannot: whether
the cAdvisor series `PrometheusTelemetry` queries are the ones Prometheus
actually holds, whether pods carry the fields `RealClusterInventory` assumes
of them, and whether the detector's hysteresis behaves the same way against
real, noisy telemetry as it does against synthetic series.

Requires a cluster brought up with `make cluster-up seed prometheus-up`.
`kubectl` and `kind` must be on PATH (`make tools`) - the suite shells out
to `make scenario-miner-start`/`scenario-miner-stop`, which need both; it
never shells out to Trivy itself. Not part of the default `make test` run;
see `make test-live` and the `live` marker registered in pyproject.toml.

Both tests share one continuous monitoring session (`monitoring_session`
below) rather than each re-running their own: the detector's Baseline needs
roughly `MIN_WINDOWS_FOR_FOREST` windows of real history before it can call
anything anomalous at all (see aidevops.baseline), so watching a live
cluster for long enough to trust a "no false positives" result already
produces a warmed-up Baseline the Scenario test can detect against
immediately, instead of paying that warm-up cost twice.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from aidevops.app import Ports
from aidevops.baseline import MIN_WINDOWS_FOR_FOREST, STEP
from aidevops.config import Settings
from aidevops.detection import detect_signal_for_workload
from aidevops.ports.cluster_inventory import RealClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import PrometheusTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel

pytestmark = pytest.mark.live

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = REPO_ROOT / "results" / "seam-b-live-results.json"
SCENARIO_STATE_FILE = REPO_ROOT / "scenarios" / "miner" / ".state" / "started-at"
SCENARIO_NAMESPACE = "web"
SCENARIO_WORKLOAD = "nginx-legacy"

# The Baseline needs this many pooled windows before it will call anything
# anomalous (see aidevops.baseline.train_baseline) - below that, every
# window is reported normal by definition, false positives included. This
# is the minimum real wall-clock time a single-replica Workload's own
# history takes to produce that many windows, plus a tail long enough to
# watch an *established* Baseline behave, not just to reach one.
_WARMUP_SECONDS = MIN_WINDOWS_FOR_FOREST * STEP.total_seconds()
_ESTABLISHED_TAIL_SECONDS = 5 * 60
QUIET_PHASE_SECONDS = _WARMUP_SECONDS + _ESTABLISHED_TAIL_SECONDS

# Two anomalous windows, STEP apart, is the earliest the hysteresis can
# possibly fire (aidevops.exposure_signal.FIRE_AFTER) - this bound is a
# generous multiple of that floor to allow for a real window's average
# needing to accumulate enough scenario-tainted samples to tip anomalous.
DETECTION_BOUND_SECONDS = 6 * 60
DETECTION_POLL_TIMEOUT_SECONDS = 15 * 60

POLL_INTERVAL_SECONDS = STEP.total_seconds()


@dataclass(frozen=True)
class MonitoringSession:
    false_positive_count: int
    quiet_observations: int
    detection_latency_seconds: float | None


def _skip_unless_live_cluster_reachable(prometheus_url: str) -> None:
    try:
        response = httpx.get(f"{prometheus_url}/-/ready", timeout=5.0)
        response.raise_for_status()
    except httpx.HTTPError as error:
        pytest.skip(
            f"Prometheus not reachable at {prometheus_url}: {error}. "
            "Run `make cluster-up seed prometheus-up` before `make test-live`."
        )

    try:
        RealClusterInventory()
    except Exception as error:  # noqa: BLE001 - any failure here means "no live cluster"
        pytest.skip(f"Kubernetes API not reachable: {error}. Run `make cluster-up seed prometheus-up` first.")


def _current_pod_names(inventory: RealClusterInventory) -> list[str] | None:
    """Looked up fresh on every tick, not resolved once - the miner
    Scenario's injection patches the Deployment's pod template, which
    Kubernetes answers with a rolling replacement onto a new pod name, the
    same "Workload survives pod restarts and rescheduling" fact
    `aidevops.detection.list_workloads_with_pods` relies on in production by
    re-reading current pods every detection cycle rather than caching them.
    """
    for workload in inventory.list_workloads():
        if workload.namespace == SCENARIO_NAMESPACE and workload.name == SCENARIO_WORKLOAD:
            return workload.replica_pod_names
    return None


def _check_signal(ports: Ports) -> bool | None:
    """One detection check against the live telemetry backend. Returns
    whether the Workload's Exposure Signal is active right now, or None if
    the Workload's pods could not be resolved or telemetry was unavailable
    for this tick - `detect_signal_for_workload` already degrades a
    Prometheus hiccup to None rather than raising, the same philosophy
    `aidevops.detection.run_detection` uses in production; callers here
    just skip a None tick and try again on the next one.
    """
    pod_names = _current_pod_names(ports.cluster_inventory)
    if not pod_names:
        return None
    signal = detect_signal_for_workload(ports, pod_names, datetime.now())
    return None if signal is None else signal.active


def _run_scenario_target(target: str) -> None:
    subprocess.run(["make", target], cwd=REPO_ROOT, check=True, capture_output=True, text=True)


def _read_scenario_started_at() -> datetime:
    raw = SCENARIO_STATE_FILE.read_text().strip()
    started_at_utc = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    # aidevops.detection works in naive local time throughout (see
    # PrometheusTelemetry and aidevops.app, both `datetime.now()` /
    # `datetime.fromtimestamp()`) - converted here so latency arithmetic
    # against `datetime.now()` compares like with like.
    return started_at_utc.astimezone().replace(tzinfo=None)


def _write_results(session: MonitoringSession) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(
        json.dumps(
            {
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "quiet_phase_seconds": QUIET_PHASE_SECONDS,
                "quiet_observations": session.quiet_observations,
                "false_positives": session.false_positive_count,
                "detection_latency_seconds": session.detection_latency_seconds,
                "detection_bound_seconds": DETECTION_BOUND_SECONDS,
            },
            indent=2,
        )
        + "\n"
    )


@pytest.fixture(scope="module")
def monitoring_session() -> MonitoringSession:
    settings = Settings.from_env()
    _skip_unless_live_cluster_reachable(settings.prometheus_url)

    ports = Ports(
        cluster_inventory=RealClusterInventory(),
        telemetry=PrometheusTelemetry(settings.prometheus_url),
        image_scanner=FakeImageScanner(),
        threat_intel=FakeThreatIntel(),
        triage_model=FakeTriageModel(),
    )
    if _current_pod_names(ports.cluster_inventory) is None:
        pytest.fail(
            f"Workload {SCENARIO_NAMESPACE}/{SCENARIO_WORKLOAD} not found - run `make seed` before `make test-live`."
        )

    # Quiet phase: long enough for the Baseline to warm up on this
    # Workload's own real telemetry and then be watched, established, for a
    # while - see QUIET_PHASE_SECONDS above.
    false_positives = 0
    observations = 0
    quiet_deadline = time.monotonic() + QUIET_PHASE_SECONDS
    while time.monotonic() < quiet_deadline:
        active = _check_signal(ports)
        if active is not None:
            observations += 1
            if active:
                false_positives += 1
        time.sleep(POLL_INTERVAL_SECONDS)

    # Scenario phase: inject the miner Scenario into the now-warmed-up
    # Workload and measure how long the Exposure Signal takes to fire,
    # against the Scenario's own recorded start time as ground truth (see
    # scenarios/README.md). Injection patches the Deployment's pod
    # template, which replaces the pod under a new name - `_check_signal`
    # re-resolves it every tick rather than reusing the quiet phase's pod.
    detection_latency_seconds: float | None = None
    try:
        _run_scenario_target("scenario-miner-start")
        scenario_started_at = _read_scenario_started_at()

        poll_deadline = time.monotonic() + DETECTION_POLL_TIMEOUT_SECONDS
        while time.monotonic() < poll_deadline:
            if _check_signal(ports):
                detection_latency_seconds = (datetime.now() - scenario_started_at).total_seconds()
                break
            time.sleep(POLL_INTERVAL_SECONDS)
    finally:
        _run_scenario_target("scenario-miner-stop")

    session = MonitoringSession(
        false_positive_count=false_positives,
        quiet_observations=observations,
        detection_latency_seconds=detection_latency_seconds,
    )
    _write_results(session)
    return session


def test_quiet_cluster_raises_no_exposure_signal(monitoring_session: MonitoringSession) -> None:
    assert monitoring_session.quiet_observations > 0
    assert monitoring_session.false_positive_count == 0


def test_miner_scenario_raises_exposure_signal_within_bound(monitoring_session: MonitoringSession) -> None:
    assert monitoring_session.detection_latency_seconds is not None, (
        f"Exposure Signal never fired within {DETECTION_POLL_TIMEOUT_SECONDS}s of the Scenario starting"
    )
    assert monitoring_session.detection_latency_seconds <= DETECTION_BOUND_SECONDS
