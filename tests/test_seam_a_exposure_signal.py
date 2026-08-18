"""Seam A: the Exposure Signal badge, driven from synthetic time series
through the fake telemetry port, with no cluster and no Prometheus running.

Drives the real application over HTTP with all five ports faked, per the
spec's testing decisions. `run_detection` is called directly to populate
the signal, the same way `test_seam_a_reconciliation.py` calls
`reconcile_workloads` directly - it is the loop body the periodic detection
loop and any manual trigger would both go through, not a second code path.

Fixture sizes and the spike/seed choice mirror `test_exposure_signal.py` -
see its module docstring for why the spike is long rather than
single-window.
"""

from __future__ import annotations

import random
import sqlite3
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.db import connect
from aidevops.detection import run_detection
from aidevops.domain import ContainerImage, TelemetrySample, TelemetrySeries, Vulnerability, Workload
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel

_START = datetime(2024, 1, 1, 12, 0, 0)
_STEP = timedelta(seconds=30)
_QUIET_COUNT = 45
_QUIET_SEED = 3


@pytest.fixture
def frontend() -> Workload:
    return Workload(
        name="frontend",
        namespace="default",
        replica_pod_names=["frontend-abc"],
        images=[ContainerImage(repository="example/repo", digest="sha256:frontend")],
        externally_reachable=True,
    )


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
    return _steady_samples(count, seed=seed, start=start, cpu=40.0, transmit=400.0, receive=5.0)


def _series(samples: list[TelemetrySample]) -> TelemetrySeries:
    return TelemetrySeries(pod_name="frontend-abc", samples=samples)


def _build_client(frontend: Workload, telemetry: FakeTelemetry) -> tuple[TestClient, sqlite3.Connection, Ports]:
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([frontend]),
        telemetry=telemetry,
        image_scanner=FakeImageScanner(
            {"sha256:frontend": [Vulnerability(
                cve_id="CVE-2024-0001",
                package="libexample",
                installed_version="1.0.0",
                severity="HIGH",
                description="An example vulnerability.",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )]}
        ),
        threat_intel=FakeThreatIntel(),
        triage_model=FakeTriageModel(),
    )
    app = create_app(connection, ports)
    client = TestClient(app)
    # A full reconcile, not just reconcile_workloads - the queue only shows
    # a Workload against a CVE row, which needs the scan-and-score steps
    # too, not only the inventory step.
    client.post("/rescan")
    return client, connection, ports


def test_the_badge_is_unmissable_in_the_queue_when_a_workload_carries_a_signal(frontend: Workload) -> None:
    quiet = _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)
    spike = _spiking_samples(20, seed=1, start=quiet[-1].timestamp + _STEP)
    telemetry = FakeTelemetry({"frontend-abc": _series(quiet + spike)})
    client, connection, ports = _build_client(frontend, telemetry)

    run_detection(connection, ports, now=spike[-1].timestamp)

    response = client.get("/")

    assert response.status_code == 200
    assert "exposure-signal-badge" in response.text
    assert "Exposure Signal" in response.text


def test_no_badge_before_a_signal_has_fired(frontend: Workload) -> None:
    quiet = _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)
    telemetry = FakeTelemetry({"frontend-abc": _series(quiet)})
    client, connection, ports = _build_client(frontend, telemetry)

    run_detection(connection, ports, now=quiet[-1].timestamp)

    response = client.get("/")

    assert response.status_code == 200
    # The CSS class name itself is always present in the page's <style>
    # block - what must be absent is an actual badge element using it.
    assert "Exposure Signal active" not in response.text
    assert 'title="Exposure Signal active"' not in response.text


def test_the_workload_detail_view_also_shows_an_active_signal(frontend: Workload) -> None:
    quiet = _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)
    spike = _spiking_samples(20, seed=1, start=quiet[-1].timestamp + _STEP)
    telemetry = FakeTelemetry({"frontend-abc": _series(quiet + spike)})
    client, connection, ports = _build_client(frontend, telemetry)

    run_detection(connection, ports, now=spike[-1].timestamp)

    response = client.get("/workloads/default/frontend")

    assert response.status_code == 200
    assert "exposure-signal" in response.text
    assert "Exposure Signal active" in response.text


def test_a_spike_that_outlives_the_refit_interval_leaves_the_badge_standing_end_to_end(frontend: Workload) -> None:
    """Per ADR-0003, asserted through the real application: a compromise
    that persists well past the Baseline's rolling training window must
    not be quietly absorbed into "normal" - the badge stays up. A short
    detection lookback stands in for the refit interval, same as the
    equivalent pure test in test_exposure_signal.py.
    """
    quiet = _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)
    spike = _spiking_samples(80, seed=1, start=quiet[-1].timestamp + _STEP)  # twice as long as the lookback below
    telemetry = FakeTelemetry({"frontend-abc": _series(quiet + spike)})
    client, connection, ports = _build_client(frontend, telemetry)

    run_detection(connection, ports, now=spike[-1].timestamp, training_lookback=timedelta(minutes=20))

    response = client.get("/")

    assert "Exposure Signal" in response.text
