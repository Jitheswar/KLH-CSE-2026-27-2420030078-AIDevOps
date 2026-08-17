"""Seam A: the Workload detail view, driven from synthetic time series
through the fake telemetry port, with no Prometheus running.

Drives the real application over HTTP with all five ports faked, per the
spec's testing decisions.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.db import connect
from aidevops.domain import ContainerImage, TelemetrySample, TelemetrySeries, Vulnerability, Workload
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel


@pytest.fixture
def frontend() -> Workload:
    return Workload(
        name="frontend",
        namespace="default",
        replica_pod_names=["frontend-abc"],
        images=[ContainerImage(repository="example/repo", digest="sha256:frontend")],
        externally_reachable=True,
    )


def _client_with_telemetry(frontend: Workload, telemetry: FakeTelemetry) -> tuple[TestClient, FastAPI]:
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
    client.post("/rescan")
    return client, app


def _synthetic_series() -> TelemetrySeries:
    now = datetime(2024, 1, 1, 12, 0, 0)
    return TelemetrySeries(
        pod_name="frontend-abc",
        samples=[
            TelemetrySample(
                timestamp=now - timedelta(minutes=minutes),
                cpu=float(minutes),
                network_transmit=float(minutes) * 10,
                network_receive=float(minutes) * 5,
            )
            for minutes in range(10, 0, -1)
        ],
    )


def test_workload_detail_reachable_from_a_queue_row(frontend: Workload) -> None:
    telemetry = FakeTelemetry({"frontend-abc": _synthetic_series()})
    client, _ = _client_with_telemetry(frontend, telemetry)

    queue_response = client.get("/")
    assert '/workloads/default/frontend"' in queue_response.text

    detail_response = client.get("/workloads/default/frontend")
    assert detail_response.status_code == 200
    assert "<svg" in detail_response.text
    assert "Not enough data yet." not in detail_response.text


def test_workload_detail_404s_for_an_unknown_workload(frontend: Workload) -> None:
    telemetry = FakeTelemetry({"frontend-abc": _synthetic_series()})
    client, _ = _client_with_telemetry(frontend, telemetry)

    response = client.get("/workloads/default/does-not-exist")

    assert response.status_code == 404


def test_workload_detail_degrades_when_telemetry_is_unavailable(frontend: Workload) -> None:
    telemetry = FakeTelemetry(available=False)
    client, _ = _client_with_telemetry(frontend, telemetry)

    detail_response = client.get("/workloads/default/frontend")
    assert detail_response.status_code == 200
    assert "telemetry-unavailable" in detail_response.text
    assert "<svg" not in detail_response.text

    # The queue itself is untouched by a telemetry outage - only the chart
    # degrades, per the spec.
    queue_response = client.get("/")
    assert queue_response.status_code == 200
    assert "CVE-2024-0001" in queue_response.text
