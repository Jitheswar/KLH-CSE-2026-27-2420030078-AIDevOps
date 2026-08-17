"""Seam A: the pre-filter and base Contextual Priority, ticket 05.

Drives the real application over HTTP with all five ports faked, per the
spec's testing decisions. The load-bearing assertion in this file is the
one the spec calls out by name: fed identical Severities, the Candidate
Set the pre-filter produces must differ by EPSS, KEV membership and fix
availability alone - proof it is not a Severity sort wearing a hat.
"""

from __future__ import annotations

import re
import sqlite3

from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.db import connect
from aidevops.domain import ContainerImage, ThreatIntel, Vulnerability, Workload
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel


def _vulnerability(cve_id: str, severity: str = "HIGH", fixed_version: str | None = "1.0.1") -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        package="libexample",
        installed_version="1.0.0",
        severity=severity,
        description="An example vulnerability.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        fixed_version=fixed_version,
    )


def _build_client(
    vulnerabilities: list[Vulnerability], intel_by_cve: dict[str, ThreatIntel]
) -> tuple[TestClient, sqlite3.Connection]:
    workload = Workload(
        name="fleet",
        namespace="default",
        replica_pod_names=["fleet-abc"],
        images=[ContainerImage(repository="example/repo", digest="sha256:fleet")],
        externally_reachable=False,
    )
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([workload]),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner({"sha256:fleet": vulnerabilities}),
        threat_intel=FakeThreatIntel(intel_by_cve),
        triage_model=FakeTriageModel(),
    )
    app = create_app(connection, ports)
    return TestClient(app), connection


def test_identical_severities_produce_a_candidate_set_shaped_by_epss_kev_and_fix_alone() -> None:
    # 60 Vulnerabilities, every one HIGH Severity - a Severity sort could
    # not tell any of these apart, let alone cut to fifty in a way that
    # means anything.
    strong_signal = [
        _vulnerability(f"CVE-2024-{i:04d}", severity="HIGH", fixed_version="1.0.1") for i in range(50)
    ]
    weak_signal = [
        _vulnerability(f"CVE-2025-{i:04d}", severity="HIGH", fixed_version=None) for i in range(10)
    ]
    intel_by_cve = {
        **{v.cve_id: ThreatIntel(cve_id=v.cve_id, epss_score=0.9, kev_listed=True) for v in strong_signal},
        **{v.cve_id: ThreatIntel(cve_id=v.cve_id, epss_score=0.0, kev_listed=False) for v in weak_signal},
    }
    client, connection = _build_client(strong_signal + weak_signal, intel_by_cve)

    with client:
        response = client.post("/rescan")

        for vulnerability in strong_signal:
            assert vulnerability.cve_id in response.text
        for vulnerability in weak_signal:
            assert vulnerability.cve_id not in response.text
    connection.close()


def test_higher_epss_alone_moves_a_vulnerability_into_the_candidate_set_over_identical_severity_peers() -> None:
    # 51 Vulnerabilities, all HIGH Severity, all fixed, none KEV-listed -
    # Severity, KEV and fix availability are identical across the board.
    # EPSS is the only signal that differs, and it alone must decide which
    # fifty make the cut.
    vulnerabilities = [_vulnerability(f"CVE-2024-{i:04d}") for i in range(51)]
    low_epss_outlier = vulnerabilities[0]
    intel_by_cve = {v.cve_id: ThreatIntel(cve_id=v.cve_id, epss_score=0.5, kev_listed=False) for v in vulnerabilities}
    intel_by_cve[low_epss_outlier.cve_id] = ThreatIntel(cve_id=low_epss_outlier.cve_id, epss_score=0.0, kev_listed=False)

    client, connection = _build_client(vulnerabilities, intel_by_cve)

    with client:
        response = client.post("/rescan")

        assert low_epss_outlier.cve_id not in response.text
        for vulnerability in vulnerabilities[1:]:
            assert vulnerability.cve_id in response.text
    connection.close()


def test_queue_ranks_by_base_contextual_priority_with_severity_shown_separately() -> None:
    low_priority = _vulnerability("CVE-2024-0001", severity="LOW", fixed_version=None)
    high_priority = _vulnerability("CVE-2024-0002", severity="CRITICAL", fixed_version="1.0.1")
    intel_by_cve = {
        low_priority.cve_id: ThreatIntel(cve_id=low_priority.cve_id, epss_score=0.0, kev_listed=False),
        high_priority.cve_id: ThreatIntel(cve_id=high_priority.cve_id, epss_score=0.99, kev_listed=True),
    }
    client, connection = _build_client([low_priority, high_priority], intel_by_cve)

    with client:
        response = client.post("/rescan")

        assert "CRITICAL" in response.text
        assert "LOW" in response.text
        assert response.text.index(high_priority.cve_id) < response.text.index(low_priority.cve_id)
    connection.close()


def test_displayed_severity_matches_the_worst_severity_the_score_was_based_on() -> None:
    # Same CVE, two images, two different reported Severities - the
    # pre-filter scores this CVE off the worst one (CRITICAL), per
    # aidevops.candidates._dedupe_by_cve, so the queue must show CRITICAL
    # next to it rather than whichever image's row the join visits first.
    cve_id = "CVE-2024-7777"
    low_severity_image = ContainerImage(repository="example/repo", digest="sha256:low")
    high_severity_image = ContainerImage(repository="example/repo", digest="sha256:high")
    low_workload = Workload(
        name="low-severity-workload",
        namespace="default",
        replica_pod_names=["low-abc"],
        images=[low_severity_image],
        externally_reachable=False,
    )
    high_workload = Workload(
        name="high-severity-workload",
        namespace="default",
        replica_pod_names=["high-abc"],
        images=[high_severity_image],
        externally_reachable=False,
    )
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([low_workload, high_workload]),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner(
            {
                low_severity_image.digest: [_vulnerability(cve_id, severity="MEDIUM")],
                high_severity_image.digest: [_vulnerability(cve_id, severity="CRITICAL")],
            }
        ),
        threat_intel=FakeThreatIntel({cve_id: ThreatIntel(cve_id=cve_id, epss_score=0.5, kev_listed=False)}),
        triage_model=FakeTriageModel(),
    )
    app = create_app(connection, ports)
    client = TestClient(app)

    with client:
        response = client.post("/rescan")

        row_start = response.text.index(cve_id)
        row = response.text[row_start : row_start + 400]
        assert "CRITICAL" in row
        assert "MEDIUM" not in row
    connection.close()


def test_a_vulnerability_appearing_in_five_images_is_triaged_and_scored_once() -> None:
    shared_cve = _vulnerability("CVE-2024-9999")
    images = [ContainerImage(repository="example/repo", digest=f"sha256:image{i}") for i in range(5)]
    workloads = [
        Workload(
            name=f"workload-{i}",
            namespace="default",
            replica_pod_names=[f"workload-{i}-abc"],
            images=[image],
            externally_reachable=False,
        )
        for i, image in enumerate(images)
    ]
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory(workloads),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner({image.digest: [shared_cve] for image in images}),
        threat_intel=FakeThreatIntel({shared_cve.cve_id: ThreatIntel(cve_id=shared_cve.cve_id, epss_score=0.5, kev_listed=False)}),
        triage_model=FakeTriageModel(),
    )
    app = create_app(connection, ports)
    client = TestClient(app)

    with client:
        response = client.post("/rescan")

        assert response.text.count(shared_cve.cve_id) == 1
        for workload in workloads:
            assert workload.name in response.text
    connection.close()


def test_an_unchanged_cluster_produces_an_identical_queue_on_two_consecutive_loads() -> None:
    vulnerabilities = [_vulnerability(f"CVE-2024-{i:04d}", severity="HIGH") for i in range(20)]
    intel_by_cve = {
        v.cve_id: ThreatIntel(cve_id=v.cve_id, epss_score=0.1 * (i % 10), kev_listed=i % 3 == 0)
        for i, v in enumerate(vulnerabilities)
    }
    client, connection = _build_client(vulnerabilities, intel_by_cve)

    with client:
        client.post("/rescan")
        first_load = client.get("/").text
        second_load = client.get("/").text

        assert _rows_in_order(first_load) == _rows_in_order(second_load)
    connection.close()


def _rows_in_order(html: str) -> list[str]:
    return re.findall(r"CVE-2024-\d{4}", html)
