"""Seam A: reconciliation, removal, deduplication, and manual rescan.

Drives the real application over HTTP with all five ports faked, per the
spec's testing decisions. The manual rescan endpoint and the periodic
inventory loop both call the same `reconcile` function - these tests only
ever go through the HTTP surface, never the internals directly.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.db import connect
from aidevops.domain import ContainerImage, Vulnerability, Workload
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel


def _image(digest: str, repository: str = "example/repo") -> ContainerImage:
    return ContainerImage(repository=repository, digest=digest)


def _vulnerability(cve_id: str, severity: str = "HIGH") -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        package="libexample",
        installed_version="1.0.0",
        severity=severity,
        description="An example vulnerability.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )


def _build_client(
    cluster_inventory: FakeClusterInventory,
    image_scanner: FakeImageScanner,
    inventory_period_seconds: float = 60.0,
) -> tuple[TestClient, sqlite3.Connection]:
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=cluster_inventory,
        telemetry=FakeTelemetry(),
        image_scanner=image_scanner,
        threat_intel=FakeThreatIntel(),
        triage_model=FakeTriageModel(),
    )
    app = create_app(connection, ports, inventory_period_seconds=inventory_period_seconds)
    return TestClient(app), connection


@pytest.fixture
def frontend() -> Workload:
    return Workload(
        name="frontend",
        namespace="default",
        replica_pod_names=["frontend-abc"],
        images=[_image("sha256:frontend")],
        externally_reachable=True,
    )


@pytest.fixture
def backend() -> Workload:
    return Workload(
        name="backend",
        namespace="default",
        replica_pod_names=["backend-abc"],
        images=[_image("sha256:backend")],
        externally_reachable=False,
    )


def test_manual_rescan_reconciles_workloads_into_the_queue(frontend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend])
    image_scanner = FakeImageScanner({"sha256:frontend": [_vulnerability("CVE-2024-0001")]})
    client, connection = _build_client(cluster_inventory, image_scanner)

    with client:
        response = client.post("/rescan")

        assert response.status_code == 200
        assert "CVE-2024-0001" in response.text
        assert "frontend" in response.text
        assert "HIGH" in response.text
    connection.close()


def test_removed_workload_leaves_the_queue(frontend: Workload, backend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend, backend])
    image_scanner = FakeImageScanner(
        {
            "sha256:frontend": [_vulnerability("CVE-2024-0001")],
            "sha256:backend": [_vulnerability("CVE-2024-0002")],
        }
    )
    client, connection = _build_client(cluster_inventory, image_scanner)

    with client:
        client.post("/rescan")

        cluster_inventory.set_workloads([frontend])
        response = client.post("/rescan")

        assert "CVE-2024-0001" in response.text
        assert "CVE-2024-0002" not in response.text
        assert "backend" not in response.text
    connection.close()


def test_new_workload_appears_without_a_restart(frontend: Workload, backend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend])
    image_scanner = FakeImageScanner(
        {
            "sha256:frontend": [_vulnerability("CVE-2024-0001")],
            "sha256:backend": [_vulnerability("CVE-2024-0002")],
        }
    )
    client, connection = _build_client(cluster_inventory, image_scanner)

    with client:
        first_response = client.post("/rescan")
        assert "CVE-2024-0002" not in first_response.text

        cluster_inventory.set_workloads([frontend, backend])
        second_response = client.post("/rescan")

        assert "CVE-2024-0002" in second_response.text
        assert "backend" in second_response.text
    connection.close()


def test_vulnerabilities_are_deduplicated_by_cve_across_images(frontend: Workload, backend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend, backend])
    shared_cve = _vulnerability("CVE-2024-9999")
    image_scanner = FakeImageScanner(
        {
            "sha256:frontend": [shared_cve],
            "sha256:backend": [shared_cve],
        }
    )
    client, connection = _build_client(cluster_inventory, image_scanner)

    with client:
        response = client.post("/rescan")

        assert response.text.count("CVE-2024-9999") == 1
        assert "frontend" in response.text
        assert "backend" in response.text
    connection.close()


def test_a_digest_already_scanned_is_never_rescanned(frontend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend])
    image_scanner = FakeImageScanner({"sha256:frontend": [_vulnerability("CVE-2024-0001")]})
    client, connection = _build_client(cluster_inventory, image_scanner)

    with client:
        client.post("/rescan")
        client.post("/rescan")

        # Observable rather than assumed, per the spec: the scanner port's
        # own call record shows the digest was scanned exactly once even
        # though the loop body ran twice.
        assert image_scanner.scanned_digests == ["sha256:frontend"]
    connection.close()


def test_a_shared_digest_discovered_by_two_workloads_is_scanned_once(frontend: Workload, backend: Workload) -> None:
    shared_image = _image("sha256:shared")
    frontend_sharing = Workload(
        name=frontend.name,
        namespace=frontend.namespace,
        replica_pod_names=frontend.replica_pod_names,
        images=[shared_image],
        externally_reachable=frontend.externally_reachable,
    )
    backend_sharing = Workload(
        name=backend.name,
        namespace=backend.namespace,
        replica_pod_names=backend.replica_pod_names,
        images=[shared_image],
        externally_reachable=backend.externally_reachable,
    )
    cluster_inventory = FakeClusterInventory([frontend_sharing, backend_sharing])
    image_scanner = FakeImageScanner({"sha256:shared": [_vulnerability("CVE-2024-0003")]})
    client, connection = _build_client(cluster_inventory, image_scanner)

    with client:
        client.post("/rescan")

        # Both Workloads reference the same, previously-unknown digest in
        # the same reconcile pass - it must still be scanned only once.
        assert image_scanner.scanned_digests == ["sha256:shared"]
    connection.close()


def test_a_first_scan_in_progress_is_shown_rather_than_an_empty_queue(frontend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend])
    image_scanner = FakeImageScanner()
    client, connection = _build_client(cluster_inventory, image_scanner)

    # Simulates the moment between the two reconcile phases: the workload
    # and its image are known, but scanning has not written a result yet
    # (see aidevops.reconcile.scan_pending_images). Deliberately not using
    # `with client:` here - that starts the periodic background loop,
    # which would race this same call for the connection.
    from aidevops.reconcile import reconcile_workloads

    reconcile_workloads(connection, client.app.state.ports, [frontend])

    response = client.get("/")

    assert "scanning" in response.text.lower()
    assert "The queue is empty." not in response.text
    connection.close()


def test_the_periodic_loop_runs_the_same_reconciliation(frontend: Workload) -> None:
    cluster_inventory = FakeClusterInventory([frontend])
    image_scanner = FakeImageScanner({"sha256:frontend": [_vulnerability("CVE-2024-0001")]})
    client, connection = _build_client(cluster_inventory, image_scanner, inventory_period_seconds=0.02)

    with client:
        deadline = time.monotonic() + 2.0
        found = False
        while time.monotonic() < deadline:
            if "CVE-2024-0001" in client.get("/").text:
                found = True
                break
            time.sleep(0.05)

        assert found, "the periodic inventory loop never reconciled the fake workload"
    connection.close()
