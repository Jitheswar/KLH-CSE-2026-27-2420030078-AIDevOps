"""Seam A: Triage, adjustment, and toggle - ticket 06.

Drives the real application over HTTP with all five ports faked, per the
spec's testing decisions. Per ADR-0004, Contextual Priority is a
deterministic base plus a bounded model adjustment, stored separately, so
the toggle is a re-render rather than a recomputation.

Deliberately not using `with client:` in most of these - that starts the
periodic background loop, which would race the explicit `/rescan` call
below for the connection, the same reasoning
`tests/test_seam_a_reconciliation.py::test_a_first_scan_in_progress_is_shown_rather_than_an_empty_queue`
already documents. Each test still exercises the real `/rescan` endpoint
end to end; it just doesn't also start a loop it isn't testing.
"""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.candidates import base_priority
from aidevops.db import connect
from aidevops.domain import ContainerImage, ThreatIntel, TriageAdjustment, Vulnerability, Workload
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel
from aidevops.queue import get_queue_rows


def _vulnerability(cve_id: str, severity: str = "HIGH") -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        package="libexample",
        installed_version="1.0.0",
        severity=severity,
        description="An example vulnerability.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        fixed_version="1.0.1",
    )


def _workload(name: str, digest: str, *, externally_reachable: bool = False) -> Workload:
    return Workload(
        name=name,
        namespace="default",
        replica_pod_names=[f"{name}-abc"],
        images=[ContainerImage(repository="example/repo", digest=digest)],
        externally_reachable=externally_reachable,
    )


def _build_client(
    workloads: list[Workload],
    vulnerabilities_by_digest: dict[str, list[Vulnerability]],
    triage_model: FakeTriageModel,
    intel_by_cve: dict[str, ThreatIntel] | None = None,
) -> tuple[TestClient, sqlite3.Connection]:
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory(workloads),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner(vulnerabilities_by_digest),
        threat_intel=FakeThreatIntel(intel_by_cve or {}),
        triage_model=triage_model,
    )
    app = create_app(connection, ports)
    return TestClient(app), connection


def test_rationale_renders_inline_in_the_queue_row() -> None:
    workload = _workload("fleet", "sha256:fleet")
    triage_model = FakeTriageModel(
        TriageAdjustment(adjustment=10, rationale="This CVE reaches an internet-facing Workload right now.")
    )
    client, connection = _build_client(
        [workload], {"sha256:fleet": [_vulnerability("CVE-2024-0001")]}, triage_model
    )

    response = client.post("/rescan")

    # Inline in the row, not behind a click - the rationale text is
    # present in the page response itself.
    assert "This CVE reaches an internet-facing Workload right now." in response.text
    connection.close()


def test_the_adjustment_moves_contextual_priority_away_from_the_base_score() -> None:
    workload = _workload("fleet", "sha256:fleet")
    triage_model = FakeTriageModel(TriageAdjustment(adjustment=20, rationale="Escalated."))
    intel = {"CVE-2024-0001": ThreatIntel(cve_id="CVE-2024-0001", epss_score=0.2, kev_listed=False)}
    client, connection = _build_client(
        [workload], {"sha256:fleet": [_vulnerability("CVE-2024-0001")]}, triage_model, intel
    )

    client.post("/rescan")
    expected_base = base_priority("HIGH", 0.2, False, True)
    rows = get_queue_rows(connection)

    assert rows[0].base_priority == expected_base
    assert rows[0].contextual_priority == expected_base + 20
    connection.close()


def test_adjustments_outside_the_permitted_range_are_clamped() -> None:
    workload = _workload("fleet", "sha256:fleet")
    triage_model = FakeTriageModel(TriageAdjustment(adjustment=999, rationale="Way too high."))
    client, connection = _build_client(
        [workload], {"sha256:fleet": [_vulnerability("CVE-2024-0001")]}, triage_model
    )

    client.post("/rescan")
    rows = get_queue_rows(connection)

    assert rows[0].contextual_priority == rows[0].base_priority + 25
    connection.close()


def test_a_failed_model_call_leaves_the_base_score_standing_and_marks_the_row() -> None:
    workload = _workload("fleet", "sha256:fleet")
    triage_model = FakeTriageModel(fail=True)
    client, connection = _build_client(
        [workload], {"sha256:fleet": [_vulnerability("CVE-2024-0001")]}, triage_model
    )

    response = client.post("/rescan")
    rows = get_queue_rows(connection)

    assert rows[0].triage_failed is True
    assert rows[0].contextual_priority == rows[0].base_priority
    assert "unavailable" in response.text.lower()
    connection.close()


def test_triage_is_cached_and_not_repeated_on_a_second_rescan() -> None:
    workload = _workload("fleet", "sha256:fleet")
    triage_model = FakeTriageModel(TriageAdjustment(adjustment=5, rationale="Cached."))
    client, connection = _build_client(
        [workload], {"sha256:fleet": [_vulnerability("CVE-2024-0001")]}, triage_model
    )

    client.post("/rescan")
    first_call_count = len(triage_model.calls)
    client.post("/rescan")

    assert first_call_count == 1
    assert len(triage_model.calls) == 1
    connection.close()


def test_toggle_reorders_the_queue_in_the_expected_way() -> None:
    # Base scores tie - identical Severity, EPSS and fix availability - so
    # with the toggle off, the CVE ID tiebreak alone puts "steady" first
    # alphabetically. The model adjustment is what should overturn that
    # ordering when the toggle is on, and turning it back off should
    # restore the tiebreak order exactly.
    boosted_workload = _workload("boosted-workload", "sha256:boosted")
    steady_workload = _workload("steady-workload", "sha256:steady")
    boosted_cve = _vulnerability("CVE-2024-0002", severity="HIGH")
    steady_cve = _vulnerability("CVE-2024-0001", severity="HIGH")
    intel = {
        boosted_cve.cve_id: ThreatIntel(cve_id=boosted_cve.cve_id, epss_score=0.5, kev_listed=False),
        steady_cve.cve_id: ThreatIntel(cve_id=steady_cve.cve_id, epss_score=0.5, kev_listed=False),
    }
    triage_model = FakeTriageModel(
        adjustments_by_cve={
            boosted_cve.cve_id: TriageAdjustment(adjustment=25, rationale="Boosted by an active incident."),
            steady_cve.cve_id: TriageAdjustment(adjustment=0, rationale="Nothing new here."),
        }
    )
    client, connection = _build_client(
        [boosted_workload, steady_workload],
        {"sha256:boosted": [boosted_cve], "sha256:steady": [steady_cve]},
        triage_model,
        intel,
    )

    client.post("/rescan")

    with_adjustment = client.get("/").text
    assert with_adjustment.index(boosted_cve.cve_id) < with_adjustment.index(steady_cve.cve_id)

    without_adjustment = client.get("/?adjustment=off").text
    assert without_adjustment.index(steady_cve.cve_id) < without_adjustment.index(boosted_cve.cve_id)
    connection.close()


def test_toggling_off_leaves_base_scores_unchanged() -> None:
    workload = _workload("fleet", "sha256:fleet")
    triage_model = FakeTriageModel(TriageAdjustment(adjustment=20, rationale="Escalated."))
    client, connection = _build_client(
        [workload], {"sha256:fleet": [_vulnerability("CVE-2024-0001")]}, triage_model
    )

    client.post("/rescan")
    with_adjustment = get_queue_rows(connection, apply_adjustment=True)
    without_adjustment = get_queue_rows(connection, apply_adjustment=False)

    assert with_adjustment[0].base_priority == without_adjustment[0].base_priority
    assert without_adjustment[0].contextual_priority == without_adjustment[0].base_priority
    assert with_adjustment[0].contextual_priority == with_adjustment[0].base_priority + 20
    connection.close()
