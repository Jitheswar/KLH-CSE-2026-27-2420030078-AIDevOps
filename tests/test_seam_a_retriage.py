"""Seam A: signal-driven re-Triage - ticket 12.

Drives the real application over HTTP with all five ports faked, per the
spec's testing decisions. `run_detection` is called directly to populate the
signal and trigger re-Triage, the same way `test_seam_a_exposure_signal.py`
calls it - it is the loop body the periodic detection loop and any manual
trigger would both go through, not a second code path.

A `_SignalAwareTriageModel` stands in for the real Triage model: unlike
`FakeTriageModel`, whose canned response only varies by CVE, this one reads
`context.exposure_signal` and escalates only when it is active - the same
distinction a real DeepSeek call would make from the prompt, per
`aidevops.ports.triage_model.build_prompt`. It is what lets these tests
prove the *context* Triage saw changed across a transition, not just that
Triage ran again.

Fixture sizes and the spike/seed choice mirror `test_exposure_signal.py` and
`test_seam_a_exposure_signal.py` - see their module docstrings for why the
spike is long rather than single-window, and why the fixed samples never
land on the irreducible-background-rate boundary.
"""

from __future__ import annotations

import random
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.db import connect
from aidevops.detection import run_detection, store_exposure_signal
from aidevops.domain import (
    ContainerImage,
    TelemetrySample,
    TelemetrySeries,
    ThreatIntel,
    TriageAdjustment,
    TriageContext,
    Vulnerability,
    Workload,
)
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.queue import get_queue_rows
from aidevops.reconcile import run_triage_sequence
from aidevops.triage import fetch_pending_triage_candidates

_START = datetime(2024, 1, 1, 12, 0, 0)
_STEP = timedelta(seconds=30)
_QUIET_COUNT = 45
_QUIET_SEED = 3

_ESCALATED = TriageAdjustment(adjustment=20, rationale="Escalated - active Exposure Signal in this cluster.")
_BASELINE = TriageAdjustment(adjustment=0, rationale="Nothing new here.")


@dataclass
class _SignalAwareTriageModel:
    """Escalates only while `context.exposure_signal.active` - see the
    module docstring. Records every call so tests can assert exactly which
    Workload's Vulnerabilities were (re-)Triaged, and how many times.
    """

    calls: list[TriageContext] = field(default_factory=list)

    def triage(self, context: TriageContext) -> TriageAdjustment:
        self.calls.append(context)
        return _ESCALATED if context.exposure_signal.active else _BASELINE

    def calls_for(self, workload_name: str) -> list[TriageContext]:
        return [call for call in self.calls if call.workload_name == workload_name]


def _steady_samples(count: int, *, seed: int, start: datetime) -> list[TelemetrySample]:
    rng = random.Random(seed)
    return [
        TelemetrySample(
            timestamp=start + _STEP * i,
            cpu=5.0 + rng.uniform(-1.0, 1.0),
            network_transmit=50.0 + rng.uniform(-10.0, 10.0),
            network_receive=25.0 + rng.uniform(-5.0, 5.0),
        )
        for i in range(count)
    ]


def _spiking_samples(count: int, *, seed: int, start: datetime) -> list[TelemetrySample]:
    rng = random.Random(seed)
    return [
        TelemetrySample(
            timestamp=start + _STEP * i,
            cpu=40.0 + rng.uniform(-1.0, 1.0),
            network_transmit=400.0 + rng.uniform(-10.0, 10.0),
            network_receive=5.0 + rng.uniform(-5.0, 5.0),
        )
        for i in range(count)
    ]


def _series(pod_name: str, samples: list[TelemetrySample]) -> TelemetrySeries:
    return TelemetrySeries(pod_name=pod_name, samples=samples)


def _vulnerability(cve_id: str) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        package="libexample",
        installed_version="1.0.0",
        severity="HIGH",
        description="An example vulnerability.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        fixed_version="1.0.1",
    )


def _workload(name: str) -> Workload:
    return Workload(
        name=name,
        namespace="default",
        replica_pod_names=[f"{name}-abc"],
        images=[ContainerImage(repository="example/repo", digest=f"sha256:{name}")],
        externally_reachable=True,
    )


def _build(triage_model: _SignalAwareTriageModel) -> tuple[TestClient, sqlite3.Connection, Ports]:
    """`frontend` carries the CVE that will be re-Triaged; `steady` carries
    one that must never be touched by `frontend`'s transitions. Same base
    priority for both (identical Severity, EPSS, fix availability) so the
    pre-Triage tie-break (alphabetical CVE ID) is the only thing ordering
    them - CVE-2024-0002 (frontend) sorts after CVE-2024-0001 (steady), so
    any reordering the test observes can only be the escalation, not the
    tie-break.
    """
    frontend = _workload("frontend")
    steady = _workload("steady")
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([frontend, steady]),
        telemetry=FakeTelemetry(
            {
                "frontend-abc": _series("frontend-abc", _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)),
                "steady-abc": _series("steady-abc", _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)),
            }
        ),
        image_scanner=FakeImageScanner(
            {
                "sha256:frontend": [_vulnerability("CVE-2024-0002")],
                "sha256:steady": [_vulnerability("CVE-2024-0001")],
            }
        ),
        threat_intel=FakeThreatIntel(
            {
                "CVE-2024-0002": ThreatIntel(cve_id="CVE-2024-0002", epss_score=0.2, kev_listed=False),
                "CVE-2024-0001": ThreatIntel(cve_id="CVE-2024-0001", epss_score=0.2, kev_listed=False),
            }
        ),
        triage_model=triage_model,
    )
    app = create_app(connection, ports)
    client = TestClient(app)
    client.post("/rescan")
    return client, connection, ports


def test_a_signal_transition_surgically_retriages_only_that_workloads_vulnerabilities_and_reorders_the_queue() -> None:
    triage_model = _SignalAwareTriageModel()
    client, connection, ports = _build(triage_model)

    # Before any signal, both CVEs sit at the same base score - only the
    # alphabetical tie-break orders them.
    initial_rows = get_queue_rows(connection)
    assert [row.cve_id for row in initial_rows] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert len(triage_model.calls_for("frontend")) == 1
    assert len(triage_model.calls_for("steady")) == 1

    # frontend spikes; steady stays quiet throughout. Both pods' full
    # history is replayed on every detection pass (FakeTelemetry ignores
    # the query window and returns the whole stored series), same as
    # test_seam_a_exposure_signal.py.
    quiet_end = _START + _STEP * (_QUIET_COUNT - 1)
    spike = _spiking_samples(20, seed=1, start=quiet_end + _STEP)
    fire_telemetry = FakeTelemetry(
        {
            "frontend-abc": _series("frontend-abc", _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START) + spike),
            "steady-abc": _series("steady-abc", _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)),
        }
    )
    fire_ports = Ports(
        cluster_inventory=ports.cluster_inventory,
        telemetry=fire_telemetry,
        image_scanner=ports.image_scanner,
        threat_intel=ports.threat_intel,
        triage_model=triage_model,
    )

    run_detection(connection, fire_ports, now=spike[-1].timestamp)

    # Re-Triage happened immediately, inside this one call - no second
    # /rescan or reconcile pass in between.
    assert len(triage_model.calls_for("frontend")) == 2
    assert triage_model.calls_for("frontend")[-1].exposure_signal.active is True
    assert triage_model.calls_for("frontend")[-1].exposure_signal.magnitude > 0.0
    # Asserted, not assumed: steady's Vulnerability was never re-submitted.
    assert len(triage_model.calls_for("steady")) == 1

    fired_rows = get_queue_rows(connection)
    assert fired_rows[0].cve_id == "CVE-2024-0002"
    assert fired_rows[0].contextual_priority > fired_rows[0].base_priority
    steady_row = next(row for row in fired_rows if row.cve_id == "CVE-2024-0001")
    assert steady_row.contextual_priority == steady_row.base_priority

    # The signal clearing is a transition too - a long quiet tail after the
    # spike clears it (fire-after-2/clear-after-3 hysteresis, see
    # aidevops.exposure_signal) - and that must also trigger re-Triage for
    # frontend immediately, putting the queue back where it started.
    clear_tail = _steady_samples(40, seed=7, start=spike[-1].timestamp + _STEP)
    clear_telemetry = FakeTelemetry(
        {
            "frontend-abc": _series(
                "frontend-abc", _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START) + spike + clear_tail
            ),
            "steady-abc": _series("steady-abc", _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)),
        }
    )
    clear_ports = Ports(
        cluster_inventory=ports.cluster_inventory,
        telemetry=clear_telemetry,
        image_scanner=ports.image_scanner,
        threat_intel=ports.threat_intel,
        triage_model=triage_model,
    )

    run_detection(connection, clear_ports, now=clear_tail[-1].timestamp)

    # No model call was needed to revert: the "inactive" cache key already
    # held a valid Triage from before frontend ever fired, so re-Triage on
    # clearing reused it rather than paying for a redundant model call -
    # the same caching the "cached and not repeated on a second rescan"
    # behaviour relies on, now proven across a signal transition too.
    assert len(triage_model.calls_for("frontend")) == 2
    assert len(triage_model.calls_for("steady")) == 1

    cleared_rows = get_queue_rows(connection)
    assert [row.cve_id for row in cleared_rows] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert cleared_rows[1].contextual_priority == cleared_rows[1].base_priority
    connection.close()


def test_a_clearing_transition_pays_for_a_fresh_model_call_when_nothing_is_cached_at_the_reverted_key() -> None:
    """The queue-reuses-the-cache path above is the common case, but
    `store_exposure_signal`'s transition detection - the mechanism
    `run_detection` uses to decide whether to call `retriage_workload` at
    all - has to fire correctly on its own terms too. This drives it
    directly, with the "inactive" cache entry the initial `/rescan` leaves
    behind removed - simulating a Workload whose only cached Triage is the
    one from while it was firing - so clearing it must pay for a real model
    call, not silently leave the escalated Triage standing because some
    other, unrelated cache entry happened to already exist.
    """
    triage_model = _SignalAwareTriageModel()
    frontend = _workload("frontend")
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([frontend]),
        telemetry=FakeTelemetry({"frontend-abc": _series("frontend-abc", [])}),
        image_scanner=FakeImageScanner({"sha256:frontend": [_vulnerability("CVE-2024-0002")]}),
        threat_intel=FakeThreatIntel({"CVE-2024-0002": ThreatIntel(cve_id="CVE-2024-0002", epss_score=0.2, kev_listed=False)}),
        triage_model=triage_model,
    )
    app = create_app(connection, ports)
    TestClient(app).post("/rescan")
    assert len(triage_model.calls) == 1
    connection.execute("DELETE FROM triage_results WHERE exposure_signal_state = 'inactive'")
    connection.commit()

    quiet = _steady_samples(_QUIET_COUNT, seed=_QUIET_SEED, start=_START)
    spike = _spiking_samples(20, seed=1, start=quiet[-1].timestamp + _STEP)
    fire_ports = Ports(
        cluster_inventory=ports.cluster_inventory,
        telemetry=FakeTelemetry({"frontend-abc": _series("frontend-abc", quiet + spike)}),
        image_scanner=ports.image_scanner,
        threat_intel=ports.threat_intel,
        triage_model=triage_model,
    )
    run_detection(connection, fire_ports, now=spike[-1].timestamp)
    assert len(triage_model.calls) == 2
    assert triage_model.calls[-1].exposure_signal.active is True

    clear_tail = _steady_samples(40, seed=7, start=spike[-1].timestamp + _STEP)
    clear_ports = Ports(
        cluster_inventory=ports.cluster_inventory,
        telemetry=FakeTelemetry({"frontend-abc": _series("frontend-abc", quiet + spike + clear_tail)}),
        image_scanner=ports.image_scanner,
        threat_intel=ports.threat_intel,
        triage_model=triage_model,
    )
    run_detection(connection, clear_ports, now=clear_tail[-1].timestamp)

    assert len(triage_model.calls) == 3
    assert triage_model.calls[-1].exposure_signal.active is False
    connection.close()


def test_magnitude_is_pinned_while_a_signal_stays_continuously_active() -> None:
    """A real detection pass recomputes magnitude fresh every tick from
    live telemetry, so it never lands on exactly the same float twice.
    `ExposureSignalState.cache_key()` (aidevops.domain) embeds magnitude to
    3 decimal places - without pinning, every one of those harmless
    recomputes would look like a fresh Exposure Signal state to
    `fetch_pending_triage_candidates`, and the unscoped periodic reconcile
    (aidevops.app._locked_reconcile) would re-Triage - and re-bill the
    model for - every actively-firing
    Workload's CVEs on every single pass, not just the one transition that
    actually happened.
    """
    connection = connect(":memory:")
    connection.execute("INSERT INTO workloads (id, namespace, name) VALUES (1, 'default', 'frontend')")
    connection.commit()

    transitioned = store_exposure_signal(connection, workload_id=1, active=True, magnitude=2.415)
    assert transitioned is True

    # Three more ticks, each with a different freshly recomputed magnitude,
    # same as real telemetry noise would produce - none of these are
    # transitions, so none of them should move the stored magnitude.
    for drifted_magnitude in (2.418, 2.402, 2.431):
        transitioned = store_exposure_signal(connection, workload_id=1, active=True, magnitude=drifted_magnitude)
        assert transitioned is False

    stored = connection.execute("SELECT magnitude FROM exposure_signals WHERE workload_id = 1").fetchone()
    assert stored["magnitude"] == 2.415

    # Clearing still zeroes it out, and the next fire re-pins to whatever
    # that pass's magnitude was.
    assert store_exposure_signal(connection, workload_id=1, active=False, magnitude=0.0) is True
    assert store_exposure_signal(connection, workload_id=1, active=True, magnitude=9.0) is True
    stored = connection.execute("SELECT magnitude FROM exposure_signals WHERE workload_id = 1").fetchone()
    assert stored["magnitude"] == 9.0
    connection.close()


def test_a_cve_shared_with_a_quiet_alphabetically_earlier_workload_is_still_escalated() -> None:
    """`fetch_pending_triage_candidates` picks one representative Workload
    per CVE (see its docstring). Before this fix that was purely the
    query's tie-break order (image digest, then namespace/name) - so a CVE
    also present on some quiet Workload that happened to sort first would
    be Triaged against the quiet context and never escalated at all, even
    while a different Workload sharing the same CVE was actively firing.
    `sha256:aaa-quiet` sorts before `sha256:zzz-firing` on every one of
    those keys, so this would have picked the quiet Workload without the
    fix.
    """
    quiet = _workload("aaa-quiet")
    firing = _workload("zzz-firing")
    shared_cve = _vulnerability("CVE-2024-0009")
    triage_model = _SignalAwareTriageModel()
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([quiet, firing]),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner(
            {"sha256:aaa-quiet": [shared_cve], "sha256:zzz-firing": [shared_cve]}
        ),
        threat_intel=FakeThreatIntel({shared_cve.cve_id: ThreatIntel(cve_id=shared_cve.cve_id, epss_score=0.2, kev_listed=False)}),
        triage_model=triage_model,
    )
    app = create_app(connection, ports)
    TestClient(app).post("/rescan")
    firing_workload_id = connection.execute("SELECT id FROM workloads WHERE name = 'zzz-firing'").fetchone()["id"]

    connection.execute("DELETE FROM triage_results")
    store_exposure_signal(connection, workload_id=firing_workload_id, active=True, magnitude=3.0)

    # Unscoped - the same call the periodic full reconcile makes
    # (aidevops.app._locked_reconcile), which sees both Workloads and has
    # to choose one representative context.
    candidates = fetch_pending_triage_candidates(connection)

    assert len(candidates) == 1
    assert candidates[0].context.exposure_signal.active is True
    assert candidates[0].context.workload_name == "zzz-firing"
    connection.close()


def test_the_queue_shows_the_escalated_adjustment_for_a_cve_shared_with_a_quiet_alphabetically_earlier_workload() -> None:
    """The fix above makes `fetch_pending_triage_candidates` pick the
    firing Workload as the CVE's representative context, and re-Triage
    stores its escalated result under that Workload's own image digest -
    but the initial, pre-signal Triage is still sitting in `triage_results`
    keyed to the quiet Workload's digest too, since nothing deletes it (see
    aidevops.queue._fetch_triage_by_cve's docstring). `get_queue_rows`
    (`queue._fetch_triage_by_cve`) has to pick between those two rows for
    the same CVE on its own read path - this is what proves the queue
    itself, not just the Triage cache, prefers the escalated one.
    """
    quiet = _workload("aaa-quiet")
    firing = _workload("zzz-firing")
    shared_cve = _vulnerability("CVE-2024-0009")
    triage_model = _SignalAwareTriageModel()
    connection = connect(":memory:")
    ports = Ports(
        cluster_inventory=FakeClusterInventory([quiet, firing]),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner(
            {"sha256:aaa-quiet": [shared_cve], "sha256:zzz-firing": [shared_cve]}
        ),
        threat_intel=FakeThreatIntel({shared_cve.cve_id: ThreatIntel(cve_id=shared_cve.cve_id, epss_score=0.2, kev_listed=False)}),
        triage_model=triage_model,
    )
    app = create_app(connection, ports)
    client = TestClient(app)
    # First pass: neither Workload has a signal yet, so the quiet Workload
    # (alphabetically first) is Triaged as the CVE's representative and
    # stored at sha256:aaa-quiet - the stale row `_fetch_triage_by_cve`
    # must not prefer once the other Workload fires.
    client.post("/rescan")
    firing_workload_id = connection.execute("SELECT id FROM workloads WHERE name = 'zzz-firing'").fetchone()["id"]

    store_exposure_signal(connection, workload_id=firing_workload_id, active=True, magnitude=3.0)
    run_triage_sequence(connection, ports)

    response = client.get("/")

    assert response.status_code == 200
    assert "Escalated - active Exposure Signal in this cluster." in response.text
    assert "Nothing new here." not in response.text
    connection.close()
