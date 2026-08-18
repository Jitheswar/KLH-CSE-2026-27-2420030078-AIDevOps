"""The FastAPI application factory.

Seam A drives this factory directly, in-process, with all five ports faked.
The real entry point (aidevops.main) wires the same factory to the real
SQLite database, on the host.
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from aidevops.candidates import compute_candidate_set
from aidevops.charts import render_line_chart
from aidevops.detection import (
    get_workload_exposure_signal_window,
    run_detection,
    workload_has_active_exposure_signal,
)
from aidevops.domain import METRIC_NAMES
from aidevops.ports.cluster_inventory import ClusterInventoryPort
from aidevops.ports.image_scanner import ImageScannerPort
from aidevops.ports.telemetry import TelemetryPort
from aidevops.ports.threat_intel import ThreatIntelPort
from aidevops.ports.triage_model import TriageModelPort
from aidevops.queue import get_queue_rows, has_pending_scans
from aidevops.reconcile import reconcile_workloads, release_scan_claim, run_triage_sequence, scan_pending_images, store_scan_result
from aidevops.workload_detail import get_workload_summary, get_workload_telemetry_and_baseline, scaled_band

if TYPE_CHECKING:
    from aidevops.domain import Vulnerability

TEMPLATES_DIR = Path(__file__).parent / "templates"
DEFAULT_INVENTORY_PERIOD_SECONDS = 60.0
DEFAULT_DETECTION_PERIOD_SECONDS = 30.0


@dataclass(frozen=True)
class Ports:
    cluster_inventory: ClusterInventoryPort
    telemetry: TelemetryPort
    image_scanner: ImageScannerPort
    threat_intel: ThreatIntelPort
    triage_model: TriageModelPort


async def _inventory_loop(
    connection: sqlite3.Connection, ports: Ports, period_seconds: float, db_lock: threading.Lock
) -> None:
    while True:
        await asyncio.to_thread(_locked_reconcile, connection, ports, db_lock)
        await asyncio.sleep(period_seconds)


def _locked_reconcile(connection: sqlite3.Connection, ports: Ports, db_lock: threading.Lock) -> None:
    # Fetching the inventory is a real network call to the Kubernetes API,
    # not just a SQLite write, so it happens before the lock is taken - the
    # lock's job is to serialize access to `connection`, not to hold up the
    # queue page for however long the cluster takes to answer.
    workloads = ports.cluster_inventory.list_workloads()
    with db_lock:
        pending = reconcile_workloads(connection, ports, workloads)

    # Scanning a newly discovered digest is a real Trivy subprocess call
    # that can run for minutes on a first scan - it must not happen while
    # db_lock is held, or every request for the queue page blocks behind
    # it. Each image's result is written and committed on its own, so a
    # scan that finishes early is visible immediately rather than waiting
    # for the slowest one in the batch.
    def _locked_store(connection: sqlite3.Connection, digest: str, vulnerabilities: list["Vulnerability"]) -> None:
        with db_lock:
            store_scan_result(connection, digest, vulnerabilities)

    def _locked_release(connection: sqlite3.Connection, digest: str) -> None:
        with db_lock:
            release_scan_claim(connection, digest)

    scan_pending_images(connection, ports, pending, store=_locked_store, release=_locked_release)

    # Threat intel lookups are in-memory dict reads against the snapshot
    # loaded at startup, not a network call, but scoring and sorting a
    # thousand-plus Vulnerabilities is still real CPU work - it runs with
    # no lock held, same reasoning as the network calls above. Only the
    # SQL read and the SQL write around it need db_lock - see
    # aidevops.candidates.compute_candidate_set for the locking split.
    compute_candidate_set(connection, ports.threat_intel, db_lock=db_lock)

    # Triages every Candidate Set member still missing one - see
    # aidevops.reconcile.run_triage_sequence for the locking split.
    run_triage_sequence(connection, ports, db_lock=db_lock)


async def _detection_loop(
    connection: sqlite3.Connection, ports: Ports, period_seconds: float, db_lock: threading.Lock
) -> None:
    while True:
        await asyncio.to_thread(_locked_detect, connection, ports, db_lock)
        await asyncio.sleep(period_seconds)


def _locked_detect(connection: sqlite3.Connection, ports: Ports, db_lock: threading.Lock) -> None:
    # Querying telemetry per Workload is a real network call to Prometheus,
    # same reasoning as _locked_reconcile above - it must not run with
    # db_lock held, or every request needing it (the queue page, Workload
    # detail, /rescan, the inventory loop) blocks for however long a
    # detection pass across every Workload takes. run_detection's own
    # `db_lock` parameter brackets only the SQL steps - see
    # aidevops.detection's module docstring.
    run_detection(connection, ports, datetime.now(), db_lock=db_lock)


def create_app(
    connection: sqlite3.Connection,
    ports: Ports,
    inventory_period_seconds: float = DEFAULT_INVENTORY_PERIOD_SECONDS,
    detection_period_seconds: float = DEFAULT_DETECTION_PERIOD_SECONDS,
) -> FastAPI:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    # A sqlite3.Connection is not safe for concurrent use across threads:
    # the background inventory loop runs reconcile() in a worker thread
    # while request handlers run in FastAPI's threadpool, so every access
    # to `connection` is serialized through this lock.
    db_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        inventory_task = asyncio.create_task(
            _inventory_loop(connection, ports, inventory_period_seconds, db_lock)
        )
        detection_task = asyncio.create_task(
            _detection_loop(connection, ports, detection_period_seconds, db_lock)
        )
        try:
            yield
        finally:
            inventory_task.cancel()
            detection_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await inventory_task
            with contextlib.suppress(asyncio.CancelledError):
                await detection_task

    app = FastAPI(title="Contextual Priority Platform", lifespan=lifespan)

    app.state.db = connection
    app.state.ports = ports

    @app.get("/", response_class=HTMLResponse)
    def queue(request: Request, adjustment: str = "on") -> HTMLResponse:
        # The model-adjustment toggle from the spec: a re-render, not a
        # recomputation - base and adjustment are already stored
        # separately (see aidevops.triage and ADR-0004), so flipping this
        # is just which column get_queue_rows adds in.
        apply_adjustment = adjustment != "off"
        with db_lock:
            rows = get_queue_rows(connection, apply_adjustment=apply_adjustment)
            scanning = has_pending_scans(connection)
        return templates.TemplateResponse(
            request,
            "queue.html",
            {"rows": rows, "scanning": scanning, "adjustment_enabled": apply_adjustment},
        )

    @app.post("/rescan")
    def rescan() -> RedirectResponse:
        # Same loop body the periodic inventory loop runs - not a separate
        # code path per the spec's manual-rescan decision.
        _locked_reconcile(connection, ports, db_lock)
        return RedirectResponse(url="/", status_code=303)

    @app.get("/workloads/{namespace}/{name}", response_class=HTMLResponse)
    def workload_detail(namespace: str, name: str, request: Request) -> HTMLResponse:
        with db_lock:
            workload = get_workload_summary(connection, namespace, name)
        if workload is None:
            raise HTTPException(status_code=404, detail="Workload not found")
        pod_names = workload.pod_names

        # Real Prometheus queries are network calls, same reasoning as the
        # cluster inventory call above - they happen with no lock held. One
        # fetch serves both the chart and the Baseline - see
        # get_workload_telemetry_and_baseline.
        now = datetime.now()
        telemetry, baseline = get_workload_telemetry_and_baseline(ports.telemetry, pod_names, end=now)

        with db_lock:
            exposure_signal_active = workload_has_active_exposure_signal(connection, namespace, name)
            signal_window = get_workload_exposure_signal_window(connection, namespace, name)
            vulnerabilities = get_queue_rows(connection, workload_id=workload.id)

        charts = None
        if telemetry.available:
            replica_count = len(pod_names)
            charts = {
                metric: render_line_chart(
                    telemetry.samples,
                    metric,
                    band=scaled_band(baseline, metric, replica_count) if baseline is not None else None,
                    window_start=signal_window.window_start,
                    fired_at=signal_window.fired_at,
                )
                for metric in METRIC_NAMES
            }

        return templates.TemplateResponse(
            request,
            "workload_detail.html",
            {
                "namespace": namespace,
                "name": name,
                "telemetry_available": telemetry.available,
                "charts": charts,
                "baseline_establishing": baseline is not None and not baseline.established,
                "exposure_signal_active": exposure_signal_active,
                "externally_reachable": workload.externally_reachable,
                "vulnerabilities": vulnerabilities,
            },
        )

    return app
