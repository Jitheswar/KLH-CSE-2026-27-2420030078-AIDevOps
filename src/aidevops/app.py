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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from aidevops.candidates import fetch_vulnerability_rows, score_candidate_set, store_candidate_set
from aidevops.charts import render_line_chart
from aidevops.detection import (
    detect_signal_for_workload,
    get_workload_exposure_signal_window,
    list_workloads_with_pods,
    store_exposure_signal,
    workload_has_active_exposure_signal,
)
from aidevops.ports.cluster_inventory import ClusterInventoryPort
from aidevops.ports.image_scanner import ImageScannerPort
from aidevops.ports.telemetry import TelemetryPort
from aidevops.ports.threat_intel import ThreatIntelPort
from aidevops.ports.triage_model import TriageModelPort
from aidevops.queue import get_queue_rows, has_pending_scans
from aidevops.reconcile import reconcile_workloads, release_scan_claim, scan_pending_images, store_scan_result
from aidevops.triage import enrich_with_threat_intel, fetch_pending_triage_candidates, run_triage_model, store_triage_outcomes
from aidevops.workload_detail import get_workload_pods, get_workload_telemetry_and_baseline, scaled_band

TEMPLATES_DIR = Path(__file__).parent / "templates"
DEFAULT_INVENTORY_PERIOD_SECONDS = 60.0
DEFAULT_DETECTION_PERIOD_SECONDS = 60.0


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
    def _locked_store(connection: sqlite3.Connection, digest: str, vulnerabilities: list) -> None:
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
    # SQL read and the SQL write around it need db_lock.
    with db_lock:
        rows = fetch_vulnerability_rows(connection)
    candidates = score_candidate_set(rows, ports.threat_intel)
    with db_lock:
        store_candidate_set(connection, candidates)

    # A real Triage call is a DeepSeek request per Vulnerability - same
    # reasoning as scanning above, it must not run with db_lock held.
    # Fetching which candidates still need it, and storing the result, are
    # both quick SQL steps and do need the lock.
    with db_lock:
        triage_candidates = fetch_pending_triage_candidates(connection)
    triage_candidates = enrich_with_threat_intel(triage_candidates, ports.threat_intel)
    outcomes = run_triage_model(ports.triage_model, triage_candidates)
    with db_lock:
        store_triage_outcomes(connection, outcomes)


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
    # detection pass across every Workload takes. Only the SQL read that
    # lists known Workloads, and the SQL write per Workload's result, need
    # the lock - see aidevops.detection's module docstring.
    with db_lock:
        known_workloads = list_workloads_with_pods(connection)

    now = datetime.now()
    for workload in known_workloads:
        signal = detect_signal_for_workload(ports, workload.pod_names, now)
        if signal is None:
            continue
        with db_lock:
            transitioned = store_exposure_signal(
                connection, workload.id, signal.active, signal.magnitude, signal.window_start, signal.fired_at
            )

        # A fire or clear transition re-Triages this Workload's
        # Vulnerabilities right now, in this same detection pass - not
        # deferred to the next inventory loop tick - same locked/unlocked
        # split as the Triage steps in _locked_reconcile, scoped to this
        # one Workload (see aidevops.reconcile.retriage_workload).
        if transitioned:
            with db_lock:
                triage_candidates = fetch_pending_triage_candidates(connection, workload_id=workload.id)
            triage_candidates = enrich_with_threat_intel(triage_candidates, ports.threat_intel)
            outcomes = run_triage_model(ports.triage_model, triage_candidates)
            with db_lock:
                store_triage_outcomes(connection, outcomes)


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
            pod_names = get_workload_pods(connection, namespace, name)
        if pod_names is None:
            raise HTTPException(status_code=404, detail="Workload not found")

        # Real Prometheus queries are network calls, same reasoning as the
        # cluster inventory call above - they happen with no lock held. One
        # fetch serves both the chart and the Baseline - see
        # get_workload_telemetry_and_baseline.
        now = datetime.now()
        telemetry, baseline = get_workload_telemetry_and_baseline(ports.telemetry, pod_names, end=now)

        with db_lock:
            exposure_signal_active = workload_has_active_exposure_signal(connection, namespace, name)
            signal_window = get_workload_exposure_signal_window(connection, namespace, name)

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
                for metric in ("cpu", "network_transmit", "network_receive")
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
            },
        )

    return app
