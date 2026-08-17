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

from aidevops.charts import render_line_chart
from aidevops.ports.cluster_inventory import ClusterInventoryPort
from aidevops.ports.image_scanner import ImageScannerPort
from aidevops.ports.telemetry import TelemetryPort
from aidevops.ports.threat_intel import ThreatIntelPort
from aidevops.ports.triage_model import TriageModelPort
from aidevops.queue import get_queue_rows, has_pending_scans
from aidevops.reconcile import reconcile_workloads, scan_pending_images, store_scan_result
from aidevops.workload_detail import get_workload_pods, get_workload_telemetry

TEMPLATES_DIR = Path(__file__).parent / "templates"
DEFAULT_INVENTORY_PERIOD_SECONDS = 60.0


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

    scan_pending_images(connection, ports, pending, store=_locked_store)


def create_app(
    connection: sqlite3.Connection,
    ports: Ports,
    inventory_period_seconds: float = DEFAULT_INVENTORY_PERIOD_SECONDS,
) -> FastAPI:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    # A sqlite3.Connection is not safe for concurrent use across threads:
    # the background inventory loop runs reconcile() in a worker thread
    # while request handlers run in FastAPI's threadpool, so every access
    # to `connection` is serialized through this lock.
    db_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(
            _inventory_loop(connection, ports, inventory_period_seconds, db_lock)
        )
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Contextual Priority Platform", lifespan=lifespan)

    app.state.db = connection
    app.state.ports = ports

    @app.get("/", response_class=HTMLResponse)
    def queue(request: Request) -> HTMLResponse:
        with db_lock:
            rows = get_queue_rows(connection)
            scanning = has_pending_scans(connection)
        return templates.TemplateResponse(request, "queue.html", {"rows": rows, "scanning": scanning})

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

        # A real Prometheus query is a network call, same reasoning as the
        # cluster inventory call above - it happens with no lock held.
        telemetry = get_workload_telemetry(ports.telemetry, pod_names, end=datetime.now())
        charts = None
        if telemetry.available:
            charts = {
                "cpu": render_line_chart(telemetry.samples, "cpu"),
                "network_transmit": render_line_chart(telemetry.samples, "network_transmit"),
                "network_receive": render_line_chart(telemetry.samples, "network_receive"),
            }

        return templates.TemplateResponse(
            request,
            "workload_detail.html",
            {
                "namespace": namespace,
                "name": name,
                "telemetry_available": telemetry.available,
                "charts": charts,
            },
        )

    return app
