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
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from aidevops.ports.cluster_inventory import ClusterInventoryPort
from aidevops.ports.image_scanner import ImageScannerPort
from aidevops.ports.telemetry import TelemetryPort
from aidevops.ports.threat_intel import ThreatIntelPort
from aidevops.ports.triage_model import TriageModelPort
from aidevops.queue import get_queue_rows
from aidevops.reconcile import reconcile

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
    with db_lock:
        reconcile(connection, ports)


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
        return templates.TemplateResponse(request, "queue.html", {"rows": rows})

    @app.post("/rescan")
    def rescan() -> RedirectResponse:
        # Same loop body the periodic inventory loop runs - not a separate
        # code path per the spec's manual-rescan decision.
        _locked_reconcile(connection, ports, db_lock)
        return RedirectResponse(url="/", status_code=303)

    return app
