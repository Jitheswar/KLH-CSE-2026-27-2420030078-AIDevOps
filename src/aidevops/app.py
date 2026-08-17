"""The FastAPI application factory.

Seam A drives this factory directly, in-process, with all five ports faked.
The real entry point (aidevops.main) wires the same factory to the real
SQLite database, on the host.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aidevops.ports.cluster_inventory import ClusterInventoryPort
from aidevops.ports.image_scanner import ImageScannerPort
from aidevops.ports.telemetry import TelemetryPort
from aidevops.ports.threat_intel import ThreatIntelPort
from aidevops.ports.triage_model import TriageModelPort
from aidevops.queue import get_queue_rows

TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass(frozen=True)
class Ports:
    cluster_inventory: ClusterInventoryPort
    telemetry: TelemetryPort
    image_scanner: ImageScannerPort
    threat_intel: ThreatIntelPort
    triage_model: TriageModelPort


def create_app(connection: sqlite3.Connection, ports: Ports) -> FastAPI:
    app = FastAPI(title="Contextual Priority Platform")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    app.state.db = connection
    app.state.ports = ports

    @app.get("/", response_class=HTMLResponse)
    def queue(request: Request) -> HTMLResponse:
        rows = get_queue_rows(connection)
        return templates.TemplateResponse(request, "queue.html", {"rows": rows})

    return app
