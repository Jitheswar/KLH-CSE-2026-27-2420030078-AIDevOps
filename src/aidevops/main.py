"""Host entry point: `uvicorn aidevops.main:app`.

Cluster inventory now talks to the real Kubernetes API - see
`aidevops.ports.cluster_inventory.RealClusterInventory` and `make cluster-up`
/ `make seed`. The remaining ports are still faked here; later tickets
replace each in turn.
"""

from __future__ import annotations

from aidevops.app import Ports, create_app
from aidevops.config import Settings
from aidevops.db import connect
from aidevops.ports.cluster_inventory import RealClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel

settings = Settings.from_env()
connection = connect(settings.database_path)
ports = Ports(
    cluster_inventory=RealClusterInventory(),
    telemetry=FakeTelemetry(),
    image_scanner=FakeImageScanner(),
    threat_intel=FakeThreatIntel(),
    triage_model=FakeTriageModel(),
)

app = create_app(connection, ports, inventory_period_seconds=settings.inventory_period_seconds)
