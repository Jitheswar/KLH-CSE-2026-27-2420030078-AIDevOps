"""Host entry point: `uvicorn aidevops.main:app`.

Every port is still faked here - no real implementation exists yet. Later
tickets replace each fake below with its real counterpart, one port at a
time.
"""

from __future__ import annotations

from aidevops.app import Ports, create_app
from aidevops.config import Settings
from aidevops.db import connect
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel

settings = Settings.from_env()
connection = connect(settings.database_path)
ports = Ports(
    cluster_inventory=FakeClusterInventory(),
    telemetry=FakeTelemetry(),
    image_scanner=FakeImageScanner(),
    threat_intel=FakeThreatIntel(),
    triage_model=FakeTriageModel(),
)

app = create_app(connection, ports, inventory_period_seconds=settings.inventory_period_seconds)
