"""Host entry point: `uvicorn aidevops.main:app`.

Cluster inventory talks to the real Kubernetes API, image scanning runs real
Trivy scans, telemetry queries the real Prometheus, and threat intel reads
the EPSS/KEV snapshots under `data/` - see
`aidevops.ports.cluster_inventory.RealClusterInventory`,
`aidevops.ports.image_scanner.RealImageScanner`,
`aidevops.ports.telemetry.PrometheusTelemetry`,
`aidevops.ports.threat_intel.RealThreatIntel`, `make cluster-up` / `make
seed` / `make prometheus-up`, and `make tools` for installing Trivy. The
remaining port is still faked here; a later ticket replaces it.
"""

from __future__ import annotations

import logging

from aidevops.app import Ports, create_app
from aidevops.config import Settings
from aidevops.db import connect
from aidevops.ports.cluster_inventory import RealClusterInventory
from aidevops.ports.image_scanner import RealImageScanner
from aidevops.ports.telemetry import PrometheusTelemetry
from aidevops.ports.threat_intel import RealThreatIntel
from aidevops.ports.triage_model import FakeTriageModel

logging.basicConfig(level=logging.INFO)

settings = Settings.from_env()
connection = connect(settings.database_path)
ports = Ports(
    cluster_inventory=RealClusterInventory(),
    telemetry=PrometheusTelemetry(settings.prometheus_url),
    image_scanner=RealImageScanner(),
    threat_intel=RealThreatIntel(),
    triage_model=FakeTriageModel(),
)

app = create_app(connection, ports, inventory_period_seconds=settings.inventory_period_seconds)
