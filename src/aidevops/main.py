"""Host entry point: `uvicorn aidevops.main:app`.

Cluster inventory talks to the real Kubernetes API, image scanning runs real
Trivy scans, telemetry queries the real Prometheus, threat intel reads the
EPSS/KEV snapshots under `data/`, and Triage calls DeepSeek - see
`aidevops.ports.cluster_inventory.RealClusterInventory`,
`aidevops.ports.image_scanner.RealImageScanner`,
`aidevops.ports.telemetry.PrometheusTelemetry`,
`aidevops.ports.threat_intel.RealThreatIntel`,
`aidevops.ports.triage_model.RealTriageModel`, `make cluster-up` / `make
seed` / `make prometheus-up`, and `make tools` for installing Trivy.
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
from aidevops.ports.triage_model import RealTriageModel

logging.basicConfig(level=logging.INFO)

settings = Settings.from_env()
connection = connect(settings.database_path)
ports = Ports(
    cluster_inventory=RealClusterInventory(),
    telemetry=PrometheusTelemetry(settings.prometheus_url),
    image_scanner=RealImageScanner(),
    threat_intel=RealThreatIntel(),
    triage_model=RealTriageModel(api_key=settings.deepseek_api_key, base_url=settings.deepseek_base_url),
)

app = create_app(connection, ports, inventory_period_seconds=settings.inventory_period_seconds)
