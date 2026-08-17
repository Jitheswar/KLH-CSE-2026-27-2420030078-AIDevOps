"""Shapes shared across ports.

These are plain data carriers, not behaviour. Kubernetes, Prometheus, Trivy
and DeepSeek are never named here or anywhere above the ports package - see
CONTEXT.md and the spec's port boundary decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ContainerImage:
    repository: str
    digest: str


@dataclass(frozen=True)
class Workload:
    name: str
    namespace: str
    replica_pod_names: list[str]
    images: list[ContainerImage]
    externally_reachable: bool


@dataclass(frozen=True)
class TelemetrySample:
    timestamp: datetime
    cpu: float
    network_transmit: float
    network_receive: float


@dataclass(frozen=True)
class TelemetrySeries:
    pod_name: str
    samples: list[TelemetrySample] = field(default_factory=list)


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    package: str
    installed_version: str
    severity: str
    description: str
    cvss_vector: str
    fixed_version: str | None = None


@dataclass(frozen=True)
class ThreatIntel:
    cve_id: str
    epss_score: float
    kev_listed: bool


@dataclass(frozen=True)
class TriageAdjustment:
    """Per ADR-0004, this is an adjustment to a base score, not the score."""

    adjustment: int
    rationale: str
