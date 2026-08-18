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


#: The three telemetry metrics tracked per pod, in the order every chart,
#: Prometheus query and per-metric aggregation shares.
METRIC_NAMES: tuple[str, str, str] = ("cpu", "network_transmit", "network_receive")


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


@dataclass(frozen=True)
class ExposureSignalState:
    """A Workload's current Exposure Signal, as the Triage model port needs
    to see it. Defaults to the inactive state for any caller that has not
    run detection yet.
    """

    active: bool = False
    magnitude: float = 0.0

    def cache_key(self) -> str:
        """Part of the Triage cache key, per the spec: caching on this
        alongside the CVE and image is what makes a signal transition
        invalidate exactly the Triages it should, by simply changing which
        cache entry a lookup lands on.
        """
        return f"active:{self.magnitude:.3f}" if self.active else "inactive"


@dataclass(frozen=True)
class TriageContext:
    """Everything the prompt needs for one Vulnerability in one Workload's
    context - see the spec's list of what the prompt must carry.
    """

    vulnerability: Vulnerability
    epss_score: float
    kev_listed: bool
    image_repository: str
    workload_name: str
    workload_namespace: str
    externally_reachable: bool
    exposure_signal: ExposureSignalState
