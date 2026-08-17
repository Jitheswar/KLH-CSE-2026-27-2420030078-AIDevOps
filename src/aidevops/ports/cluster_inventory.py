"""Cluster inventory port.

Returns the current set of Workloads. The real implementation (a later
ticket) polls the Kubernetes API; nothing above this interface may know
that.
"""

from __future__ import annotations

from typing import Protocol

from aidevops.domain import Workload


class ClusterInventoryPort(Protocol):
    def list_workloads(self) -> list[Workload]: ...


class FakeClusterInventory:
    def __init__(self, workloads: list[Workload] | None = None) -> None:
        self._workloads = workloads or []

    def list_workloads(self) -> list[Workload]:
        return list(self._workloads)
