"""Threat intel port.

Returns EPSS score and KEV membership for a CVE. The real implementation
(a later ticket) reads snapshot files under data/; nothing above this
interface may know that.
"""

from __future__ import annotations

from typing import Protocol

from aidevops.domain import ThreatIntel


class ThreatIntelPort(Protocol):
    def lookup(self, cve_id: str) -> ThreatIntel: ...


class FakeThreatIntel:
    def __init__(self, intel_by_cve: dict[str, ThreatIntel] | None = None) -> None:
        self._intel_by_cve = intel_by_cve or {}

    def lookup(self, cve_id: str) -> ThreatIntel:
        return self._intel_by_cve.get(
            cve_id, ThreatIntel(cve_id=cve_id, epss_score=0.0, kev_listed=False)
        )
