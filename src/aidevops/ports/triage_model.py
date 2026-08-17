"""Triage model port.

Returns a bounded adjustment and a rationale for one Vulnerability in one
context. The real implementation (a later ticket) calls DeepSeek; nothing
above this interface may know that.
"""

from __future__ import annotations

from typing import Protocol

from aidevops.domain import TriageAdjustment, Vulnerability, Workload


class TriageModelPort(Protocol):
    def triage(self, vulnerability: Vulnerability, workload: Workload) -> TriageAdjustment: ...


class FakeTriageModel:
    def __init__(self, adjustment: TriageAdjustment | None = None) -> None:
        self._adjustment = adjustment or TriageAdjustment(adjustment=0, rationale="fake: no adjustment")

    def triage(self, vulnerability: Vulnerability, workload: Workload) -> TriageAdjustment:
        return self._adjustment
