"""Image scanner port.

Returns the Vulnerabilities for one image digest. The real implementation
(a later ticket) runs Trivy as a subprocess and parses its JSON; nothing
above this interface may know that.
"""

from __future__ import annotations

from typing import Protocol

from aidevops.domain import Vulnerability


class ImageScannerPort(Protocol):
    def scan(self, digest: str) -> list[Vulnerability]: ...


class FakeImageScanner:
    def __init__(self, vulnerabilities_by_digest: dict[str, list[Vulnerability]] | None = None) -> None:
        self._vulnerabilities_by_digest = vulnerabilities_by_digest or {}

    def scan(self, digest: str) -> list[Vulnerability]:
        return list(self._vulnerabilities_by_digest.get(digest, []))
