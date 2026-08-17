"""Image scanner port.

Returns the Vulnerabilities for one image. The real implementation runs
Trivy as a subprocess and parses its JSON; nothing above this interface may
know that.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Protocol

from aidevops.domain import ContainerImage, Vulnerability

logger = logging.getLogger(__name__)


class ImageScannerPort(Protocol):
    def scan(self, image: ContainerImage) -> list[Vulnerability]: ...


class FakeImageScanner:
    def __init__(self, vulnerabilities_by_digest: dict[str, list[Vulnerability]] | None = None) -> None:
        self._vulnerabilities_by_digest = vulnerabilities_by_digest or {}
        # Test seam: lets Seam A tests assert a digest was, or was not,
        # scanned - see the spec's requirement that the permanent cache be
        # observable rather than assumed.
        self.scanned_digests: list[str] = []

    def scan(self, image: ContainerImage) -> list[Vulnerability]:
        self.scanned_digests.append(image.digest)
        return list(self._vulnerabilities_by_digest.get(image.digest, []))


class RealImageScanner:
    """Runs Trivy as a subprocess and parses its JSON output into this
    platform's own model.

    Trivy needs a full pullable reference to scan an image, not a bare
    digest, so `repository@digest` (the same shape `parse_image_reference`
    produces) is what gets passed on the command line.
    """

    def scan(self, image: ContainerImage) -> list[Vulnerability]:
        reference = f"{image.repository}@{image.digest}"
        logger.info("running trivy against %s", reference)
        result = subprocess.run(
            ["trivy", "image", "--quiet", "--format", "json", reference],
            capture_output=True,
            text=True,
            check=True,
        )
        vulnerabilities = parse_trivy_output(result.stdout)
        logger.info("trivy found %d vulnerabilities in %s", len(vulnerabilities), reference)
        return vulnerabilities


def parse_trivy_output(raw_json: str) -> list[Vulnerability]:
    """Turns Trivy's `--format json` output into this platform's model.

    Kept separate from the subprocess call so it can be exercised with
    canned Trivy output, with no subprocess and no network - the same
    carve-out `aidevops.ports.cluster_inventory` uses for its parsing code.
    """
    payload = json.loads(raw_json or "{}")
    vulnerabilities: list[Vulnerability] = []
    for result in payload.get("Results") or []:
        for entry in result.get("Vulnerabilities") or []:
            vulnerabilities.append(
                Vulnerability(
                    cve_id=entry["VulnerabilityID"],
                    package=entry["PkgName"],
                    installed_version=entry["InstalledVersion"],
                    severity=entry.get("Severity", "UNKNOWN"),
                    description=entry.get("Description", ""),
                    cvss_vector=extract_cvss_vector(entry.get("CVSS") or {}),
                    fixed_version=entry.get("FixedVersion") or None,
                )
            )
    return vulnerabilities


def extract_cvss_vector(cvss_by_source: dict[str, Any]) -> str:
    """Trivy nests a CVSS entry per scoring source (nvd, redhat, ghsa, ...);
    nvd is preferred when present, and any source with a v3 vector otherwise.
    """
    preferred = (cvss_by_source.get("nvd") or {}).get("V3Vector")
    if preferred:
        return preferred
    for entry in cvss_by_source.values():
        vector = entry.get("V3Vector")
        if vector:
            return vector
    return ""
