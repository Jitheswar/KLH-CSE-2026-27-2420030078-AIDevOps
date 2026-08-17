"""Unit tests for the real image scanner's pure parsing logic.

These do not run Trivy or touch a subprocess - that is Seam B's job, for a
later ticket. What is tested here is deterministic parsing of Trivy's own
JSON shape into this platform's model, the same carve-out
`tests/test_real_cluster_inventory.py` uses for Kubernetes object parsing.
"""

from __future__ import annotations

import json

from aidevops.domain import Vulnerability
from aidevops.ports.image_scanner import extract_cvss_vector, parse_trivy_output


def _trivy_output(vulnerabilities: list[dict]) -> str:
    return json.dumps({"Results": [{"Vulnerabilities": vulnerabilities}]})


def test_parses_a_vulnerability_with_a_fix_available() -> None:
    raw = _trivy_output(
        [
            {
                "VulnerabilityID": "CVE-2024-0001",
                "PkgName": "libexample",
                "InstalledVersion": "1.0.0",
                "FixedVersion": "1.0.1",
                "Severity": "HIGH",
                "Description": "An example vulnerability.",
                "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
            }
        ]
    )

    vulnerabilities = parse_trivy_output(raw)

    assert vulnerabilities == [
        Vulnerability(
            cve_id="CVE-2024-0001",
            package="libexample",
            installed_version="1.0.0",
            severity="HIGH",
            description="An example vulnerability.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            fixed_version="1.0.1",
        )
    ]


def test_parses_a_vulnerability_with_no_fix_available() -> None:
    raw = _trivy_output(
        [
            {
                "VulnerabilityID": "CVE-2024-0002",
                "PkgName": "libexample",
                "InstalledVersion": "1.0.0",
                "Severity": "CRITICAL",
                "Description": "No fix yet.",
                "CVSS": {},
            }
        ]
    )

    vulnerabilities = parse_trivy_output(raw)

    assert vulnerabilities[0].fixed_version is None


def test_a_scan_with_no_results_produces_no_vulnerabilities() -> None:
    assert parse_trivy_output(json.dumps({"Results": []})) == []


def test_a_scan_with_no_vulnerabilities_key_produces_no_vulnerabilities() -> None:
    assert parse_trivy_output(json.dumps({"Results": [{"Target": "example"}]})) == []


def test_empty_output_produces_no_vulnerabilities() -> None:
    assert parse_trivy_output("") == []


def test_prefers_the_nvd_cvss_vector() -> None:
    vector = extract_cvss_vector(
        {
            "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"},
            "nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
    )

    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_falls_back_to_another_source_when_nvd_is_absent() -> None:
    vector = extract_cvss_vector({"redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}})

    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"


def test_no_cvss_source_produces_an_empty_vector() -> None:
    assert extract_cvss_vector({}) == ""
