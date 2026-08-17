"""Unit tests for the real threat intel port's snapshot loading.

These build tiny fixture snapshots on disk rather than touching the
committed data/ files - that keeps the test independent of whatever the
current EPSS/KEV snapshot happens to contain. No network call is made
anywhere here; RealThreatIntel only ever reads files.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from aidevops.ports.threat_intel import RealThreatIntel


def _write_snapshots(data_dir: Path, epss_rows: list[tuple[str, float]], kev_cve_ids: list[str]) -> None:
    with gzip.open(data_dir / "epss_scores.csv.gz", mode="wt", newline="") as handle:
        handle.write("#model_version:v2026.06.15,score_date:2026-08-17T12:03:47Z\n")
        handle.write("cve,epss,percentile\n")
        for cve_id, score in epss_rows:
            handle.write(f"{cve_id},{score},0.5\n")

    (data_dir / "kev.json").write_text(
        json.dumps({"catalog_version": "test", "date_released": "2026-08-17", "count": len(kev_cve_ids), "cve_ids": kev_cve_ids})
    )


def test_looks_up_epss_score_and_kev_membership_for_a_known_cve(tmp_path: Path) -> None:
    _write_snapshots(
        tmp_path,
        epss_rows=[("CVE-2024-0001", 0.87654)],
        kev_cve_ids=["CVE-2024-0001"],
    )
    threat_intel = RealThreatIntel(data_dir=tmp_path)

    result = threat_intel.lookup("CVE-2024-0001")

    assert result.cve_id == "CVE-2024-0001"
    assert result.epss_score == 0.87654
    assert result.kev_listed is True


def test_an_unknown_cve_defaults_to_zero_epss_and_no_kev(tmp_path: Path) -> None:
    _write_snapshots(tmp_path, epss_rows=[], kev_cve_ids=[])
    threat_intel = RealThreatIntel(data_dir=tmp_path)

    result = threat_intel.lookup("CVE-2024-9999")

    assert result.epss_score == 0.0
    assert result.kev_listed is False


def test_a_cve_with_an_epss_score_but_not_kev_listed(tmp_path: Path) -> None:
    _write_snapshots(
        tmp_path,
        epss_rows=[("CVE-2024-0002", 0.1234)],
        kev_cve_ids=["CVE-2024-0001"],
    )
    threat_intel = RealThreatIntel(data_dir=tmp_path)

    result = threat_intel.lookup("CVE-2024-0002")

    assert result.epss_score == 0.1234
    assert result.kev_listed is False
