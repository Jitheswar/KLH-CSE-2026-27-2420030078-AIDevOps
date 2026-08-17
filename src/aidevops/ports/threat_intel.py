"""Threat intel port.

Returns EPSS score and KEV membership for a CVE. The real implementation
reads snapshot files under data/ - see data/README.md for their source and
RealThreatIntel below; nothing above this interface may know that.
"""

from __future__ import annotations

import csv
import gzip
import json
import logging
from pathlib import Path
from typing import Protocol

from aidevops.domain import ThreatIntel

logger = logging.getLogger(__name__)

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"


class ThreatIntelPort(Protocol):
    def lookup(self, cve_id: str) -> ThreatIntel: ...


class FakeThreatIntel:
    def __init__(self, intel_by_cve: dict[str, ThreatIntel] | None = None) -> None:
        self._intel_by_cve = intel_by_cve or {}

    def lookup(self, cve_id: str) -> ThreatIntel:
        return self._intel_by_cve.get(
            cve_id, ThreatIntel(cve_id=cve_id, epss_score=0.0, kev_listed=False)
        )


class RealThreatIntel:
    """Reads the EPSS and KEV snapshots under `data/` once, at construction,
    into an in-memory table keyed by CVE ID.

    Both are point-in-time snapshots rather than a live feed - see
    data/README.md - so a lookup is a dict access, not a network call, and
    is cheap enough to run once per CVE on every reconcile pass.
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        data_dir = data_dir or DEFAULT_DATA_DIR
        self._epss_by_cve = _load_epss(data_dir / "epss_scores.csv.gz")
        self._kev_cve_ids = _load_kev(data_dir / "kev.json")
        logger.info(
            "threat intel snapshots loaded: %d EPSS scores, %d KEV entries",
            len(self._epss_by_cve),
            len(self._kev_cve_ids),
        )

    def lookup(self, cve_id: str) -> ThreatIntel:
        return ThreatIntel(
            cve_id=cve_id,
            epss_score=self._epss_by_cve.get(cve_id, 0.0),
            kev_listed=cve_id in self._kev_cve_ids,
        )


def _load_epss(path: Path) -> dict[str, float]:
    scores: dict[str, float] = {}
    with gzip.open(path, mode="rt", newline="") as handle:
        next(handle, None)  # the model-version/score-date comment line, not a CSV header
        reader = csv.DictReader(handle)
        for row in reader:
            scores[row["cve"]] = float(row["epss"])
    return scores


def _load_kev(path: Path) -> frozenset[str]:
    payload = json.loads(path.read_text())
    return frozenset(payload["cve_ids"])
