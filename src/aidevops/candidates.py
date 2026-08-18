"""The pre-filter and base Contextual Priority.

Runs after scanning, deterministically and before any model call. Per the
spec, Severity, EPSS, KEV membership and fix availability must each be able
to move a Vulnerability into or out of the Candidate Set on their own - a
single weighted score computed from all four, used both to rank and to cut
the set to roughly the top fifty, is what makes that true: changing any one
signal changes the score, which can push a Vulnerability across the cutoff
regardless of what its Severity is.

Base Contextual Priority is stored on its own in `candidate_priorities`,
independent of the model's adjustment (see aidevops.triage) - see ADR-0004.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aidevops.ports.threat_intel import ThreatIntelPort

TARGET_CANDIDATE_SET_SIZE = 50

# Trivy's own severity vocabulary, plus a fallback for anything else a
# scanner might emit. Deliberately not a bare ordinal: the gaps are part of
# how much each Severity band contributes relative to EPSS, KEV and fix
# availability below.
SEVERITY_SCORE = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "NEGLIGIBLE": 10,
    "UNKNOWN": 30,
}

SEVERITY_WEIGHT = 0.35
EPSS_WEIGHT = 0.30
KEV_WEIGHT = 0.20
FIX_WEIGHT = 0.15


@dataclass(frozen=True)
class _DedupedVulnerability:
    cve_id: str
    severity: str
    fix_available: bool


def base_priority(severity: str, epss_score: float, kev_listed: bool, fix_available: bool) -> int:
    """Deterministic 0-100 base score. Per the spec's fix-availability user
    story, a Vulnerability with a fix scores higher than an otherwise
    identical one without - actionability outranks theoretical risk here.
    """
    severity_component = SEVERITY_SCORE.get(severity.upper(), SEVERITY_SCORE["UNKNOWN"])
    epss_component = max(0.0, min(epss_score, 1.0)) * 100
    kev_component = 100.0 if kev_listed else 0.0
    fix_component = 100.0 if fix_available else 0.0

    score = (
        SEVERITY_WEIGHT * severity_component
        + EPSS_WEIGHT * epss_component
        + KEV_WEIGHT * kev_component
        + FIX_WEIGHT * fix_component
    )
    return round(max(0.0, min(score, 100.0)))


def compute_candidate_set(connection: sqlite3.Connection, threat_intel: "ThreatIntelPort") -> None:
    """Dedupes every known Vulnerability by CVE, scores each, and persists
    the top `TARGET_CANDIDATE_SET_SIZE` to `candidate_priorities`.

    Deterministic and reproducible: reading the same `vulnerabilities` rows
    and the same threat intel snapshot twice produces the same Candidate
    Set both times, which is what the spec's "identical queue on two
    consecutive loads" requirement needs.

    Split into `fetch_vulnerability_rows`, `score_candidate_set` and
    `store_candidate_set` so a caller holding a lock around `connection`
    (see aidevops.app) only holds it across the two quick SQL steps, not
    across the scoring pass in between - the same shape
    aidevops.reconcile splits scanning out of its own DB-locked steps for.
    """
    rows = fetch_vulnerability_rows(connection)
    candidates = score_candidate_set(rows, threat_intel)
    store_candidate_set(connection, candidates)


def fetch_vulnerability_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT cve_id, severity, fixed_version FROM vulnerabilities ORDER BY cve_id"
    ).fetchall()


def score_candidate_set(rows: list[sqlite3.Row], threat_intel: "ThreatIntelPort") -> list[tuple[str, int]]:
    """Pure computation, no `connection` involved - only in-memory threat
    intel lookups - so it never needs to run under the DB lock.
    """
    deduped = _dedupe_by_cve(rows)

    scored: list[tuple[str, int]] = []
    for dedup in deduped:
        intel = threat_intel.lookup(dedup.cve_id)
        scored.append(
            (dedup.cve_id, base_priority(dedup.severity, intel.epss_score, intel.kev_listed, dedup.fix_available))
        )
    # Highest score first; CVE ID as a stable tiebreaker so an unchanged
    # cluster's Candidate Set - and its order - never depends on dict or
    # SQLite iteration order.
    scored.sort(key=lambda item: (-item[1], item[0]))
    return scored[:TARGET_CANDIDATE_SET_SIZE]


def store_candidate_set(connection: sqlite3.Connection, candidates: list[tuple[str, int]]) -> None:
    connection.execute("DELETE FROM candidate_priorities")
    connection.executemany(
        "INSERT INTO candidate_priorities (cve_id, base_priority) VALUES (?, ?)",
        candidates,
    )
    connection.commit()


def _dedupe_by_cve(rows: list[sqlite3.Row]) -> list[_DedupedVulnerability]:
    """One CVE can appear across several images and packages. Its
    consolidated Severity is the worst seen anywhere it appears, and it
    counts as fix-available if a fix exists in at least one of them - both
    choices favour not under-selling a Vulnerability that dedup could
    otherwise hide.
    """
    by_cve: dict[str, _DedupedVulnerability] = {}
    for row in rows:
        cve_id = row["cve_id"]
        severity = (row["severity"] or "UNKNOWN").upper()
        fix_available = row["fixed_version"] is not None

        existing = by_cve.get(cve_id)
        if existing is None:
            by_cve[cve_id] = _DedupedVulnerability(cve_id, severity, fix_available)
            continue

        worse_severity = (
            severity
            if SEVERITY_SCORE.get(severity, 0) > SEVERITY_SCORE.get(existing.severity, 0)
            else existing.severity
        )
        by_cve[cve_id] = _DedupedVulnerability(
            cve_id, worse_severity, existing.fix_available or fix_available
        )

    return list(by_cve.values())
