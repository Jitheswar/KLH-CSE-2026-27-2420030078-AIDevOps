"""Runs the Triage model over the Candidate Set and caches the result.

One model call per Vulnerability, not batched - see the spec: batching
would key the cache on a whole batch, which would break the surgical
re-Triage a later ticket depends on. Split into a locked fetch, an unlocked
run against the model port, and a locked store - the same shape
aidevops.reconcile and aidevops.app use for scanning, because a real model
call is a network request and must not happen while the caller's db_lock
(see aidevops.app) is held.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aidevops.domain import ExposureSignalState, TriageContext, Vulnerability
from aidevops.ports.threat_intel import ThreatIntelPort
from aidevops.ports.triage_model import TriageModelPort, TriageUnavailable, clamp_adjustment

if TYPE_CHECKING:
    from aidevops.app import Ports

logger = logging.getLogger(__name__)

# No Workload carries an Exposure Signal from this module's point of view -
# wiring Triage to react to one is signal-driven re-Triage (a later
# ticket). Every candidate is triaged at this fixed key until then.
_NO_SIGNAL = ExposureSignalState()


@dataclass(frozen=True)
class _TriageCandidate:
    context: TriageContext
    image_digest: str


@dataclass(frozen=True)
class _TriageOutcome:
    cve_id: str
    image_digest: str
    exposure_signal_state: str
    adjustment: int
    rationale: str
    failed: bool


def fetch_pending_triage_candidates(connection: sqlite3.Connection) -> list[_TriageCandidate]:
    """Every Candidate Set member that has no cached, successful Triage at
    its current Exposure Signal key. A `failed` cache row does not count as
    cached here, so a transient model outage is retried on the next
    reconcile rather than stuck forever - see aidevops.db's schema comment.

    One representative image is chosen per CVE - the lexicographically
    smallest digest among the images it appears in - so a CVE occurring in
    several images is still Triaged once, matching the spec's per-CVE
    dedup applied everywhere else in the Candidate Set.
    """
    rows = connection.execute(
        """
        SELECT
            cp.cve_id AS cve_id,
            v.image_digest AS image_digest,
            v.package AS package,
            v.installed_version AS installed_version,
            v.severity AS severity,
            v.description AS description,
            v.cvss_vector AS cvss_vector,
            v.fixed_version AS fixed_version,
            i.repository AS image_repository,
            w.name AS workload_name,
            w.namespace AS workload_namespace,
            w.externally_reachable AS externally_reachable
        FROM candidate_priorities cp
        JOIN vulnerabilities v ON v.cve_id = cp.cve_id
        JOIN images i ON i.digest = v.image_digest
        JOIN workload_images wi ON wi.image_digest = v.image_digest
        JOIN workloads w ON w.id = wi.workload_id
        ORDER BY cp.cve_id, v.image_digest, w.namespace, w.name
        """
    ).fetchall()

    cached = {
        (row["cve_id"], row["image_digest"])
        for row in connection.execute(
            "SELECT cve_id, image_digest FROM triage_results WHERE exposure_signal_state = ? AND failed = 0",
            (_NO_SIGNAL.cache_key(),),
        ).fetchall()
    }

    candidates: list[_TriageCandidate] = []
    seen_cves: set[str] = set()
    for row in rows:
        if row["cve_id"] in seen_cves:
            continue
        seen_cves.add(row["cve_id"])
        if (row["cve_id"], row["image_digest"]) in cached:
            continue

        vulnerability = Vulnerability(
            cve_id=row["cve_id"],
            package=row["package"],
            installed_version=row["installed_version"],
            severity=row["severity"],
            description=row["description"] or "",
            cvss_vector=row["cvss_vector"] or "",
            fixed_version=row["fixed_version"],
        )
        context = TriageContext(
            vulnerability=vulnerability,
            epss_score=0.0,
            kev_listed=False,
            image_repository=row["image_repository"],
            workload_name=row["workload_name"],
            workload_namespace=row["workload_namespace"],
            externally_reachable=bool(row["externally_reachable"]),
            exposure_signal=_NO_SIGNAL,
        )
        candidates.append(_TriageCandidate(context=context, image_digest=row["image_digest"]))
    return candidates


def enrich_with_threat_intel(
    candidates: list[_TriageCandidate], threat_intel: ThreatIntelPort
) -> list[_TriageCandidate]:
    """Threat intel lookups are in-memory dict reads, not a network call -
    see aidevops.ports.threat_intel.RealThreatIntel - but they still don't
    need `connection`, so this runs alongside the model calls, outside any
    lock, the same as aidevops.app's candidate scoring step.
    """
    enriched: list[_TriageCandidate] = []
    for candidate in candidates:
        intel = threat_intel.lookup(candidate.context.vulnerability.cve_id)
        context = TriageContext(
            vulnerability=candidate.context.vulnerability,
            epss_score=intel.epss_score,
            kev_listed=intel.kev_listed,
            image_repository=candidate.context.image_repository,
            workload_name=candidate.context.workload_name,
            workload_namespace=candidate.context.workload_namespace,
            externally_reachable=candidate.context.externally_reachable,
            exposure_signal=candidate.context.exposure_signal,
        )
        enriched.append(_TriageCandidate(context=context, image_digest=candidate.image_digest))
    return enriched


def run_triage_model(triage_model: TriageModelPort, candidates: list[_TriageCandidate]) -> list[_TriageOutcome]:
    """The network-calling half - no `connection` involved, so callers
    holding a lock around SQLite access (see aidevops.app) run this with
    no lock held, same reasoning as aidevops.reconcile.scan_pending_images.
    """
    outcomes: list[_TriageOutcome] = []
    for candidate in candidates:
        cve_id = candidate.context.vulnerability.cve_id
        try:
            result = triage_model.triage(candidate.context)
            outcomes.append(
                _TriageOutcome(
                    cve_id=cve_id,
                    image_digest=candidate.image_digest,
                    exposure_signal_state=candidate.context.exposure_signal.cache_key(),
                    adjustment=clamp_adjustment(result.adjustment),
                    rationale=result.rationale,
                    failed=False,
                )
            )
        except TriageUnavailable:
            # Per the spec: a failed or unavailable model call leaves the
            # base score standing and marks the row as such, so a fallback
            # ranking is never read as a considered one.
            logger.exception("triage failed for %s, base score stands", cve_id)
            outcomes.append(
                _TriageOutcome(
                    cve_id=cve_id,
                    image_digest=candidate.image_digest,
                    exposure_signal_state=candidate.context.exposure_signal.cache_key(),
                    adjustment=0,
                    rationale="Triage unavailable - showing the base score.",
                    failed=True,
                )
            )
    return outcomes


def store_triage_outcomes(connection: sqlite3.Connection, outcomes: list[_TriageOutcome]) -> None:
    for outcome in outcomes:
        connection.execute(
            """
            INSERT INTO triage_results (cve_id, image_digest, exposure_signal_state, adjustment, rationale, failed)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (cve_id, image_digest, exposure_signal_state)
            DO UPDATE SET adjustment = excluded.adjustment, rationale = excluded.rationale, failed = excluded.failed
            """,
            (
                outcome.cve_id,
                outcome.image_digest,
                outcome.exposure_signal_state,
                outcome.adjustment,
                outcome.rationale,
                int(outcome.failed),
            ),
        )
    connection.commit()


def run_triage(connection: sqlite3.Connection, ports: "Ports") -> None:
    """Composes every step for a caller with no lock to worry about - the
    reference shape aidevops.app's own locked composition follows, same
    relationship as aidevops.reconcile.reconcile has to aidevops.app.
    """
    candidates = fetch_pending_triage_candidates(connection)
    candidates = enrich_with_threat_intel(candidates, ports.threat_intel)
    outcomes = run_triage_model(ports.triage_model, candidates)
    store_triage_outcomes(connection, outcomes)
