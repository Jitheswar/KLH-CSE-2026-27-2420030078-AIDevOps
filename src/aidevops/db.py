"""SQLite persistence.

The schema is created idempotently on first connection, so a restart against
an existing database file finds its tables already there rather than
recreating them.
"""

from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS workloads (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    externally_reachable INTEGER NOT NULL DEFAULT 0,
    UNIQUE (namespace, name)
);

CREATE TABLE IF NOT EXISTS workload_pods (
    id INTEGER PRIMARY KEY,
    workload_id INTEGER NOT NULL REFERENCES workloads (id) ON DELETE CASCADE,
    pod_name TEXT NOT NULL
);

-- `scanning` is a claim, distinct from `scanned_at`: reconcile_workloads
-- sets it the moment a pass decides an image needs scanning, under
-- db_lock, so a second reconcile pass racing the first - e.g. the
-- periodic loop's immediate first tick overlapping a manual rescan - sees
-- the claim and does not queue the same digest for a second, redundant
-- scan. A failed scan clears the claim so the next reconcile retries it -
-- see aidevops.reconcile.
CREATE TABLE IF NOT EXISTS images (
    digest TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    scanned_at TEXT,
    scanning INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS workload_images (
    workload_id INTEGER NOT NULL REFERENCES workloads (id) ON DELETE CASCADE,
    image_digest TEXT NOT NULL REFERENCES images (digest),
    PRIMARY KEY (workload_id, image_digest)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT NOT NULL,
    image_digest TEXT NOT NULL REFERENCES images (digest),
    package TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version TEXT,
    severity TEXT NOT NULL,
    cvss_vector TEXT,
    description TEXT,
    PRIMARY KEY (cve_id, image_digest, package)
);

-- One row per CVE that survived the pre-filter (see aidevops.candidates).
-- base_priority is the deterministic score computed from Severity, EPSS,
-- KEV membership and fix availability - stored on its own, independently of
-- any later model adjustment (a later ticket), per ADR-0004 and the spec's
-- requirement that the toggle be a re-render rather than a recomputation.
CREATE TABLE IF NOT EXISTS candidate_priorities (
    cve_id TEXT PRIMARY KEY,
    base_priority INTEGER NOT NULL
);

-- Whether a Workload currently carries an Exposure Signal, per the
-- fire-after-2/clear-after-3 hysteresis in aidevops.exposure_signal. The
-- detection loop recomputes this from scratch on every pass - see
-- aidevops.detection - so this table is a cache of that computation for the
-- queue and Workload detail views to read, not state the loop accumulates
-- into incrementally.
CREATE TABLE IF NOT EXISTS exposure_signals (
    workload_id INTEGER PRIMARY KEY REFERENCES workloads (id) ON DELETE CASCADE,
    active INTEGER NOT NULL DEFAULT 0
);

-- Per ADR-0004, cached keyed on the CVE, the image, and the Workload's
-- Exposure Signal state (see aidevops.domain.ExposureSignalState.cache_key)
-- so a signal transition invalidates exactly the Triages it should, simply
-- by changing which row a lookup lands on. `failed` rows are retried on the
-- next reconcile rather than treated as a permanent cache hit, so a
-- transient model outage self-heals.
CREATE TABLE IF NOT EXISTS triage_results (
    cve_id TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    exposure_signal_state TEXT NOT NULL,
    adjustment INTEGER NOT NULL,
    rationale TEXT NOT NULL,
    failed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cve_id, image_digest, exposure_signal_state)
);
"""


def connect(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    connection.commit()
    return connection
