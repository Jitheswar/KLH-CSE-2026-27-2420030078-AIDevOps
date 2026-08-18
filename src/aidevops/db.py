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
    scanned_at TEXT
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
-- the model's adjustment (see aidevops.triage), per ADR-0004 and the spec's
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
    active INTEGER NOT NULL DEFAULT 0,
    magnitude REAL NOT NULL DEFAULT 0.0,
    window_start TEXT,
    fired_at TEXT
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

# Columns added after a table's first release. `CREATE TABLE IF NOT EXISTS`
# is a no-op against a database file that already has the table, so a
# column introduced later has to be added explicitly - see `_migrate` -
# or a restart against an existing `DATABASE_PATH` finds the old, narrower
# table and every query naming the new column fails.
#
# `images.scanning` and `triage_results.claimed` are both in-flight claims
# a reconcile pass takes out before doing the slow, unlocked work (a Trivy
# scan, a DeepSeek call) the claim is guarding - see aidevops.reconcile and
# aidevops.triage. Neither can legitimately still be held the moment a
# process starts: whatever was claiming it no longer exists. `_migrate`
# resets both to unclaimed on every connect, so a crash between claiming
# and releasing does not orphan the claim forever.
_MIGRATIONS: list[tuple[str, str, str]] = [
    ("images", "scanning", "ALTER TABLE images ADD COLUMN scanning INTEGER NOT NULL DEFAULT 0"),
    ("triage_results", "claimed", "ALTER TABLE triage_results ADD COLUMN claimed INTEGER NOT NULL DEFAULT 0"),
    ("exposure_signals", "magnitude", "ALTER TABLE exposure_signals ADD COLUMN magnitude REAL NOT NULL DEFAULT 0.0"),
    ("exposure_signals", "window_start", "ALTER TABLE exposure_signals ADD COLUMN window_start TEXT"),
    ("exposure_signals", "fired_at", "ALTER TABLE exposure_signals ADD COLUMN fired_at TEXT"),
]


def _migrate(connection: sqlite3.Connection) -> None:
    for table, column, ddl in _MIGRATIONS:
        existing_columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing_columns:
            connection.execute(ddl)
    connection.execute("UPDATE images SET scanning = 0 WHERE scanning != 0")
    connection.execute("UPDATE triage_results SET claimed = 0 WHERE claimed != 0")
    connection.commit()


def connect(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    # SQLite ignores ON DELETE CASCADE unless foreign key enforcement is
    # turned on per connection - without this, deleting a Workload leaves
    # its exposure_signals row behind, and a redeployed Workload that
    # reuses the freed rowid inherits the stale signal.
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA)
    connection.commit()
    _migrate(connection)
    return connection
