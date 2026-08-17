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
-- any later model adjustment (a later ticket), per ADR-0004 and the spec's
-- requirement that the toggle be a re-render rather than a recomputation.
CREATE TABLE IF NOT EXISTS candidate_priorities (
    cve_id TEXT PRIMARY KEY,
    base_priority INTEGER NOT NULL
);
"""


def connect(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    connection.commit()
    return connection
