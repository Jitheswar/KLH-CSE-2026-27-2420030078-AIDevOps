# Data

Threat intel snapshots used by `aidevops.ports.threat_intel.RealThreatIntel`.
Both are point-in-time snapshots, not live feeds.
The platform never queries either source at request time; refreshing them is a manual, occasional act of replacing the file, not something the running service does.

## Data Source Reference

### `epss_scores.csv.gz`

EPSS (Exploit Prediction Scoring System) scores for every published CVE.
Source: FIRST.org, downloaded from `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`.
Format: gzipped CSV with columns `cve`, `epss`, `percentile`.
License: FIRST.org publishes EPSS data for public use; see `https://www.first.org/epss/`.
Snapshot date is recorded in the file's own header comment (`score_date`).

### `kev.json`

The CISA Known Exploited Vulnerabilities (KEV) catalog, trimmed to the CVE IDs the platform needs.
Source: CISA, downloaded from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
Format: JSON object with `catalog_version`, `date_released`, `count`, and `cve_ids` (a sorted list of CVE identifiers currently in the catalog).
License: public domain, US government work.
