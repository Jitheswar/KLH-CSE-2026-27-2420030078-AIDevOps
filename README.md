# AIDevOps

_Project title: Contextual Priority Platform_

## Team

| Name | ID Number |
|---|---|
| Ch. Jitheswar | 2420030078 |
| N. Rithvik Sai | 2420030333 |
| V. Abhignan | 2420030731 |

**Branch:** CSE
**Academic Year:** 2026-27

## Supervisor

TBD

## Abstract

A container image scanner pointed at a realistic Kubernetes cluster returns well over a thousand vulnerabilities, each carrying a CVSS severity that is identical everywhere that CVE appears and blind to what the cluster is actually doing right now.
A critical CVE in a container nothing can reach is noise; a medium CVE in a container that is, at this moment, reachable from outside and behaving abnormally is the thing to look at first.
Severity alone cannot tell those two cases apart.

This project treats a vulnerability's urgency as a property of the running cluster rather than of the CVE record alone.
The platform discovers what is deployed in a Kubernetes cluster, scans the images those workloads run, and continuously models each workload's normal runtime behaviour from its own telemetry history.
When a workload starts behaving abnormally, that becomes an exposure signal attached to it, and the vulnerabilities in its images are re-triaged and rise in a single ranked queue.
Each row in that queue carries a contextual priority, the underlying severity beside it so the two can be compared, a written rationale grounded in that specific cluster, and a badge when the workload is currently under an exposure signal.
An operator can toggle a language model's contribution off and re-render the queue, to see precisely what it changed.

The deliverable is a single Python service (FastAPI, SQLite, server-rendered HTMX) that runs against a seeded local Kubernetes cluster with five workloads of deliberately different risk profiles, plus a scripted, reproducible compromise scenario used to exercise detection end to end.

## Folder Structure

- `/src` - Source code.
- `/docs` - Design documents, diagrams, and reference material.
- `/data` - Datasets used by the project, or a reference to where the data is hosted if it is not stored in this repository. See `data/README.md`.
- `/results` - Generated outputs, metrics, and experiment results.
- `/reports` - Written reports and submission documents.
- `/deploy` - Kubernetes manifests for the local kind cluster: cluster config, ingress-nginx wiring, the seeded Workloads, Prometheus, and the platform's own in-cluster deployment (`deploy/platform/`). See `make cluster-up`, `make seed`, `make prometheus-up`, and `make platform-deploy` / `make platform-down`.
- `/scenarios` - Scripted, reproducible compromise simulations used to exercise detection. Deliberately not part of the platform; see `scenarios/README.md` and `docs/adr/0006-attack-simulation-stays-outside-the-platform.md`.

## Setup and Execution Instructions

### Prerequisites

The Makefile installs `kubectl`, `kind` and `trivy` into `./bin` itself if they are not already on `PATH` (see `make tools` below), so only these need to already be present on the machine:

- [uv](https://docs.astral.sh/uv/) (Python 3.14 is pinned in `pyproject.toml`; `uv` installs it automatically if missing)
- [Docker](https://docs.docker.com/get-docker/), running and reachable from the current user

Everything below is run from the repository root.
`export PATH="$PWD/bin:$PATH"` is only needed if you want to call `kubectl`/`kind`/`trivy` directly outside the Makefile; every Makefile target already puts `./bin` on `PATH` for itself.

### Configuration

Configuration is read from environment variables, documented by name (never by value) in `.env.example`.
Copy it before running anything that needs it:

```
cp .env.example .env
```

- `DATABASE_PATH` - path to the SQLite file. Optional; defaults to `aidevops.db` in the repository root when unset.
- `INVENTORY_PERIOD_SECONDS` - seconds between automatic inventory-and-scan reconciliations. Optional; defaults to `60`.
- `PROMETHEUS_URL` - base URL of the Prometheus instance from `make prometheus-up`. Optional on the host; defaults to `http://localhost:9090`, which matches the port `deploy/kind/kind-config.yaml` maps out of the kind node.
- `DEEPSEEK_API_KEY` - API key for DeepSeek, used by the Triage model port. Required for the model to actually score anything; the platform still runs and serves the queue without it, with every row's Triage recorded as failed/unavailable rather than considered (see `docs/adr/0004-contextual-priority-is-bounded-llm-adjustment.md`).
- `DEEPSEEK_BASE_URL` - base URL of the DeepSeek API. Optional; defaults to `https://api.deepseek.com`.

`.env` is gitignored.
Never commit it, and never put a real value anywhere else in the repository.

### Makefile targets

Every target below is run as `make <target>` from the repository root.

| Target | What it does |
|---|---|
| `tools` | Installs `kubectl`, `kind` and `trivy` into `./bin` if not already on `PATH`. A dependency of every other target that touches the cluster, Trivy, or the host run, so it rarely needs to be called on its own. |
| `run` | Starts the platform on the host with `uvicorn --reload`, reading configuration from `.env` if present. Uses the real cluster inventory, real Trivy, real Prometheus and real DeepSeek ports; needs `cluster-up`, `seed` and `prometheus-up` first for inventory and telemetry to return anything. |
| `test` | Runs the fast test suite (Seam A: the application in-process against all five ports faked). No cluster, no network, no subprocess; completes in seconds. |
| `test-live` | Runs the two Seam B tests against a real cluster (`tests/test_seam_b_live.py`). Needs `cluster-up`, `seed` and `prometheus-up` first, and takes tens of minutes, since the detector needs that much real telemetry history before it will call anything anomalous. Excluded from `test` so the fast suite stays fast. |
| `cluster-up` | Brings up a local kind cluster named `aidevops` with ingress-nginx installed. Safe to re-run after `cluster-down`; kind refuses to recreate a cluster that already exists. |
| `seed` | Applies the five seeded Workloads under `deploy/seed/` and waits for them to become available. |
| `prometheus-up` | Deploys a plain Prometheus into the cluster, scraping the kubelet's cAdvisor endpoint on every node at 15 second resolution. No operator, no Grafana. |
| `cluster-down` | Tears the kind cluster down completely. `cluster-up` afterwards returns to a working state with no manual cleanup. |
| `scenario-miner-build` | Builds the miner Scenario's image and loads it into the kind cluster. Not part of the platform; see `scenarios/README.md`. |
| `scenario-miner-start` | Injects the miner Scenario into the internet-facing `nginx-legacy` Workload's already-running pod as an ephemeral container, and records the moment it comes up as ground truth for `test-live`. Builds the image first if needed. |
| `scenario-miner-stop` | Removes the miner Scenario by restarting the `nginx-legacy` rollout, returning the Workload to the shape `deploy/seed/01-nginx-legacy.yaml` describes. |
| `platform-build` | Builds the platform's own image and loads it into the kind cluster. |
| `platform-deploy` | Deploys the platform into the cluster it watches, under its own least-privilege ServiceAccount (see `deploy/platform/`). Requires `.env` to exist locally; builds a Kubernetes Secret from it that is never written to a file or manifest. Builds the image first if needed. |
| `platform-down` | Removes everything `platform-deploy` created, including the Secret, by deleting the `aidevops` namespace. |

### Demonstration sequence

This is the order that takes a clean checkout to a working platform with a detected compromise, on the host, against a real cluster:

```
cp .env.example .env        # fill in DEEPSEEK_API_KEY to see considered Triage rationale;
                             # the platform runs without it, with Triage recorded as failed

make cluster-up              # kind cluster + ingress-nginx
make seed                    # the five seeded Workloads
make prometheus-up           # Prometheus scraping cAdvisor

make run                     # starts the platform on the host at http://localhost:8000
                              # leave this running in its own terminal
```

With the platform running, in a second terminal:

```
make scenario-miner-start    # injects the miner Scenario into nginx-legacy
```

Watch the queue at `http://localhost:8000`: the CVEs on `nginx-legacy` rise as the detector accumulates enough anomalous windows to fire an exposure signal, and the workload's detail view shows its telemetry, Baseline band and the triggering window once it does.

```
make scenario-miner-stop     # removes the Scenario, nginx-legacy returns to normal
```

To also see the platform running inside the cluster it watches, rather than on the host:

```
make platform-deploy         # builds the image, loads it into kind, deploys into the
                              # aidevops namespace, reachable in-cluster only
make platform-down           # tears that back down
```

To tear everything down:

```
make cluster-down
```

## Current Phase Status

**Phase 2: Implementation Complete**
The Contextual Priority Platform is implemented: cluster discovery and scanning, threat-intel-informed pre-filtering, LLM-adjusted Triage, telemetry-based exposure detection, the queue and workload detail views, the seeded local cluster, the miner Scenario, and both the host and in-cluster deployment paths.
See `docs/adr/` for the recorded design decisions.
