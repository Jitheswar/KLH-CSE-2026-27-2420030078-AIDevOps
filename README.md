# AIDevOps

_Project title: Contextual Priority Platform_

[![tests](https://github.com/Jitheswar/KLH-CSE-2026-27-2420030078-AIDevOps/actions/workflows/tests.yml/badge.svg)](https://github.com/Jitheswar/KLH-CSE-2026-27-2420030078-AIDevOps/actions/workflows/tests.yml)

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

## What it does

Scan the container images in a real Kubernetes cluster and you get over a thousand vulnerabilities. Each one has a severity score that is the same everywhere that CVE shows up, and says nothing about what the cluster is doing right now. A critical CVE in a container nothing can reach is noise. A medium one in a container that is reachable from outside and acting strangely should be looked at first.

This project ranks vulnerabilities by how urgent they are in the running cluster, not just by their CVE record. It:

1. finds what's deployed in the cluster and scans those images
2. learns what normal behavior looks like for each workload from its own metrics
3. flags a workload as exposed when it starts behaving abnormally, and moves the vulnerabilities in its images up the queue

Each row in the queue shows the contextual priority, the original severity next to it, a written reason specific to that cluster, and a badge if the workload is currently flagged. You can switch the language model's part off and re-render the queue to see what it changed.

It's one Python service (FastAPI, SQLite, server-rendered HTMX). It runs against a local Kubernetes cluster with five workloads of different risk levels, plus a scripted attack scenario for testing detection end to end.

## Folders

- `/src` source code
- `/docs` design documents and diagrams (decisions are in `docs/adr/`)
- `/data` datasets (see `data/README.md`)
- `/results` generated outputs and metrics
- `/reports` written reports and submission documents
- `/deploy` Kubernetes manifests for the local kind cluster: cluster config, ingress-nginx, the five workloads, Prometheus, and the platform's own deployment (`deploy/platform/`)
- `/scenarios` scripted attack simulations. These are deliberately not part of the platform (see `scenarios/README.md` and `docs/adr/0006-attack-simulation-stays-outside-the-platform.md`).

## Setup

You need [uv](https://docs.astral.sh/uv/) (it installs the pinned Python 3.14 for you) and [Docker](https://docs.docker.com/get-docker/), running. The Makefile installs `kubectl`, `kind` and `trivy` into `./bin` if they're missing. Run everything from the repo root.

Settings come from environment variables, listed by name in `.env.example`:

```
cp .env.example .env
```

| Variable | Default | What it's for |
|---|---|---|
| `DATABASE_PATH` | `aidevops.db` in the repo root | SQLite file |
| `INVENTORY_PERIOD_SECONDS` | `60` | seconds between cluster scans |
| `PROMETHEUS_URL` | `http://localhost:9090` | Prometheus from `make prometheus-up` |
| `DEEPSEEK_API_KEY` | none | needed for the model to score anything. Without it the platform still runs and shows the queue, with each row's triage marked failed (see `docs/adr/0004-contextual-priority-is-bounded-llm-adjustment.md`). |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek API address |

`.env` is gitignored. Never commit it.

## Demo

From a clean checkout to a detected attack:

```
cp .env.example .env     # add DEEPSEEK_API_KEY to see the written rationale

make cluster-up          # kind cluster + ingress-nginx
make seed                # the five workloads
make prometheus-up       # Prometheus scraping cAdvisor

make run                 # platform at http://localhost:8000, leave it running
```

In a second terminal:

```
make scenario-miner-start    # injects a crypto-miner into nginx-legacy
```

Watch the queue at http://localhost:8000. The CVEs on `nginx-legacy` move up once the detector has seen enough abnormal windows, and the workload page shows its metrics, its normal band and the window that triggered the flag.

```
make scenario-miner-stop     # removes it, nginx-legacy goes back to normal
```

To run the platform inside the cluster instead of on your machine:

```
make platform-deploy     # builds the image and deploys it to the aidevops namespace
make platform-down       # removes it
```

To tear everything down: `make cluster-down`.

## Make targets

| Target | What it does |
|---|---|
| `tools` | Installs `kubectl`, `kind` and `trivy` into `./bin` if missing. Other targets call it for you. |
| `run` | Starts the platform on your machine with `uvicorn --reload`. Needs `cluster-up`, `seed` and `prometheus-up` first to have any data. |
| `test` | Fast tests: the app in-process with all five outside connections faked. No cluster or network. Takes seconds. |
| `test-live` | Two tests against a real cluster. Needs `cluster-up`, `seed` and `prometheus-up`, and takes tens of minutes because the detector needs real history. |
| `cluster-up` / `cluster-down` | Create or fully remove the kind cluster named `aidevops`. |
| `seed` | Applies the five workloads in `deploy/seed/` and waits until they're up. |
| `prometheus-up` | Deploys a plain Prometheus scraping the kubelet's cAdvisor every 15 seconds. |
| `scenario-miner-build` | Builds the miner scenario's image and loads it into the cluster. |
| `scenario-miner-start` | Injects the miner into `nginx-legacy` and records when it started, for `test-live`. Builds the image first if needed. |
| `scenario-miner-stop` | Restarts the `nginx-legacy` rollout to remove it. |
| `platform-build` | Builds the platform's image and loads it into the cluster. |
| `platform-deploy` | Deploys the platform into the cluster with a least-privilege service account. Needs a local `.env`, which becomes a Kubernetes Secret and is never written to a file. |
| `platform-down` | Deletes the `aidevops` namespace and everything in it. |

## Status

Phase 2 is done. The platform is built: cluster discovery and scanning, threat-intel pre-filtering, model-adjusted triage, metrics-based exposure detection, the queue and workload pages, the local cluster, the miner scenario, and both ways of running it (on your machine and in the cluster). Design decisions are in `docs/adr/`.
