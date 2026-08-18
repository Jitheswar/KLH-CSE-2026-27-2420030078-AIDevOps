#!/usr/bin/env bash
# Brings a clean checkout up to a running platform, following the
# demonstration sequence in README.md: cluster, seed, Prometheus, then the
# platform itself on the host at http://localhost:8000.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -f .env ]; then
    echo "No .env found - copying .env.example to .env"
    echo "Fill in DEEPSEEK_API_KEY afterwards to see considered Triage rationale;"
    echo "the platform still runs without it, with Triage recorded as failed."
    cp .env.example .env
fi

make cluster-up
make seed
make prometheus-up

echo "Starting the platform at http://localhost:8000 (Ctrl-C to stop)"
make run
