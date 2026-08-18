#!/usr/bin/env bash
# Reverses start.sh: stops the platform running on the host, then tears
# down the kind cluster (which takes Prometheus and the seeded Workloads
# down with it).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# `make run` runs uvicorn with --reload, which forks a reloader process
# that owns a worker child - killing only the parent leaves the worker
# running, so match on the uvicorn invocation itself.
if pkill -f "uvicorn aidevops.main:app" 2>/dev/null; then
    echo "Stopped the platform"
else
    echo "Platform was not running"
fi

make cluster-down
