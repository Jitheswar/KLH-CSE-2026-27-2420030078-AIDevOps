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

if curl -sf -o /dev/null http://localhost:8000/docs 2>/dev/null; then
    echo "Platform already running at http://localhost:8000"
    exit 0
fi

make tools
export PATH="$PWD/bin:$PATH"
if kind get clusters 2>/dev/null | grep -qx aidevops; then
    echo "kind cluster \"aidevops\" already exists, reusing it"
else
    make cluster-up
fi
make seed
make prometheus-up

make run &
RUN_PID=$!
trap 'kill "$RUN_PID" 2>/dev/null' EXIT

echo "Waiting for the platform to come up..."
until curl -sf -o /dev/null http://localhost:8000/docs 2>/dev/null; do
    if ! kill -0 "$RUN_PID" 2>/dev/null; then
        echo "Platform process exited before it came up" >&2
        exit 1
    fi
    sleep 1
done

echo ""
echo "Platform running at http://localhost:8000 (Ctrl-C to stop)"
echo ""
wait "$RUN_PID"
