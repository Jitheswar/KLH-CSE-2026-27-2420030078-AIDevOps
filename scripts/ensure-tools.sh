#!/usr/bin/env bash
# Installs kubectl and kind into ./bin if they are not already on PATH.
# Neither is present on the development machine per the spec, and this
# script is what the Makefile's cluster targets depend on before touching
# either tool.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR"

KIND_VERSION="v0.30.0"

if command -v kubectl >/dev/null 2>&1 || [ -x "$BIN_DIR/kubectl" ]; then
    echo "kubectl already available"
else
    echo "Installing kubectl into $BIN_DIR"
    KUBECTL_VERSION="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
    curl -fsSLo "$BIN_DIR/kubectl" "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
    chmod +x "$BIN_DIR/kubectl"
fi

if command -v kind >/dev/null 2>&1 || [ -x "$BIN_DIR/kind" ]; then
    echo "kind already available"
else
    echo "Installing kind into $BIN_DIR"
    curl -fsSLo "$BIN_DIR/kind" "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
    chmod +x "$BIN_DIR/kind"
fi
