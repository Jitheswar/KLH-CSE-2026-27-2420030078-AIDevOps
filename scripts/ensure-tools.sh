#!/usr/bin/env bash
# Installs kubectl, kind and trivy into ./bin if they are not already on
# PATH. None of the three is present on the development machine per the
# spec, and this script is what the Makefile's cluster and run targets
# depend on before touching any of them.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR"

KIND_VERSION="v0.30.0"
TRIVY_VERSION="$(cat "$ROOT_DIR/.trivy-version")"

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

if command -v trivy >/dev/null 2>&1 || [ -x "$BIN_DIR/trivy" ]; then
    echo "trivy already available"
else
    echo "Installing trivy $TRIVY_VERSION into $BIN_DIR"
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b "$BIN_DIR" "$TRIVY_VERSION"
fi
