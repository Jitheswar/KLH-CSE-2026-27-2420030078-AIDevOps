.PHONY: run test tools cluster-up seed cluster-down

export PATH := $(CURDIR)/bin:$(PATH)

CLUSTER_NAME := aidevops

# Starts the platform on the host, reading configuration from .env if present.
run:
	uv run $(if $(wildcard .env),--env-file .env,) uvicorn aidevops.main:app --app-dir src --reload

test:
	uv run pytest

# Installs kubectl and kind into ./bin if they are absent from the
# development machine.
tools:
	./scripts/ensure-tools.sh

# Brings up a kind cluster with ingress-nginx installed, then seeds it with
# the five Workloads the spec describes. Safe to run again after
# `cluster-down`: kind refuses to recreate a cluster that already exists,
# but a fresh `cluster-down` followed by `cluster-up` always returns to a
# working state.
cluster-up: tools
	kind create cluster --name $(CLUSTER_NAME) --config deploy/kind/kind-config.yaml
	kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/kind/deploy.yaml
	# The controller Pod does not exist the instant the Deployment is
	# applied, and `kubectl wait` errors immediately rather than waiting
	# when its selector matches nothing yet - so wait for it to appear
	# before waiting for it to become ready.
	until kubectl get pods --namespace ingress-nginx \
		--selector=app.kubernetes.io/component=controller \
		--no-headers 2>/dev/null | grep -q .; do sleep 1; done
	kubectl wait --namespace ingress-nginx \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/component=controller \
		--timeout=180s

seed: tools
	kubectl apply -f deploy/seed/
	kubectl wait --for=condition=available --timeout=300s deployment --all --all-namespaces

# Tears the cluster down completely. `cluster-up` after this returns the
# platform to a working state with no manual cleanup.
cluster-down: tools
	kind delete cluster --name $(CLUSTER_NAME)
