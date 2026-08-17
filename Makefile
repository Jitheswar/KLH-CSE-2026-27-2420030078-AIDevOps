.PHONY: run test tools cluster-up seed cluster-down scenario-miner-build scenario-miner-start scenario-miner-stop

export PATH := $(CURDIR)/bin:$(PATH)

CLUSTER_NAME := aidevops
SCENARIO_MINER_IMAGE := aidevops-miner-scenario:latest
SCENARIO_MINER_DEPLOYMENT := nginx-legacy
SCENARIO_MINER_NAMESPACE := web

# Starts the platform on the host, reading configuration from .env if
# present. Depends on `tools` because the real image scanner shells out to
# trivy directly.
run: tools
	uv run $(if $(wildcard .env),--env-file .env,) uvicorn aidevops.main:app --app-dir src --reload

test:
	uv run pytest

# Installs kubectl, kind and trivy into ./bin if they are absent from the
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

# Builds the miner Scenario's image and loads it into the kind cluster.
# Not part of the platform - see scenarios/README.md and ADR-0006.
scenario-miner-build: tools
	docker build -t $(SCENARIO_MINER_IMAGE) scenarios/miner
	kind load docker-image $(SCENARIO_MINER_IMAGE) --name $(CLUSTER_NAME)

# Injects the miner Scenario into the internet-facing nginx Workload and
# records the moment it comes up as ground truth for the Seam B tests.
scenario-miner-start: scenario-miner-build
	kubectl patch deployment $(SCENARIO_MINER_DEPLOYMENT) \
		--namespace $(SCENARIO_MINER_NAMESPACE) \
		--type=strategic \
		-p "$$(sed 's|aidevops-miner-scenario:latest|$(SCENARIO_MINER_IMAGE)|' scenarios/miner/inject-patch.yaml)"
	kubectl rollout status deployment/$(SCENARIO_MINER_DEPLOYMENT) \
		--namespace $(SCENARIO_MINER_NAMESPACE) --timeout=120s
	mkdir -p scenarios/miner/.state
	date -u +%Y-%m-%dT%H:%M:%SZ > scenarios/miner/.state/started-at
	echo "Scenario started at $$(cat scenarios/miner/.state/started-at)"

# Removes the miner Scenario and returns the Workload to the shape
# deploy/seed/01-nginx-legacy.yaml describes.
scenario-miner-stop: tools
	kubectl patch deployment $(SCENARIO_MINER_DEPLOYMENT) \
		--namespace $(SCENARIO_MINER_NAMESPACE) \
		--type=strategic \
		--patch-file=scenarios/miner/remove-patch.yaml
	kubectl rollout status deployment/$(SCENARIO_MINER_DEPLOYMENT) \
		--namespace $(SCENARIO_MINER_NAMESPACE) --timeout=120s
	rm -f scenarios/miner/.state/started-at
