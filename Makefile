.PHONY: run test test-live tools cluster-up seed cluster-down prometheus-up scenario-miner-build scenario-miner-start scenario-miner-stop

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
	uv run pytest -m "not live"

# Seam B: the two tests that run against a real cluster (see
# tests/test_seam_b_live.py). Needs `make cluster-up seed prometheus-up`
# first; takes tens of minutes, since the detector's Baseline needs that
# much real telemetry history before it will call anything anomalous.
# Deliberately excluded from `test` so the fast suite stays fast.
test-live: tools
	uv run pytest -m live

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

# Deploys a plain Prometheus into the cluster, scraping the kubelet's
# cAdvisor endpoint on every node at 15 second resolution. No operator, no
# Grafana - see ticket 07's port-boundary decision.
prometheus-up: tools
	kubectl apply -f deploy/prometheus/
	kubectl wait --namespace monitoring --for=condition=available --timeout=180s deployment/prometheus

# Builds the miner Scenario's image and loads it into the kind cluster.
# Not part of the platform - see scenarios/README.md and ADR-0006.
scenario-miner-build: tools
	docker build -t $(SCENARIO_MINER_IMAGE) scenarios/miner
	kind load docker-image $(SCENARIO_MINER_IMAGE) --name $(CLUSTER_NAME)

# Injects the miner Scenario into the internet-facing nginx Workload's
# already-running pod as an ephemeral container, and records the moment it
# comes up (Kubernetes' own timestamp for it) as ground truth for the Seam B
# tests. Deliberately not a Deployment template patch: adding a regular
# container to a pod's template forces Kubernetes to replace the pod under a
# new name, which throws away every second of Baseline history the detector
# had built up for it - the exact history a real compromise of the running
# container would never touch. An ephemeral container attaches to the pod
# that is already there, so its identity, and the detector's Baseline for
# it, survive injection - see scenarios/README.md.
scenario-miner-start: scenario-miner-build
	# A pod's `status.phase` stays Running while it is Terminating - a
	# selector alone can still match a just-replaced pod on its way out, so
	# this picks the newest by creation time rather than the selector's
	# first match.
	@pod="$$(kubectl get pod --namespace $(SCENARIO_MINER_NAMESPACE) \
		--selector=app=$(SCENARIO_MINER_DEPLOYMENT) --sort-by=.metadata.creationTimestamp \
		-o jsonpath='{.items[-1:].metadata.name}')"; \
	kubectl debug --namespace $(SCENARIO_MINER_NAMESPACE) "$$pod" \
		--image=$(SCENARIO_MINER_IMAGE) --image-pull-policy=Never \
		--container=miner-scenario --attach=false; \
	until kubectl get pod --namespace $(SCENARIO_MINER_NAMESPACE) "$$pod" \
		-o jsonpath='{.status.ephemeralContainerStatuses[?(@.name=="miner-scenario")].state.running.startedAt}' \
		2>/dev/null | grep -q .; do sleep 1; done; \
	mkdir -p scenarios/miner/.state; \
	kubectl get pod --namespace $(SCENARIO_MINER_NAMESPACE) "$$pod" \
		-o jsonpath='{.status.ephemeralContainerStatuses[?(@.name=="miner-scenario")].state.running.startedAt}' \
		> scenarios/miner/.state/started-at; \
	echo "Scenario started at $$(cat scenarios/miner/.state/started-at)"

# Removes the miner Scenario and returns the Workload to the shape
# deploy/seed/01-nginx-legacy.yaml describes. An ephemeral container cannot
# be removed from a running pod once added - a Kubernetes API restriction,
# not a choice made here - so the only way back to a clean pod is a new one.
# The Deployment's own pod template was never touched by `-start` above, so
# restarting its rollout is enough: the fresh pod it creates has no
# ephemeral container to begin with.
scenario-miner-stop: tools
	kubectl rollout restart deployment/$(SCENARIO_MINER_DEPLOYMENT) \
		--namespace $(SCENARIO_MINER_NAMESPACE)
	kubectl rollout status deployment/$(SCENARIO_MINER_DEPLOYMENT) \
		--namespace $(SCENARIO_MINER_NAMESPACE) --timeout=120s
	rm -f scenarios/miner/.state/started-at
