"""Cluster inventory port.

Returns the current set of Workloads. The real implementation polls the
Kubernetes API; nothing above this interface may know that.
"""

from __future__ import annotations

from typing import Any, Protocol

from aidevops.domain import ContainerImage, Workload

# Namespaces that hold cluster machinery rather than seeded Workloads. A
# Deployment in one of these is never something an operator wants ranked.
_SYSTEM_NAMESPACES = frozenset(
    {"kube-system", "kube-node-lease", "kube-public", "ingress-nginx", "local-path-storage", "monitoring"}
)

# Service types that make a Service reachable from outside the cluster, per
# the spec's coarse Service-and-Ingress reachability proxy.
_EXTERNALLY_REACHABLE_SERVICE_TYPES = frozenset({"LoadBalancer", "NodePort"})


class ClusterInventoryPort(Protocol):
    def list_workloads(self) -> list[Workload]: ...


class FakeClusterInventory:
    def __init__(self, workloads: list[Workload] | None = None) -> None:
        self._workloads = workloads or []

    def list_workloads(self) -> list[Workload]:
        return list(self._workloads)

    def set_workloads(self, workloads: list[Workload]) -> None:
        """Test seam: lets Seam A tests script the inventory changing between rescans."""
        self._workloads = workloads


def parse_image_reference(image_id: str, fallback_repository: str) -> ContainerImage | None:
    """Turns a pod container status's imageID into a digest-pinned reference.

    `imageID` looks like `docker-pullable://nginx@sha256:...` under Docker or
    `<registry>/nginx@sha256:...` under containerd (what kind uses). Before a
    pod has finished pulling, imageID is empty - the caller skips it and
    picks it up on a later reconcile, the same way a slow first scan does.
    """
    if "@sha256:" not in image_id:
        return None

    repository, digest = image_id.rsplit("@", 1)
    repository = repository.removeprefix("docker-pullable://")
    return ContainerImage(repository=repository or fallback_repository, digest=digest)


def is_externally_reachable(service_types: set[str], has_routing_ingress: bool) -> bool:
    """The spec's coarse proxy: LoadBalancer/NodePort, or ClusterIP behind an Ingress."""
    return bool(service_types & _EXTERNALLY_REACHABLE_SERVICE_TYPES) or has_routing_ingress


def _selector_matches(selector: dict[str, str], labels: dict[str, str]) -> bool:
    return bool(selector) and all(labels.get(key) == value for key, value in selector.items())


class RealClusterInventory:
    """Polls the Kubernetes API for Deployments, their pods, and their reachability.

    Loads its client config the way `kubectl` does: `KUBECONFIG` if set,
    otherwise `~/.kube/config`, which is exactly what `kind create cluster`
    writes and points at.
    """

    def __init__(self) -> None:
        from kubernetes import client, config

        config.load_kube_config()
        self._apps = client.AppsV1Api()
        self._core = client.CoreV1Api()
        self._networking = client.NetworkingV1Api()

    def list_workloads(self) -> list[Workload]:
        deployments = self._apps.list_deployment_for_all_namespaces().items
        services = self._core.list_service_for_all_namespaces().items
        ingresses = self._networking.list_ingress_for_all_namespaces().items
        # One list call for every pod in the cluster, grouped in memory
        # below by Deployment selector - cheaper than a namespaced pod-list
        # call per Deployment and it scales the same way regardless of how
        # many Workloads are seeded.
        pods = self._core.list_pod_for_all_namespaces().items

        return [
            self._workload_from_deployment(deployment, pods, services, ingresses)
            for deployment in deployments
            if deployment.metadata.namespace not in _SYSTEM_NAMESPACES
        ]

    def _workload_from_deployment(
        self, deployment: Any, pods: list[Any], services: list[Any], ingresses: list[Any]
    ) -> Workload:
        namespace = deployment.metadata.namespace
        name = deployment.metadata.name
        selector = (deployment.spec.selector.match_labels or {}) if deployment.spec.selector else {}

        # An empty selector means this Deployment uses matchExpressions
        # rather than matchLabels (out of scope - the spec covers Deployment
        # kinds seeded with plain label selectors only); treat it as
        # matching no pods rather than guessing.
        matching_pods = [
            pod
            for pod in pods
            if pod.metadata.namespace == namespace and _selector_matches(selector, pod.metadata.labels or {})
        ]

        replica_pod_names = [pod.metadata.name for pod in matching_pods]
        images = _unique_images(matching_pods)

        namespace_services = [service for service in services if service.metadata.namespace == namespace]
        matching_services = [
            service
            for service in namespace_services
            if _selector_matches(service.spec.selector or {}, deployment.spec.template.metadata.labels or {})
        ]
        service_types = {service.spec.type for service in matching_services}
        matching_service_names = {service.metadata.name for service in matching_services}

        namespace_ingresses = [ingress for ingress in ingresses if ingress.metadata.namespace == namespace]
        has_routing_ingress = any(
            _ingress_routes_to(ingress, matching_service_names) for ingress in namespace_ingresses
        )

        return Workload(
            name=name,
            namespace=namespace,
            replica_pod_names=replica_pod_names,
            images=images,
            externally_reachable=is_externally_reachable(service_types, has_routing_ingress),
        )


def _unique_images(pods: list[Any]) -> list[ContainerImage]:
    images: dict[str, ContainerImage] = {}
    for pod in pods:
        for status in pod.status.container_statuses or []:
            image = parse_image_reference(status.image_id or "", fallback_repository=status.image)
            if image is not None:
                images[image.digest] = image
    return list(images.values())


def _ingress_routes_to(ingress: Any, service_names: set[str]) -> bool:
    for rule in ingress.spec.rules or []:
        if rule.http is None:
            continue
        for path in rule.http.paths or []:
            backend_service = path.backend.service
            if backend_service is not None and backend_service.name in service_names:
                return True
    return False
