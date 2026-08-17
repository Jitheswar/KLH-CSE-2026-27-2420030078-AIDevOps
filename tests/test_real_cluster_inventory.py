"""Unit tests for the real cluster inventory's pure adapter logic.

These do not touch a live cluster - that is Seam B's job, for a later
ticket. What is tested here is deterministic parsing and derivation code
that has no Kubernetes API calls in it, so it does not fit Seam A's fakes
and does not pin any behavioural state machine either.
"""

from __future__ import annotations

from aidevops.domain import ContainerImage
from aidevops.ports.cluster_inventory import is_externally_reachable, parse_image_reference


def test_parses_a_containerd_image_reference() -> None:
    image = parse_image_reference(
        "docker.io/library/nginx@sha256:" + "a" * 64, fallback_repository="nginx:1.14.2"
    )

    assert image == ContainerImage(repository="docker.io/library/nginx", digest="sha256:" + "a" * 64)


def test_parses_a_docker_pullable_image_reference() -> None:
    image = parse_image_reference(
        "docker-pullable://nginx@sha256:" + "b" * 64, fallback_repository="nginx:1.14.2"
    )

    assert image == ContainerImage(repository="nginx", digest="sha256:" + "b" * 64)


def test_an_image_still_being_pulled_has_no_digest_yet() -> None:
    assert parse_image_reference("", fallback_repository="nginx:1.14.2") is None


def test_load_balancer_service_is_externally_reachable() -> None:
    assert is_externally_reachable({"LoadBalancer"}, has_routing_ingress=False) is True


def test_node_port_service_is_externally_reachable() -> None:
    assert is_externally_reachable({"NodePort"}, has_routing_ingress=False) is True


def test_cluster_ip_alone_is_not_externally_reachable() -> None:
    assert is_externally_reachable({"ClusterIP"}, has_routing_ingress=False) is False


def test_cluster_ip_behind_a_routing_ingress_is_externally_reachable() -> None:
    assert is_externally_reachable({"ClusterIP"}, has_routing_ingress=True) is True
