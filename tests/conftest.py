from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aidevops.app import Ports, create_app
from aidevops.db import connect
from aidevops.ports.cluster_inventory import FakeClusterInventory
from aidevops.ports.image_scanner import FakeImageScanner
from aidevops.ports.telemetry import FakeTelemetry
from aidevops.ports.threat_intel import FakeThreatIntel
from aidevops.ports.triage_model import FakeTriageModel


@pytest.fixture
def db_connection() -> Iterator[sqlite3.Connection]:
    connection = connect(":memory:")
    yield connection
    connection.close()


@pytest.fixture
def fake_ports() -> Ports:
    return Ports(
        cluster_inventory=FakeClusterInventory(),
        telemetry=FakeTelemetry(),
        image_scanner=FakeImageScanner(),
        threat_intel=FakeThreatIntel(),
        triage_model=FakeTriageModel(),
    )


@pytest.fixture
def app(db_connection: sqlite3.Connection, fake_ports: Ports) -> FastAPI:
    return create_app(db_connection, fake_ports)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
