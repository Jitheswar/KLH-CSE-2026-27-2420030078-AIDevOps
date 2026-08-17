"""Seam A: the real application, in-process, with all five ports faked.

Drives the app over HTTP and asserts on the response, per the spec's
testing decisions. Nothing here reaches inside the app to check internals.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_empty_queue_renders_without_erroring(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "The queue is empty." in response.text


def test_schema_survives_a_restart(tmp_path) -> None:
    from aidevops.db import connect

    database_path = str(tmp_path / "aidevops.db")

    first_connection = connect(database_path)
    first_connection.close()

    second_connection = connect(database_path)
    tables = {
        row["name"]
        for row in second_connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    second_connection.close()

    assert "workloads" in tables
    assert "vulnerabilities" in tables
