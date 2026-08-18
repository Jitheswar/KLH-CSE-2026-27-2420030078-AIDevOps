"""Configuration read from the host environment.

Nothing in this module ever hardcodes a credential. Values come from
os.environ only, and the committed .env.example documents the required
keys without values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_path: str
    inventory_period_seconds: float
    telemetry_url: str
    triage_model_api_key: str
    triage_model_base_url: str

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_path=os.environ.get("DATABASE_PATH") or "aidevops.db",
            inventory_period_seconds=float(os.environ.get("INVENTORY_PERIOD_SECONDS") or 60.0),
            telemetry_url=os.environ.get("PROMETHEUS_URL") or "http://localhost:9090",
            triage_model_api_key=os.environ.get("DEEPSEEK_API_KEY") or "",
            triage_model_base_url=os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com",
        )
