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

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_path=os.environ.get("DATABASE_PATH") or "aidevops.db",
        )
