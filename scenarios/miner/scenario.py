#!/usr/bin/env python3
"""Miner Scenario: a simulated compromise, not real mining software.

Burns CPU with a busy loop of throwaway hash computations and opens a
short-lived outbound TCP connection at a fixed interval. This produces
the CPU-and-traffic correlation the platform's detector is built to
see, without running any mining software, contacting any pool, or
doing anything of value with the CPU cycles or the network bytes.
"""

import hashlib
import os
import socket
import threading
import time

CPU_WORKERS = int(os.environ.get("SCENARIO_CPU_WORKERS", "2"))
BEACON_INTERVAL_SECONDS = float(os.environ.get("SCENARIO_BEACON_INTERVAL_SECONDS", "5"))
BEACON_HOSTS = os.environ.get("SCENARIO_BEACON_HOSTS", "1.1.1.1,8.8.8.8,9.9.9.9").split(",")
BEACON_PORT = int(os.environ.get("SCENARIO_BEACON_PORT", "443"))
BEACON_PAYLOAD = b"scenario-beacon\n"


def burn_cpu() -> None:
    """Throwaway arithmetic, not proof-of-work: the point is CPU load, not a result."""
    data = os.urandom(4096)
    while True:
        data = hashlib.sha256(data).digest()


def beacon() -> None:
    """Steady small outbound connections at a fixed interval; connection failures are ignored
    because the point is the outbound attempt and its bytes, not a successful round trip."""
    index = 0
    while True:
        host = BEACON_HOSTS[index % len(BEACON_HOSTS)]
        index += 1
        try:
            with socket.create_connection((host, BEACON_PORT), timeout=2) as conn:
                conn.sendall(BEACON_PAYLOAD)
        except OSError:
            pass
        time.sleep(BEACON_INTERVAL_SECONDS)


def main() -> None:
    for _ in range(CPU_WORKERS):
        threading.Thread(target=burn_cpu, daemon=True).start()
    beacon()


if __name__ == "__main__":
    main()
