# Scenarios

A Scenario is a scripted, reproducible simulation of a compromise, used to exercise the platform's detection.
It is a test fixture and deliberately not part of the platform: see `docs/adr/0006-attack-simulation-stays-outside-the-platform.md`.
There is no control anywhere in the platform's interface that triggers a Scenario.
Every Scenario in this directory is run from the Makefile, on its own, outside the running platform's code paths.

## miner

Simulates a compromised internet-facing nginx Workload burning CPU and beaconing outbound at a fixed interval.
This is the CPU-and-traffic correlation the detector is built to see.

**This is not real cryptocurrency mining.**
`miner/scenario.py` computes throwaway SHA-256 hashes to burn CPU and opens short TCP connections to public DNS resolvers to produce outbound traffic.
There is no mining software, no pool address, and no proof-of-work anywhere in it.

### Running it

```
make scenario-miner-start   # builds the image, loads it into the kind cluster,
                             # and injects it into the nginx-legacy Workload
make scenario-miner-stop    # removes it and returns the Workload to normal
```

`scenario-miner-start` records the moment the injected container comes up in `scenarios/miner/.state/started-at`, an ISO-8601 UTC timestamp.
This file is the ground truth the Seam B live tests use to measure detection latency; it is not committed, since it only makes sense for the cluster currently running.

### How injection works

The Scenario image is added to the `nginx-legacy` Deployment's pod template as a second container, via a strategic merge patch (`inject-patch.yaml`).
Because it shares the pod with the real nginx container, its CPU and network behaviour is attributed to the same Workload a real compromise of that container would affect, without touching the nginx image itself.
`scenario-miner-stop` removes it with the inverse patch (`remove-patch.yaml`) and waits for the rollout to finish, which is what "returns to normal" means here: the Deployment goes back to exactly the shape `deploy/seed/01-nginx-legacy.yaml` describes.

Two runs of the Scenario produce comparable behaviour because both the CPU load (fixed thread count) and the beacon interval are fixed constants, not randomised.
