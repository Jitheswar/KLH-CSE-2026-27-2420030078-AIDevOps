# Detect per pod, attribute per Workload, aggregate by max

Telemetry arrives per pod but pods are ephemeral, so a pod restart would otherwise wipe its own Baseline and reset detection to blind.
We learn Baselines and detect anomalies at pod level, then attach the resulting Exposure Signal to the Workload, pooling a Deployment's replicas when training so a freshly-scheduled replica inherits a trained model instead of cold-starting.

Replicas are aggregated by **maximum, not mean**.
The deciding scenario: a compromise affecting one replica of three would dilute below any threshold under averaging, which is precisely the case the platform exists to catch.
