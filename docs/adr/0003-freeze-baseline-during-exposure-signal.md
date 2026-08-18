# Freeze the Baseline while an Exposure Signal is active

Baselines are refit on a rolling two-hour window, which means a compromise that persists long enough would be absorbed into "normal" and the Exposure Signal would silently clear while the compromise was still live.
We therefore freeze a Workload's training window for as long as its Exposure Signal is active.

This is a deliberate guard against self-poisoning of an unsupervised detector, and it is not obvious from reading the refit code alone - anyone tidying up the training loop would naturally remove it.
