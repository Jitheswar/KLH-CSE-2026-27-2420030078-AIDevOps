# Attack simulation stays outside the platform

Compromise simulations live in `scenarios/` as scripted test fixtures, run from the Makefile, and are deliberately not exposed as a feature of the platform - there is no "simulate compromise" control in the UI.

A security platform that can also cause the condition it detects undermines its own demonstration, and the boundary is worth recording because adding such a button would otherwise look like an obvious convenience.
The scenarios double as ground truth for the integration tests, since the moment a simulated compromise starts is known exactly.
