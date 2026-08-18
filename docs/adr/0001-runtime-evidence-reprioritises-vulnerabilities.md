# Runtime evidence re-prioritises vulnerabilities

The project could have been two independent modules sharing a title: a vulnerability triage tool and a Kubernetes anomaly detector.
We chose instead to make them one platform joined by a single claim - that live evidence of a workload misbehaving changes how urgent that workload's vulnerabilities are - because that link is the only thing that makes this one project rather than two, and it is the contribution a CVSS sort structurally cannot reproduce.

## Consequences

Every design decision downstream inherits a hard requirement: there must be an unbroken chain from a running pod, to the image it runs, to that image's CVEs.
Any change that breaks that chain (scanning repositories instead of running images, for instance) collapses the platform back into two bundled demos.
