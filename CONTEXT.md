# AIDevOps

A DevSecOps platform that re-prioritises container vulnerabilities using live evidence of how the affected workloads are actually behaving in a Kubernetes cluster.
Its central claim is that a vulnerability's urgency is a property of the running cluster, not of the CVE record alone.

## Language

**Vulnerability**:
A single CVE reported by a scanner against a container image running in the cluster.
_Avoid_: Vuln, issue, bug, finding

**Severity**:
The static CVSS rating a scanner attaches to a Vulnerability, identical everywhere that CVE appears.
_Avoid_: Priority, risk, criticality

**Exposure Signal**:
Live evidence that a workload is behaving abnormally right now, derived from its runtime telemetry rather than from any scanner.
_Avoid_: Alert, anomaly score, incident

**Contextual Priority**:
The platform's ranking of one Vulnerability in this cluster at this moment, formed from its Severity together with any Exposure Signal on the workload running the affected image.
_Avoid_: Score, risk score, priority score

**Triage**:
The act of turning a Vulnerability plus its cluster context into a Contextual Priority and a written rationale.
_Avoid_: Scoring, ranking, classification

**Workload**:
A Kubernetes Deployment, treated as the stable unit that owns Vulnerabilities and carries Exposure Signals across pod restarts and rescheduling.
_Avoid_: Service, app, pod, container

**Baseline**:
The behaviour a pod's telemetry has established as normal, against which an Exposure Signal is judged.
_Avoid_: Profile, model, normal state

**Candidate Set**:
The small subset of Vulnerabilities that survives deterministic pre-filtering and is therefore worth spending a Triage on.
_Avoid_: Shortlist, top N, filtered set

**Scenario**:
A scripted, reproducible simulation of a compromise, used to exercise detection.
It is a test fixture and deliberately not part of the platform.
_Avoid_: Attack, simulation mode, chaos test
