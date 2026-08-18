"""Triage model port.

Returns a bounded adjustment and a rationale for one Vulnerability in one
context. The real implementation calls DeepSeek; nothing above this
interface may know that.
"""

from __future__ import annotations

import json
import logging
from typing import Protocol

import httpx

from aidevops.domain import TriageAdjustment, TriageContext

logger = logging.getLogger(__name__)

# Per ADR-0004: the model adjusts a deterministic base score by roughly
# ±25 on a 0-100 scale, it does not produce the score itself.
MIN_ADJUSTMENT = -25
MAX_ADJUSTMENT = 25

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"


class TriageModelPort(Protocol):
    def triage(self, context: TriageContext) -> TriageAdjustment: ...


class TriageUnavailable(Exception):
    """Raised when the real model backend cannot answer, or answers with
    something this platform cannot parse. Callers leave the base score
    standing and mark the row as such - see aidevops.triage.
    """


class FakeTriageModel:
    def __init__(
        self,
        adjustment: TriageAdjustment | None = None,
        adjustments_by_cve: dict[str, TriageAdjustment] | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self._default = adjustment or TriageAdjustment(adjustment=0, rationale="fake: no adjustment")
        self._by_cve = adjustments_by_cve or {}
        # Test seam: lets Seam A tests script a failing or unavailable
        # model call, with no network involved.
        self._fail = fail
        # Test seam: lets Seam A tests assert the cache is doing its job -
        # a CVE Triaged once must not be Triaged again on the next
        # reconcile unless its cache key changes.
        self.calls: list[TriageContext] = []

    def triage(self, context: TriageContext) -> TriageAdjustment:
        self.calls.append(context)
        if self._fail:
            raise TriageUnavailable("fake: model call failed")
        return self._by_cve.get(context.vulnerability.cve_id, self._default)


class RealTriageModel:
    """Calls DeepSeek's chat completions API for one Vulnerability in one
    Workload's context, and parses its response into a bounded adjustment
    and a rationale.

    One call per Vulnerability, not batched - see the spec's reasoning: a
    batch response can only be cached keyed on the whole batch, which would
    break the surgical re-Triage a later ticket depends on.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 30.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    def triage(self, context: TriageContext) -> TriageAdjustment:
        prompt = build_prompt(context)
        try:
            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"},
                    "temperature": 0,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as error:
            raise TriageUnavailable(f"DeepSeek call failed for {context.vulnerability.cve_id}: {error}") from error

        return parse_model_response(content)


def parse_model_response(content: str) -> TriageAdjustment:
    """Turns the model's JSON reply into a bounded TriageAdjustment. Kept
    separate from the HTTP call so it can be exercised with canned model
    output, with no network - the same carve-out
    `aidevops.ports.image_scanner.parse_trivy_output` uses.
    """
    try:
        payload = json.loads(content)
        adjustment = clamp_adjustment(int(payload["adjustment"]))
        rationale = str(payload["rationale"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise TriageUnavailable(f"could not parse model response: {content!r}") from error
    return TriageAdjustment(adjustment=adjustment, rationale=rationale)


def clamp_adjustment(adjustment: int) -> int:
    """Per the spec: adjustments outside the permitted range are clamped,
    so a bad response cannot untether the ranking from the data.
    """
    return max(MIN_ADJUSTMENT, min(adjustment, MAX_ADJUSTMENT))


_RUBRIC = f"""\
Score band guidance for your adjustment (relative to the base score, which
is already computed from Severity, EPSS, KEV membership and fix
availability - do not re-derive the base score, only decide how far this
cluster's specific context should move it):

+15 to +{MAX_ADJUSTMENT}: This Workload is currently under an active Exposure Signal
  AND is externally reachable, or the CVE is KEV-listed and this Workload is
  reachable from outside the cluster right now.
+5 to +15: Meaningfully more concerning in this context than the base score
  suggests - e.g. externally reachable with no fix available, or an active
  Exposure Signal on an otherwise internal Workload.
-5 to +5: The base score already reflects this Vulnerability's urgency
  reasonably well in this context.
-15 to -5: Meaningfully less concerning here - e.g. an internal-only
  Workload, no Exposure Signal, and low real-world exploitation likelihood.
-{MAX_ADJUSTMENT} to -15: Effectively irrelevant in this specific cluster - no plausible
  exposure and nothing suggesting active misuse.

Respond with a single JSON object and nothing else, using this exact shape:
{{"adjustment": <integer between {MIN_ADJUSTMENT} and {MAX_ADJUSTMENT}>, "rationale": "<one or two sentences, referring to this Workload and cluster specifically, not a generic CVE description>"}}
"""


def build_prompt(context: TriageContext) -> str:
    """Builds the per-Vulnerability prompt. Carries every field the spec
    requires - CVE identifier and description, CVSS vector, package and
    installed version, fixed version where one exists, EPSS score, KEV
    membership, image, Workload name and namespace, external reachability,
    and current Exposure Signal state - plus the banded rubric above,
    because unanchored per-item scoring clumps into a narrow band and the
    queue stops discriminating.
    """
    vulnerability = context.vulnerability
    signal = context.exposure_signal
    signal_description = (
        f"active (magnitude {signal.magnitude:.2f})" if signal.active else "not active"
    )
    fixed_version = vulnerability.fixed_version or "no fix available"

    return f"""\
You are scoring one Vulnerability's contextual urgency for a security
operator's ranked queue. You do not set the final score - you propose a
bounded adjustment to a base score already computed from Severity, EPSS,
KEV membership and fix availability alone.

CVE: {vulnerability.cve_id}
Description: {vulnerability.description}
CVSS vector: {vulnerability.cvss_vector}
Package: {vulnerability.package} (installed {vulnerability.installed_version})
Fixed version: {fixed_version}
Severity: {vulnerability.severity}
EPSS score: {context.epss_score:.4f}
KEV listed: {context.kev_listed}

Image: {context.image_repository}
Workload: {context.workload_namespace}/{context.workload_name}
Externally reachable: {context.externally_reachable}
Exposure Signal: {signal_description}

{_RUBRIC}"""
