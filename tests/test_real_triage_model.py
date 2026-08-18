"""Unit tests for the real Triage model's pure prompt-building, response
parsing, and clamping logic.

These do not call DeepSeek - that is Seam B's job, for a later ticket. What
is tested here is deterministic, no network involved - the same carve-out
`tests/test_real_image_scanner.py` uses for Trivy's JSON shape.
"""

from __future__ import annotations

import json

from aidevops.domain import ExposureSignalState, TriageAdjustment, TriageContext, Vulnerability
from aidevops.ports.triage_model import (
    MAX_ADJUSTMENT,
    MIN_ADJUSTMENT,
    build_prompt,
    clamp_adjustment,
    parse_model_response,
)


def _context(**overrides: object) -> TriageContext:
    defaults: dict[str, object] = dict(
        vulnerability=Vulnerability(
            cve_id="CVE-2024-0001",
            package="libexample",
            installed_version="1.0.0",
            severity="CRITICAL",
            description="A textbook remote code execution.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            fixed_version="1.0.1",
        ),
        epss_score=0.87,
        kev_listed=True,
        image_repository="example/repo",
        workload_name="checkout",
        workload_namespace="payments",
        externally_reachable=True,
        exposure_signal=ExposureSignalState(active=True, magnitude=4.2),
    )
    defaults.update(overrides)
    return TriageContext(**defaults)  # type: ignore[arg-type]


def test_prompt_carries_every_field_the_spec_requires() -> None:
    prompt = build_prompt(_context())

    assert "CVE-2024-0001" in prompt
    assert "A textbook remote code execution." in prompt
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in prompt
    assert "libexample" in prompt
    assert "1.0.0" in prompt
    assert "1.0.1" in prompt
    assert "0.8700" in prompt
    assert "KEV listed: True" in prompt
    assert "example/repo" in prompt
    assert "payments/checkout" in prompt
    assert "Externally reachable: True" in prompt
    assert "active" in prompt.lower()
    assert "4.20" in prompt


def test_prompt_reports_no_fix_available_when_there_is_none() -> None:
    vulnerability = Vulnerability(
        cve_id="CVE-2024-0002",
        package="libexample",
        installed_version="1.0.0",
        severity="HIGH",
        description="No fix yet.",
        cvss_vector="",
        fixed_version=None,
    )
    prompt = build_prompt(_context(vulnerability=vulnerability))

    assert "no fix available" in prompt


def test_prompt_reports_an_inactive_exposure_signal() -> None:
    prompt = build_prompt(_context(exposure_signal=ExposureSignalState()))

    assert "Exposure Signal: not active" in prompt


def test_prompt_includes_a_banded_rubric() -> None:
    prompt = build_prompt(_context())

    assert "band" in prompt.lower()
    # An anchored, discriminating rubric - not just a single number to
    # imitate - per the spec's reasoning that unanchored per-item scoring
    # clumps into a narrow band.
    assert str(MIN_ADJUSTMENT) in prompt
    assert str(MAX_ADJUSTMENT) in prompt


def test_clamp_adjustment_leaves_in_range_values_untouched() -> None:
    assert clamp_adjustment(10) == 10
    assert clamp_adjustment(-10) == -10
    assert clamp_adjustment(0) == 0


def test_clamp_adjustment_clamps_values_above_the_maximum() -> None:
    assert clamp_adjustment(999) == MAX_ADJUSTMENT


def test_clamp_adjustment_clamps_values_below_the_minimum() -> None:
    assert clamp_adjustment(-999) == MIN_ADJUSTMENT


def test_parse_model_response_reads_a_well_formed_reply() -> None:
    content = json.dumps({"adjustment": 12, "rationale": "Reachable and KEV-listed in this cluster."})

    result = parse_model_response(content)

    assert result == TriageAdjustment(adjustment=12, rationale="Reachable and KEV-listed in this cluster.")


def test_parse_model_response_clamps_an_out_of_range_adjustment() -> None:
    content = json.dumps({"adjustment": 500, "rationale": "Overconfident."})

    result = parse_model_response(content)

    assert result.adjustment == MAX_ADJUSTMENT


def test_parse_model_response_raises_on_malformed_json() -> None:
    import pytest

    from aidevops.ports.triage_model import TriageUnavailable

    with pytest.raises(TriageUnavailable):
        parse_model_response("not json")


def test_parse_model_response_raises_when_a_required_field_is_missing() -> None:
    import pytest

    from aidevops.ports.triage_model import TriageUnavailable

    with pytest.raises(TriageUnavailable):
        parse_model_response(json.dumps({"adjustment": 5}))
