"""Unit tests for the deterministic pre-filter's scoring logic.

Pure function tests against `base_priority` - no SQLite, no ports. The
seam-level proof that the pre-filter is not a Severity sort lives in
tests/test_seam_a_queue.py, driven over HTTP per the spec's testing
decisions; what is tested here is the arithmetic underneath it.
"""

from __future__ import annotations

from aidevops.candidates import base_priority


def test_kev_membership_raises_the_score_over_an_otherwise_identical_vulnerability() -> None:
    without_kev = base_priority("HIGH", epss_score=0.1, kev_listed=False, fix_available=True)
    with_kev = base_priority("HIGH", epss_score=0.1, kev_listed=True, fix_available=True)

    assert with_kev > without_kev


def test_higher_epss_raises_the_score_over_an_otherwise_identical_vulnerability() -> None:
    low_epss = base_priority("HIGH", epss_score=0.01, kev_listed=False, fix_available=True)
    high_epss = base_priority("HIGH", epss_score=0.95, kev_listed=False, fix_available=True)

    assert high_epss > low_epss


def test_a_fix_being_available_raises_the_score_over_an_otherwise_identical_vulnerability() -> None:
    no_fix = base_priority("HIGH", epss_score=0.1, kev_listed=False, fix_available=False)
    has_fix = base_priority("HIGH", epss_score=0.1, kev_listed=False, fix_available=True)

    assert has_fix > no_fix


def test_score_is_bounded_to_0_100() -> None:
    minimum = base_priority("LOW", epss_score=0.0, kev_listed=False, fix_available=False)
    maximum = base_priority("CRITICAL", epss_score=1.0, kev_listed=True, fix_available=True)

    assert 0 <= minimum <= 100
    assert 0 <= maximum <= 100
    assert maximum == 100


def test_an_unrecognised_severity_falls_back_rather_than_erroring() -> None:
    score = base_priority("SOMETHING-NEW", epss_score=0.0, kev_listed=False, fix_available=False)

    assert isinstance(score, int)


def test_score_is_deterministic_for_the_same_inputs() -> None:
    first = base_priority("MEDIUM", epss_score=0.42, kev_listed=True, fix_available=False)
    second = base_priority("MEDIUM", epss_score=0.42, kev_listed=True, fix_available=False)

    assert first == second
