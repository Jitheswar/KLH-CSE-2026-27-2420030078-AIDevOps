"""Unit tests for the inline SVG line chart renderer. Pure function, no
network and no browser."""

from __future__ import annotations

from datetime import datetime

from aidevops.charts import render_line_chart
from aidevops.domain import TelemetrySample


def _sample(minute: int, cpu: float) -> TelemetrySample:
    return TelemetrySample(
        timestamp=datetime(2024, 1, 1, 12, minute, 0), cpu=cpu, network_transmit=0.0, network_receive=0.0
    )


def test_renders_a_polyline_for_two_or_more_samples() -> None:
    svg = render_line_chart([_sample(0, 1.0), _sample(1, 2.0)], "cpu")

    assert "<polyline" in svg
    assert "points=" in svg


def test_a_flat_series_does_not_divide_by_zero() -> None:
    svg = render_line_chart([_sample(0, 5.0), _sample(1, 5.0), _sample(2, 5.0)], "cpu")

    assert "<polyline" in svg


def test_fewer_than_two_samples_says_not_enough_data() -> None:
    assert "Not enough data yet." in render_line_chart([], "cpu")
    assert "Not enough data yet." in render_line_chart([_sample(0, 1.0)], "cpu")
