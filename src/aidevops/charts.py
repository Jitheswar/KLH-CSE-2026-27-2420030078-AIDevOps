"""Renders telemetry samples as an inline SVG line chart.

No charting library and no CDN - the platform's interface is the actual
deliverable, so it stays self-contained rather than depending on one.
"""

from __future__ import annotations

import bisect
from datetime import datetime

from aidevops.baseline import BaselineBand
from aidevops.domain import TelemetrySample

_WIDTH = 640
_HEIGHT = 160
_PADDING = 8
# Mirrors the `--danger` token in templates/_shared_style.html - kept as a
# literal here since this module has no access to the page's CSS.
_DANGER_COLOR = "#b00020"


def render_line_chart(
    samples: list[TelemetrySample],
    metric: str,
    band: BaselineBand | None = None,
    window_start: datetime | None = None,
    fired_at: datetime | None = None,
) -> str:
    values = [getattr(sample, metric) for sample in samples]
    if len(values) < 2:
        return (
            f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" class="telemetry-chart" role="img">'
            '<text x="8" y="20">Not enough data yet.</text></svg>'
        )

    minimum, maximum = min(values), max(values)
    if band is not None:
        minimum = min(minimum, band.low)
        maximum = max(maximum, band.high)
    span = (maximum - minimum) or 1.0

    def _y(value: float) -> float:
        return _HEIGHT - _PADDING - ((value - minimum) / span) * (_HEIGHT - 2 * _PADDING)

    def _x_for_index(index: float) -> float:
        return _PADDING + (index / (len(values) - 1)) * (_WIDTH - 2 * _PADDING)

    def _point(index: int, value: float) -> str:
        return f"{_x_for_index(index):.1f},{_y(value):.1f}"

    band_rect = ""
    if band is not None:
        band_top = _y(band.high)
        band_bottom = _y(band.low)
        band_rect = (
            f'<rect class="baseline-band" x="{_PADDING}" y="{band_top:.1f}" '
            f'width="{_WIDTH - 2 * _PADDING}" height="{(band_bottom - band_top):.1f}" '
            'fill="currentColor" fill-opacity="0.15" stroke="none" />'
        )

    timestamps = [sample.timestamp for sample in samples]

    def _x(timestamp: datetime) -> float:
        # Maps onto the same index-based x coordinates `_point` uses for
        # the polyline itself, by interpolating between the two nearest
        # samples' indices - not a separate wall-clock-proportional
        # mapping, which would drift out of alignment with the polyline
        # whenever samples are not evenly spaced (a dropped scrape, a
        # replica joining mid-window). Timestamps outside the plotted
        # range clamp to the nearest edge - the moment a signal fired can
        # sit right at the edge of the chart's window - so the marker
        # stays visible rather than landing off the drawable area.
        if timestamp <= timestamps[0]:
            index = 0.0
        elif timestamp >= timestamps[-1]:
            index = float(len(timestamps) - 1)
        else:
            right_index = bisect.bisect_left(timestamps, timestamp)
            left, right = timestamps[right_index - 1], timestamps[right_index]
            step = (right - left).total_seconds() or 1.0
            fraction = (timestamp - left).total_seconds() / step
            index = (right_index - 1) + fraction
        return _x_for_index(index)

    trigger_rect = ""
    if window_start is not None and fired_at is not None:
        window_x_start = _x(window_start)
        window_x_end = _x(fired_at)
        trigger_rect = (
            f'<rect class="triggering-window" x="{window_x_start:.1f}" y="{_PADDING}" '
            f'width="{(window_x_end - window_x_start):.1f}" height="{_HEIGHT - 2 * _PADDING}" '
            f'fill="{_DANGER_COLOR}" fill-opacity="0.12" stroke="none" />'
        )

    fired_marker = ""
    if fired_at is not None:
        fired_x = _x(fired_at)
        fired_marker = (
            f'<line class="fired-marker" x1="{fired_x:.1f}" y1="{_PADDING}" x2="{fired_x:.1f}" y2="{_HEIGHT - _PADDING}" '
            f'stroke="{_DANGER_COLOR}" stroke-width="2" stroke-dasharray="4 3" />'
        )

    points = " ".join(_point(index, value) for index, value in enumerate(values))
    return (
        f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" class="telemetry-chart" role="img">'
        f"{band_rect}"
        f"{trigger_rect}"
        f'<polyline points="{points}" fill="none" stroke="currentColor" stroke-width="2" />'
        f"{fired_marker}"
        "</svg>"
    )
