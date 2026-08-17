"""Renders telemetry samples as an inline SVG line chart.

No charting library and no CDN - the platform's interface is the actual
deliverable (see ticket 07's port-boundary decision to exclude Grafana), so
it stays self-contained rather than depending on one.
"""

from __future__ import annotations

from aidevops.baseline import BaselineBand
from aidevops.domain import TelemetrySample

_WIDTH = 640
_HEIGHT = 160
_PADDING = 8


def render_line_chart(samples: list[TelemetrySample], metric: str, band: BaselineBand | None = None) -> str:
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

    def _point(index: int, value: float) -> str:
        x = _PADDING + (index / (len(values) - 1)) * (_WIDTH - 2 * _PADDING)
        return f"{x:.1f},{_y(value):.1f}"

    band_rect = ""
    if band is not None:
        band_top = _y(band.high)
        band_bottom = _y(band.low)
        band_rect = (
            f'<rect class="baseline-band" x="{_PADDING}" y="{band_top:.1f}" '
            f'width="{_WIDTH - 2 * _PADDING}" height="{(band_bottom - band_top):.1f}" '
            'fill="currentColor" fill-opacity="0.15" stroke="none" />'
        )

    points = " ".join(_point(index, value) for index, value in enumerate(values))
    return (
        f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" class="telemetry-chart" role="img">'
        f"{band_rect}"
        f'<polyline points="{points}" fill="none" stroke="currentColor" stroke-width="2" />'
        "</svg>"
    )
