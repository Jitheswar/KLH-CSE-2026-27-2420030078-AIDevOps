"""Renders telemetry samples as an inline SVG line chart.

No charting library and no CDN - the platform's interface is the actual
deliverable (see ticket 07's port-boundary decision to exclude Grafana), so
it stays self-contained rather than depending on one.
"""

from __future__ import annotations

from aidevops.domain import TelemetrySample

_WIDTH = 640
_HEIGHT = 160
_PADDING = 8


def render_line_chart(samples: list[TelemetrySample], metric: str) -> str:
    values = [getattr(sample, metric) for sample in samples]
    if len(values) < 2:
        return (
            f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" class="telemetry-chart" role="img">'
            '<text x="8" y="20">Not enough data yet.</text></svg>'
        )

    minimum, maximum = min(values), max(values)
    span = (maximum - minimum) or 1.0

    def _point(index: int, value: float) -> str:
        x = _PADDING + (index / (len(values) - 1)) * (_WIDTH - 2 * _PADDING)
        y = _HEIGHT - _PADDING - ((value - minimum) / span) * (_HEIGHT - 2 * _PADDING)
        return f"{x:.1f},{y:.1f}"

    points = " ".join(_point(index, value) for index, value in enumerate(values))
    return (
        f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" class="telemetry-chart" role="img">'
        f'<polyline points="{points}" fill="none" stroke="currentColor" stroke-width="2" />'
        "</svg>"
    )
