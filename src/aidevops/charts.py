"""Renders telemetry samples as an inline SVG line chart.

No charting library and no CDN - the platform's interface is the actual
deliverable, so it stays self-contained rather than depending on one.

The chart is drawn to be read at a glance rather than measured precisely:
the Baseline band behind the line is what "normal" looks like, the shaded
window and dashed marker are where an Exposure Signal fired, and the value
labels give enough scale to interpret them. Colour comes from the page -
the line, the band and the area fill all follow `currentColor`, so a metric
is recoloured in CSS without touching this module.
"""

from __future__ import annotations

import bisect
from datetime import datetime

from aidevops.baseline import BaselineBand
from aidevops.domain import TelemetrySample

# The viewBox is sized close to how wide a chart card actually renders,
# so the SVG's own text and stroke widths land at roughly their nominal
# pixel size instead of being scaled up into a caricature of themselves.
# That is also why all three charts are stacked one per row on the
# Workload page - two different render widths would need two different
# nominal sizes here.
_WIDTH = 1160
_HEIGHT = 220
_PADDING = 10
_PAD_TOP = 26
_PAD_BOTTOM = 30
_GRID_LINES = 4
# Mirrors the `--danger` token in templates/_shared_style.html - kept as a
# literal here since this module has no access to the page's CSS.
_DANGER_COLOR = "#ff4d6d"
_GRID_COLOR = "rgba(255,255,255,0.07)"
_LABEL_COLOR = "rgba(255,255,255,0.42)"


def _format_value(value: float) -> str:
    """Enough precision to tell two readings apart, no more - the metrics
    on one page span fractions of a CPU core and thousands of bytes.
    """
    magnitude = abs(value)
    if magnitude >= 1000:
        return f"{value:,.0f}"
    if magnitude >= 100:
        return f"{value:.0f}"
    if magnitude >= 10:
        return f"{value:.1f}"
    if magnitude >= 1:
        return f"{value:.2f}"
    return f"{value:.3f}"


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
            f'<text x="{_WIDTH / 2:.0f}" y="{_HEIGHT / 2:.0f}" fill="{_LABEL_COLOR}" font-size="13" '
            'text-anchor="middle" font-family="system-ui, sans-serif">Not enough data yet.</text></svg>'
        )

    minimum, maximum = min(values), max(values)
    if band is not None:
        minimum = min(minimum, band.low)
        maximum = max(maximum, band.high)
    span = (maximum - minimum) or 1.0

    def _y(value: float) -> float:
        return _HEIGHT - _PAD_BOTTOM - ((value - minimum) / span) * (_HEIGHT - _PAD_TOP - _PAD_BOTTOM)

    def _x_for_index(index: float) -> float:
        return _PADDING + (index / (len(values) - 1)) * (_WIDTH - 2 * _PADDING)

    def _point(index: int, value: float) -> str:
        return f"{_x_for_index(index):.1f},{_y(value):.1f}"

    # A gradient per metric, since all three charts share one document and
    # an id collision would silently repaint the wrong one.
    fill_id = f"fill-{metric}"
    defs = (
        f'<defs><linearGradient id="{fill_id}" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0%" stop-color="currentColor" stop-opacity="0.35" />'
        '<stop offset="100%" stop-color="currentColor" stop-opacity="0" />'
        "</linearGradient></defs>"
    )

    grid = "".join(
        f'<line class="grid-line" x1="{_PADDING}" y1="{y:.1f}" x2="{_WIDTH - _PADDING}" y2="{y:.1f}" '
        f'stroke="{_GRID_COLOR}" stroke-width="1" />'
        for y in (
            _PAD_TOP + step * (_HEIGHT - _PAD_TOP - _PAD_BOTTOM) / _GRID_LINES for step in range(_GRID_LINES + 1)
        )
    )

    band_rect = ""
    if band is not None:
        band_top = _y(band.high)
        band_bottom = _y(band.low)
        band_rect = (
            f'<rect class="baseline-band" x="{_PADDING}" y="{band_top:.1f}" '
            f'width="{_WIDTH - 2 * _PADDING}" height="{(band_bottom - band_top):.1f}" '
            'fill="currentColor" fill-opacity="0.15" stroke="currentColor" stroke-opacity="0.3" '
            'stroke-dasharray="3 3" stroke-width="1" rx="2" />'
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
            f'<rect class="triggering-window" x="{window_x_start:.1f}" y="{_PAD_TOP}" '
            f'width="{(window_x_end - window_x_start):.1f}" height="{_HEIGHT - _PAD_TOP - _PAD_BOTTOM}" '
            f'fill="{_DANGER_COLOR}" fill-opacity="0.14" stroke="none" />'
        )

    fired_marker = ""
    if fired_at is not None:
        fired_x = _x(fired_at)
        fired_marker = (
            f'<line class="fired-marker" x1="{fired_x:.1f}" y1="{_PAD_TOP - 6}" x2="{fired_x:.1f}" '
            f'y2="{_HEIGHT - _PAD_BOTTOM}" stroke="{_DANGER_COLOR}" stroke-width="2" stroke-dasharray="4 3" />'
            f'<circle class="fired-marker-head" cx="{fired_x:.1f}" cy="{_PAD_TOP - 6}" r="3.5" fill="{_DANGER_COLOR}" />'
        )

    points = " ".join(_point(index, value) for index, value in enumerate(values))
    baseline_y = _HEIGHT - _PAD_BOTTOM
    area = (
        f'<polygon class="series-area" points="{_PADDING},{baseline_y:.1f} {points} '
        f'{_WIDTH - _PADDING},{baseline_y:.1f}" fill="url(#{fill_id})" stroke="none" />'
    )
    last_x, last_y = _x_for_index(len(values) - 1), _y(values[-1])
    head = (
        f'<circle class="series-head" cx="{last_x:.1f}" cy="{last_y:.1f}" r="3.5" fill="currentColor" '
        'stroke="#0e1420" stroke-width="2" />'
    )
    label_font = 'font-size="12" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif"'
    window = f"{timestamps[0]:%H:%M} - {timestamps[-1]:%H:%M}"
    labels = (
        f'<text class="axis-label" x="{_PADDING + 2}" y="16" fill="{_LABEL_COLOR}" {label_font}>'
        f"{_format_value(maximum)}</text>"
        f'<text class="axis-label" x="{_PADDING + 2}" y="{_HEIGHT - 10}" fill="{_LABEL_COLOR}" {label_font}>'
        f"{_format_value(minimum)}</text>"
        f'<text class="axis-label window" x="{_WIDTH - _PADDING - 2}" y="{_HEIGHT - 10}" fill="{_LABEL_COLOR}" '
        f'text-anchor="end" {label_font}>{window}</text>'
        f'<text class="axis-label latest" x="{_WIDTH - _PADDING - 2}" y="16" fill="currentColor" '
        f'font-weight="700" text-anchor="end" {label_font}>now {_format_value(values[-1])}</text>'
    )
    return (
        f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" class="telemetry-chart" role="img">'
        f"{defs}"
        f"{grid}"
        f"{band_rect}"
        f"{trigger_rect}"
        f"{area}"
        f'<polyline points="{points}" fill="none" stroke="currentColor" stroke-width="2" '
        'stroke-linejoin="round" stroke-linecap="round" />'
        f"{head}"
        f"{fired_marker}"
        f"{labels}"
        "</svg>"
    )
