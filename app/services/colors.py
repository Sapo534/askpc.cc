"""Validation for user-chosen accent colors (username color of sponsors).

The value ends up inside a `style="color: ..."` attribute on many pages, so it
must be a strict #rrggbb string. It must also stay readable on both the light
(#ffffff) and dark (#0d0d0d) theme.
"""
import re

HEX_RE = re.compile(r"#[0-9a-fA-F]{6}")

# Relative luminance of the two theme backgrounds (see static/style.css).
LIGHT_BG = 1.0      # #ffffff
DARK_BG = 0.004     # #0d0d0d
MIN_CONTRAST = 3.0  # WCAG minimum for large/bold text


def _channel(value: int) -> float:
    s = value / 255
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def normalize_accent_color(value: str) -> str | None:
    """Return a lowercase #rrggbb if it is readable on both themes, else None."""
    value = (value or "").strip()
    if not HEX_RE.fullmatch(value):
        return None
    lum = luminance(value)
    on_light = (LIGHT_BG + 0.05) / (lum + 0.05)
    on_dark = (lum + 0.05) / (DARK_BG + 0.05)
    if on_light < MIN_CONTRAST or on_dark < MIN_CONTRAST:
        return None
    return value.lower()
