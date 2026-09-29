"""
gui/icons.py - small flat icons drawn with PIL: the window icon and the
four notebook tab glyphs, plus sun/moon for the theme toggle.

Drawn programmatically rather than shipped as image files, so they always
match the active palette (including after a light/dark toggle) without
needing a set of pre-rendered assets per theme.
"""
from __future__ import annotations

import math

from PIL import Image, ImageDraw

_SCALE = 6  # draw large, downsample for antialiasing - PIL has no AA drawing


def _canvas(size: int):
    big = size * _SCALE
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    return img, ImageDraw.Draw(img), big


def _finish(img: Image.Image, size: int) -> Image.Image:
    return img.resize((size, size), Image.LANCZOS)


def _lighten(hex_color: str, amount: float) -> tuple:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    r = int(r + (255 - r) * amount)
    g = int(g + (255 - g) * amount)
    b = int(b + (255 - b) * amount)
    return (r, g, b)


def _darken(hex_color: str, amount: float) -> tuple:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return (int(r * (1 - amount)), int(g * (1 - amount)), int(b * (1 - amount)))


def window_icon(size: int = 64, color: str = "#2563eb") -> Image.Image:
    """Modern rounded-square app tile with a centered padlock, plus a
    subtle top-to-bottom shade for depth - matches how a real app icon
    (macOS/iOS/Windows tile style) reads, instead of a flat cutout shape."""
    img, d, big = _canvas(size)
    m = big * 0.03

    # vertical gradient tile: darker accent at top fading to the base
    # accent at the bottom, drawn as horizontal strips then masked to the
    # rounded-square shape so the corners stay clean.
    tile = Image.new("RGB", (big, big), color)
    top_c, bot_c = _lighten(color, 0.18), _darken(color, 0.12)
    for y in range(big):
        t = y / max(1, big - 1)
        row = tuple(int(top_c[i] + (bot_c[i] - top_c[i]) * t) for i in range(3))
        ImageDraw.Draw(tile).line([(0, y), (big, y)], fill=row)
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle([m, m, big - m, big - m], radius=big * 0.22,
                                           fill=255)
    img.paste(tile, (0, 0), mask)

    # thin light rim for a touch of polish
    d.rounded_rectangle([m, m, big - m, big - m], radius=big * 0.22,
                        outline=_lighten(color, 0.35), width=max(1, int(big * 0.008)))

    # padlock, cleanly centered and proportioned. ly is offset from the
    # tile's geometric center (not big*0.5 directly) since the shackle
    # extends further above the body than the body extends below it -
    # centering ly instead left the whole glyph sitting visibly low.
    lock_w, lock_h = big * 0.40, big * 0.30
    lx, ly = (big - lock_w) / 2, big * 0.426
    d.rounded_rectangle([lx, ly, lx + lock_w, ly + lock_h], radius=lock_w * 0.20,
                        fill="white")
    keyhole_r = lock_h * 0.14
    kcx, kcy = big / 2, ly + lock_h * 0.42
    d.ellipse([kcx - keyhole_r, kcy - keyhole_r, kcx + keyhole_r, kcy + keyhole_r],
             fill=color)
    d.polygon([(kcx - keyhole_r * 0.5, kcy + keyhole_r * 0.3),
              (kcx + keyhole_r * 0.5, kcy + keyhole_r * 0.3),
              (kcx + keyhole_r * 0.9, kcy + lock_h * 0.32),
              (kcx - keyhole_r * 0.9, kcy + lock_h * 0.32)], fill=color)

    # shackle: two straight legs feeding into an arch, not a bare arc() -
    # guarantees a symmetric, clearly-CLOSED loop rather than an ambiguous
    # open-looking curve at small sizes.
    lw = max(2, int(big * 0.05))
    shackle_r = lock_w * 0.22
    leg_x = lock_w * 0.22
    scx = big / 2
    arch_top = ly - shackle_r * 1.7
    leg_bottom = ly + lw * 0.5
    d.line([scx - leg_x, leg_bottom, scx - leg_x, arch_top + shackle_r], fill="white", width=lw)
    d.line([scx + leg_x, leg_bottom, scx + leg_x, arch_top + shackle_r], fill="white", width=lw)
    d.arc([scx - leg_x - lw * 0.4, arch_top, scx + leg_x + lw * 0.4, arch_top + shackle_r * 2],
         start=180, end=360, fill="white", width=lw)
    return _finish(img, size)


def tab_icon(kind: str, size: int = 20, color: str = "#1d4ed8") -> Image.Image:
    """kind: 'protect' | 'verify' | 'attack' | 'cases'."""
    img, d, big = _canvas(size)
    m = big * 0.12
    lw = max(2, int(big * 0.10))

    if kind == "protect":  # padlock
        body_w, body_h = big - 2 * m, (big - 2 * m) * 0.62
        bx, by = m, big - m - body_h
        d.rounded_rectangle([bx, by, bx + body_w, by + body_h],
                            radius=body_w * 0.18, outline=color, width=lw)
        r = body_w * 0.28
        cx, cy = big / 2, by
        d.arc([cx - r, cy - r * 1.7, cx + r, cy + r * 0.3], start=180, end=360,
             fill=color, width=lw)
        d.ellipse([cx - lw * 0.9, by + body_h * 0.32, cx + lw * 0.9,
                  by + body_h * 0.32 + lw * 1.8], fill=color)

    elif kind == "verify":  # shield + checkmark
        h = big - 2 * m
        points = [
            (m, m), (big - m, m),
            (big - m, m + h * 0.5),
            (big / 2, big - m),
            (m, m + h * 0.5),
        ]
        d.line(points + [points[0]], fill=color, width=lw, joint="curve")
        d.line([big * 0.32, big * 0.52, big * 0.46, big * 0.66], fill=color, width=lw)
        d.line([big * 0.46, big * 0.66, big * 0.72, big * 0.36], fill=color, width=lw)

    elif kind == "cases":  # clipboard with a tick
        d.rounded_rectangle([m * 1.3, m, big - m * 1.3, big - m], radius=big * 0.08,
                            outline=color, width=lw)
        d.line([big * 0.38, m, big * 0.62, m], fill=color, width=lw * 2)
        d.line([big * 0.32, big * 0.55, big * 0.46, big * 0.69], fill=color, width=lw)
        d.line([big * 0.46, big * 0.69, big * 0.70, big * 0.40], fill=color, width=lw)

    elif kind == "attack":  # warning triangle
        points = [(big / 2, m), (big - m, big - m), (m, big - m)]
        d.line(points + [points[0]], fill=color, width=lw, joint="curve")
        d.line([big / 2, big * 0.42, big / 2, big * 0.66], fill=color, width=lw)
        d.ellipse([big / 2 - lw * 0.6, big * 0.72, big / 2 + lw * 0.6,
                  big * 0.72 + lw * 1.2], fill=color)

    return _finish(img, size)


def theme_icon(mode: str, size: int = 16, color: str = "#f3f6fb") -> Image.Image:
    """Sun (click to go light) or moon (click to go dark) for the toggle button."""
    img, d, big = _canvas(size)
    if mode == "dark":
        r = big * 0.32
        cx, cy = big * 0.55, big * 0.45
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)
        d.ellipse([cx - r * 0.55, cy - r * 1.15, cx + r * 1.15, cy + r * 0.55],
                 fill=(0, 0, 0, 0))
    else:
        r = big * 0.22
        cx, cy = big / 2, big / 2
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)
        lw = max(2, int(big * 0.06))
        for i in range(8):
            ang = math.pi * i / 4
            x0, y0 = cx + math.cos(ang) * r * 1.5, cy + math.sin(ang) * r * 1.5
            x1, y1 = cx + math.cos(ang) * r * 2.2, cy + math.sin(ang) * r * 2.2
            d.line([x0, y0, x1, y1], fill=color, width=lw)
    return _finish(img, size)
