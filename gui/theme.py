"""
gui/theme.py - one place for the whole app's look: palette, fonts, ttk styles.

Tkinter's native look (especially macOS Aqua) barely takes styling, so this
switches to the 'clam' theme - the only built-in ttk theme that actually
honours background/foreground/font overrides - then defines every custom
style the tabs use by name. Nothing here changes behaviour; widgets.py and
the tab files just reference these style names and theme.COLORS[...].

DARK MODE: `COLORS` is a plain dict that every file reads live via
`theme.COLORS[...]` (never `from .theme import COLORS`, which would bind a
stale copy). `set_mode()` mutates that same dict object in place, so every
call site picks up the swap automatically - callers just need to rebuild
their widgets afterward (color values are read at widget-construction time,
not watched live), which is what App.toggle_theme() does.
"""
from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

if sys.platform == "win32":
    FONT_FAMILY = "Segoe UI"
    MONO_FAMILY = "Consolas"
elif sys.platform == "darwin":
    FONT_FAMILY = "Helvetica Neue"
    MONO_FAMILY = "Menlo"
else:
    FONT_FAMILY = "DejaVu Sans"
    MONO_FAMILY = "DejaVu Sans Mono"

LIGHT = {
    "bg": "#eef2f8",           # window / tab body background
    "card": "#ffffff",         # LabelFrame / panel background
    "border": "#d3dbe6",
    "text": "#1f2937",
    "muted": "#5b6b83",
    "header_bg": "#132339",
    "header_fg": "#f3f6fb",
    "header_sub": "#8fb3e8",
    "accent": "#2563eb",
    "accent_dark": "#1d4ed8",
    "accent_soft": "#dbe6fb",
    "accent_active": "#c7d9f7",
    "accent_pressed": "#b7cdf5",
    "good": "#15803d",
    "good_bg": "#e6f4ea",
    "bad": "#c0392b",
    "bad_bg": "#fbe9e7",
    "warn": "#a06600",
    "warn_bg": "#fdf2d9",
    "field": "#ffffff",
    "idle_bg": "#dfe5ee",
    "idle_fg": "#5b6b83",
    "trough": "#e2e8f0",
}

DARK = {
    "bg": "#141a24",
    "card": "#1d2530",
    "border": "#333f52",
    "text": "#e6ebf3",
    "muted": "#9aa8bd",
    "header_bg": "#0a0f17",
    "header_fg": "#f3f6fb",
    "header_sub": "#7fa8e0",
    "accent": "#3b82f6",
    "accent_dark": "#60a5fa",
    "accent_soft": "#22334f",
    "accent_active": "#2c4472",
    "accent_pressed": "#365488",
    "good": "#4ade80",
    "good_bg": "#173321",
    "bad": "#f87171",
    "bad_bg": "#3a1f1f",
    "warn": "#facc15",
    "warn_bg": "#3a3111",
    "field": "#232c3a",
    "idle_bg": "#283142",
    "idle_fg": "#9aa8bd",
    "trough": "#232c3a",
}

MODE = "light"
COLORS = dict(LIGHT)


def set_mode(mode: str) -> None:
    """Swap the palette in place. Callers must rebuild widgets afterward -
    colors are read at construction time, not watched live."""
    global MODE
    MODE = mode
    COLORS.clear()
    COLORS.update(DARK if mode == "dark" else LIGHT)


def toggle_mode() -> str:
    set_mode("dark" if MODE == "light" else "light")
    return MODE


def font(size=11, weight="normal"):
    return (FONT_FAMILY, size, weight)


def mono_font(size=10, weight="normal"):
    return (MONO_FAMILY, size, weight)


def apply(root: tk.Tk) -> None:
    c = COLORS
    root.configure(background=c["bg"])

    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=c["bg"], foreground=c["text"], font=font(11))
    style.configure("TFrame", background=c["bg"])
    style.configure("TLabel", background=c["bg"], foreground=c["text"])
    # background is pinned for 'active' (hover) - left unmapped, clam falls
    # back to its own built-in near-white hover fill regardless of theme,
    # which swallowed the light-colored dark-mode text hovering over it.
    style.configure("TCheckbutton", background=c["bg"], foreground=c["text"])
    style.map("TCheckbutton", background=[("active", c["accent_soft"])])
    style.configure("TRadiobutton", background=c["bg"], foreground=c["text"])
    style.map("TRadiobutton", background=[("active", c["accent_soft"])])

    style.configure("TLabelframe", background=c["bg"], bordercolor=c["border"],
                    borderwidth=1, relief="solid")
    style.configure("TLabelframe.Label", background=c["bg"], foreground=c["accent_dark"],
                    font=font(11, "bold"))

    style.configure("TButton", background=c["accent_soft"], foreground=c["accent_dark"],
                    borderwidth=0, focusthickness=0, padding=(11, 7), font=font(10, "bold"),
                    cursor="hand2")
    style.map("TButton",
             background=[("active", c["accent_active"]), ("pressed", c["accent_pressed"]),
                        ("disabled", c["border"])],
             foreground=[("disabled", c["muted"])])

    style.configure("Accent.TButton", background=c["accent"], foreground="white",
                    borderwidth=0, focusthickness=0, padding=(15, 10), font=font(11, "bold"),
                    cursor="hand2")
    style.map("Accent.TButton",
             background=[("active", c["accent_dark"]), ("pressed", c["accent_dark"]),
                        ("disabled", c["border"])],
             foreground=[("disabled", c["muted"])])

    # Header light/dark toggle. Must be a ttk style (not a raw tk.Button) -
    # classic Tk buttons render with native Aqua chrome on macOS, which
    # ignores background/foreground overrides almost entirely and produced
    # the barely-visible washed-out button reported by the user.
    # foreground uses accent_dark (same pairing as the plain TButton style
    # above), not header_fg - header_fg is white in both themes, but the
    # pill's background is pale in light mode, so white text was unreadable
    # there even though it looked fine against the dark-mode pill.
    style.configure("Toggle.TButton", background=c["accent_soft"], foreground=c["accent_dark"],
                    borderwidth=0, focusthickness=0, padding=(12, 8), font=font(9, "bold"),
                    cursor="hand2")
    style.map("Toggle.TButton",
             background=[("active", c["accent_active"]), ("pressed", c["accent_pressed"])],
             foreground=[("active", c["accent_dark"]), ("pressed", c["accent_dark"])])

    style.configure("TEntry", fieldbackground=c["field"], foreground=c["text"],
                    bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
                    insertcolor=c["text"], padding=5)
    # arrowcolor/background are set explicitly for the up/down and dropdown
    # arrow buttons - left unset, clam falls back to a default that isn't
    # part of this palette and landed close to the dark-mode field color,
    # making the arrows effectively invisible after a toggle to dark mode.
    style.configure("TSpinbox", fieldbackground=c["field"], foreground=c["text"],
                    bordercolor=c["border"], arrowsize=13, padding=5,
                    background=c["field"], arrowcolor=c["text"])
    style.map("TSpinbox", arrowcolor=[("disabled", c["muted"])])
    style.configure("TCombobox", fieldbackground=c["field"], foreground=c["text"],
                    bordercolor=c["border"], padding=5,
                    background=c["field"], arrowcolor=c["text"])
    style.map("TCombobox", fieldbackground=[("readonly", c["field"])],
             background=[("active", c["accent_soft"]), ("pressed", c["accent_soft"])],
             arrowcolor=[("disabled", c["muted"])])

    style.configure("TNotebook", background=c["bg"], borderwidth=0, tabmargins=(6, 6, 6, 0))
    style.configure("TNotebook.Tab", background=c["accent_soft"], foreground=c["accent_dark"],
                    padding=(16, 11), font=font(11, "bold"), borderwidth=0)
    style.map("TNotebook.Tab",
             background=[("selected", c["accent"])],
             foreground=[("selected", "white")])

    style.configure("Horizontal.TProgressbar", troughcolor=c["trough"],
                    background=c["accent"], bordercolor=c["trough"],
                    lightcolor=c["accent"], darkcolor=c["accent"])
    style.configure("Good.Horizontal.TProgressbar", troughcolor=c["trough"],
                    background=c["good"], bordercolor=c["trough"],
                    lightcolor=c["good"], darkcolor=c["good"])
    style.configure("Bad.Horizontal.TProgressbar", troughcolor=c["trough"],
                    background=c["bad"], bordercolor=c["trough"],
                    lightcolor=c["bad"], darkcolor=c["bad"])

    style.configure("Treeview", background=c["card"], fieldbackground=c["card"],
                    foreground=c["text"], rowheight=26, font=font(10), borderwidth=0)
    style.configure("Treeview.Heading", background=c["accent_soft"], foreground=c["accent_dark"],
                    font=font(10, "bold"), relief="flat")
    style.map("Treeview.Heading", background=[("active", c["accent_active"])])
    style.map("Treeview", background=[("selected", c["accent"])],
             foreground=[("selected", "white")])

    style.configure("TScrollbar", background=c["accent_soft"], troughcolor=c["bg"],
                    bordercolor=c["bg"], arrowsize=13)
    style.map("TScrollbar", background=[("active", c["accent_active"]),
                                        ("pressed", c["accent_pressed"])])
