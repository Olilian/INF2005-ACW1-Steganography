"""
gui/app.py - the production GUI window: Protect, Verify, Exchange (party A/B)
and Attack tabs sharing one SessionState.
"""
from __future__ import annotations

import tkinter as tk
import traceback
from tkinter import messagebox, ttk

from PIL import ImageTk

import a2_crypto as a2

from . import icons, theme
from .attack_tab import AttackTab
from .exchange_tab import ExchangeTab
from .protect_tab import ProtectTab
from .session import SessionState
from .verify_tab import VerifyTab
from .widgets import PLAYBACK_AVAILABLE

API_VERSION_EXPECTED = "1.0"

TABS = (
    ("protect", "  Protect  ", lambda nb, app: ProtectTab(nb, app.session, app.go_to_verify)),
    ("verify", "  Verify  ", lambda nb, app: VerifyTab(nb, app.session)),
    ("exchange", "  Party A -> B demo  ", lambda nb, app: ExchangeTab(nb, app.session)),
    ("attack", "  Attack simulation  ", lambda nb, app: AttackTab(nb, app.session)),
)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("INF2005 ACW1 - Steganographic Image and Audio Integrity Verification")
        self.geometry("1240x880")
        self.minsize(900, 560)

        self.session = SessionState()
        a2.check_api_version(API_VERSION_EXPECTED)

        self._body = None            # torn down and rebuilt on theme toggle
        self._icon_refs = []         # keep PhotoImage references alive
        self._build()

    # =====================================================================
    def _build(self):
        theme.apply(self)
        self._set_window_icon()

        self._body = ttk.Frame(self)
        self._body.pack(fill="both", expand=True)

        self._build_header(self._body)

        nb = ttk.Notebook(self._body)
        nb.pack(fill="both", expand=True, padx=10, pady=(0, 0))
        self.nb = nb

        self._icon_refs = []
        self._tab_icons = {}   # tab widget id (str) -> (unselected_photo, selected_photo)
        for key, label, factory in TABS:
            tab = factory(nb, self)
            setattr(self, "{}_tab".format(key), tab)
            # Two colour variants: ttk swaps a selected tab's TEXT to white
            # via style.map, but a tab's `image` is a plain PhotoImage that
            # doesn't follow that automatically - without this, the icon
            # keeps its unselected colour and blends into the selected
            # tab's (similarly-blue) background. Swapped on tab-change below.
            unselected = ImageTk.PhotoImage(icons.tab_icon(
                key, size=17, color=theme.COLORS["accent_dark"]))
            selected = ImageTk.PhotoImage(icons.tab_icon(key, size=17, color="white"))
            self._icon_refs += [unselected, selected]
            nb.add(tab, text=label, image=unselected, compound="left")
            self._tab_icons[str(tab)] = (unselected, selected)

        nb.bind("<<NotebookTabChanged>>", self._sync_tab_icons)
        self._sync_tab_icons()

        status = "bitstream: {}   |   signature algorithms: {}   |   audio playback: {}".format(
            self.session.bits.name, ", ".join(a2.SIGNERS),
            "enabled" if PLAYBACK_AVAILABLE else "disabled (pip install sounddevice)")
        bar = tk.Label(self._body, text=status, anchor="w",
                       background=theme.COLORS["header_bg"],
                       foreground=theme.COLORS["header_sub"], font=theme.font(9),
                       padx=10, pady=5)
        bar.pack(fill="x", side="bottom")

    def _sync_tab_icons(self, _event=None):
        current = self.nb.select()
        for tab_id in self.nb.tabs():
            unselected, selected = self._tab_icons[tab_id]
            self.nb.tab(tab_id, image=selected if tab_id == current else unselected)

    def _set_window_icon(self):
        photo = ImageTk.PhotoImage(icons.window_icon(64, color=theme.COLORS["accent"]))
        self._icon_refs.append(photo)
        try:
            self.iconphoto(True, photo)
        except tk.TclError:
            pass

    def _build_header(self, parent):
        c = theme.COLORS
        header = tk.Frame(parent, background=c["header_bg"])
        header.pack(fill="x", side="top")
        row = tk.Frame(header, background=c["header_bg"])
        row.pack(fill="x", padx=18, pady=(14, 12))

        text_col = tk.Frame(row, background=c["header_bg"])
        text_col.pack(side="left", fill="x", expand=True)
        tk.Label(text_col, text="Steganographic Image & Audio Integrity Verification",
                background=c["header_bg"], foreground=c["header_fg"],
                font=theme.font(18, "bold")).pack(anchor="w")
        tk.Label(text_col, text="LSB steganography  •  digital signatures  •  hash "
                                "verification  •  tamper detection  •  INF2005 ACW1",
                background=c["header_bg"], foreground=c["header_sub"],
                font=theme.font(10)).pack(anchor="w", pady=(2, 0))

        # One single button carrying both the icon and the label text, so
        # the whole visible pill is one hit-region - previously the icon
        # and its "switch to X mode" caption were two separate widgets and
        # only the tiny icon was actually clickable. Must be a ttk.Button
        # (style="Toggle.TButton"), not a raw tk.Button - classic Tk buttons
        # render with native Aqua chrome on macOS and ignore color overrides,
        # which is why the toggle looked like a washed-out grey blob.
        toggle_icon = ImageTk.PhotoImage(icons.theme_icon(
            theme.MODE, size=16, color=c["header_fg"]))
        self._icon_refs.append(toggle_icon)
        other = "light" if theme.MODE == "dark" else "dark"
        toggle = ttk.Button(
            row, image=toggle_icon, text="  {} mode".format(other.capitalize()),
            compound="left", command=self.toggle_theme, style="Toggle.TButton")
        toggle.pack(side="right", padx=(10, 0), anchor="n")

    def report_callback_exception(self, exc, val, tb):
        """Safety net: Tk's default just prints a traceback to the terminal,
        so an unexpected error in any button looked like the button did
        nothing. Keep the traceback for debugging, but tell the user too."""
        traceback.print_exception(exc, val, tb)
        messagebox.showerror("Unexpected error",
                             "Something went wrong:\n\n{}: {}".format(exc.__name__, val))

    # =====================================================================
    def toggle_theme(self):
        """Rebuild the whole UI in the other palette. Session state (keys,
        last Protect result, etc.) survives - only in-progress, unsubmitted
        form text in the old widgets is lost, since colors are read at
        widget-construction time rather than watched live."""
        current_tab = self.nb.index(self.nb.select()) if self.nb.tabs() else 0
        theme.toggle_mode()
        self._body.destroy()
        self._build()
        if self.nb.tabs():
            self.nb.select(current_tab)

    def go_to_verify(self):
        self.nb.select(self.verify_tab)
        self.verify_tab.load_from_protect()


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
