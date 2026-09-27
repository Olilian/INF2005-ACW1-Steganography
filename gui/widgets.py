"""
gui/widgets.py - small reusable Tk widgets shared across tabs.

ScrollableFrame       vertically scrollable container; tabs pack content
                     into `.body` so tall content isn't clipped by the window
ImagePreview        thumbnail of a numpy image array
WaveformView         downsampled min/max envelope of an audio array, on a Canvas
CapacityBar          renders an a2_crypto.capacity_report() dict
VerdictBanner        renders an a2_crypto.Verdict
AudioPlayButton       plays/stops raw PCM through sounddevice, if available

Audio playback is optional: if sounddevice isn't installed the Play buttons
disable themselves instead of crashing the app, since playback is a nice-to
-have for the demo, not something the crypto/verdict logic depends on.

NOTE ON THE LIBRARY CHOICE: this used to go through `simpleaudio`, which
segfaults the whole process on Apple Silicon macOS the moment a clip finishes
playing naturally (confirmed: exit code 139/SIGSEGV, reproducible every
time). That is a native crash, not a Python exception, so no amount of
try/except in this file could have caught it. `sounddevice` (PortAudio
under the hood) plays the same buffers without crashing and is still
maintained.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

import numpy as np
from PIL import Image, ImageTk

from . import theme

try:
    import sounddevice as sd
    PLAYBACK_AVAILABLE = True
except ImportError:
    sd = None
    PLAYBACK_AVAILABLE = False


_DTYPE_FOR_SAMPWIDTH = {1: np.uint8, 2: np.int16, 4: np.int32}


def _pcm_bytes_to_array(data: bytes, sampwidth: int) -> np.ndarray:
    """Raw interleaved PCM bytes -> a dtype sounddevice/PortAudio accepts."""
    dtype = _DTYPE_FOR_SAMPWIDTH.get(sampwidth)
    if dtype is not None:
        return np.frombuffer(data, dtype=dtype)
    if sampwidth == 3:
        # no native 24-bit dtype - widen to int32 (same technique as
        # audio_codec.samples_for_waveform), scaled up so volume isn't tiny
        b = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
        as_int32 = (b[:, 0].astype(np.int32) | (b[:, 1].astype(np.int32) << 8)
                   | (b[:, 2].astype(np.int32) << 16))
        as_int32 = np.where(as_int32 & 0x800000, as_int32 - 0x1000000, as_int32)
        return (as_int32 << 8).astype(np.int32)
    raise ValueError("Unsupported sample width for playback: {} bytes".format(sampwidth))


def read_n_lsb(var) -> int | None:
    """The LSB spinbox value, or None after telling the user it's invalid.
    A spinbox accepts typed text, and IntVar.get() raises on 'abc'."""
    try:
        n = int(var.get())
    except (tk.TclError, ValueError):
        n = None
    if n is None or not 1 <= n <= 8:
        messagebox.showwarning("Invalid LSB count", "LSBs must be a whole number from 1 to 8.")
        return None
    return n


# =============================================================================
# scrollable container
# =============================================================================
class ScrollableFrame(ttk.Frame):
    """
    Scrollable container, both axes. A tab's content can be taller than the
    window (e.g. Protect's before/after comparison panel once it's full of
    thumbnails or waveforms), and narrower widgets (attack toolbar, the
    evidence log's fixed-width Treeview columns, parameter grids) can end up
    wider than the window once it's resized down - without this, that
    content is just clipped with no way to reach it. Tabs pack their widgets
    into `.body`, not into the tab frame itself.
    """

    def __init__(self, master):
        super().__init__(master)
        canvas = tk.Canvas(self, background=theme.COLORS["bg"], highlightthickness=0)
        vbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        hbar = ttk.Scrollbar(self, orient="horizontal", command=canvas.xview)
        canvas.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        vbar.pack(side="right", fill="y")
        hbar.pack(side="bottom", fill="x")
        canvas.pack(side="left", fill="both", expand=True)

        self.body = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=self.body, anchor="nw")

        # No width forcing here (unlike the old vertical-only version) - the
        # body is left free to grow past the canvas's own width when its
        # content needs it, which is what makes the horizontal scrollbar
        # able to reach that overflow instead of it just being clipped.
        # When content is narrower than the canvas it just leaves blank
        # canvas-colored space, which is invisible since the colors match.
        self.body.bind("<Configure>",
                       lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))

        def _wheel(event):
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")
            else:
                canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

        def _wheel_horizontal(event):
            if event.num == 6:
                canvas.xview_scroll(-1, "units")
            elif event.num == 7:
                canvas.xview_scroll(1, "units")
            else:
                canvas.xview_scroll(-1 if event.delta > 0 else 1, "units")

        # Bind the wheel only while the pointer is over this canvas, and via
        # bind_all so it fires no matter which child widget is directly
        # under the cursor (a button, label, etc. would otherwise swallow it).
        # Shift+wheel (or a trackpad's native horizontal swipe, which Tk
        # reports as Shift-MouseWheel on Windows/Linux and as its own
        # <Shift-MouseWheel>-less two-finger pan on macOS) scrolls sideways.
        def _bind_wheel(_e):
            canvas.bind_all("<MouseWheel>", _wheel)
            canvas.bind_all("<Shift-MouseWheel>", _wheel_horizontal)
            canvas.bind_all("<Button-4>", _wheel)
            canvas.bind_all("<Button-5>", _wheel)
            canvas.bind_all("<Shift-Button-4>", _wheel_horizontal)
            canvas.bind_all("<Shift-Button-5>", _wheel_horizontal)

        def _unbind_wheel(_e):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Shift-MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
            canvas.unbind_all("<Shift-Button-4>")
            canvas.unbind_all("<Shift-Button-5>")

        canvas.bind("<Enter>", _bind_wheel)
        canvas.bind("<Leave>", _unbind_wheel)


# =============================================================================
# image preview
# =============================================================================
class ImagePreview(ttk.LabelFrame):
    def __init__(self, master, title: str, size=(220, 220)):
        super().__init__(master, text=title)
        self.size = size
        self._label = tk.Label(self, background=theme.COLORS["card"],
                               foreground=theme.COLORS["muted"],
                               highlightthickness=1, highlightbackground=theme.COLORS["border"],
                               font=theme.font(10))
        self._label.pack(padx=6, pady=6)
        self._photo = None
        self.clear()

    def clear(self):
        self._photo = None
        self._label.configure(image="", text="(none)", width=26, height=13,
                              compound="center")

    def show_array(self, arr: np.ndarray):
        img = Image.fromarray(arr)
        img.thumbnail(self.size)
        self._photo = ImageTk.PhotoImage(img)
        self._label.configure(image=self._photo, text="", width=img.width,
                              height=img.height)


# =============================================================================
# audio waveform
# =============================================================================
def _downsample_minmax(samples: np.ndarray, buckets: int):
    n = len(samples)
    if n == 0:
        return np.zeros(1), np.zeros(1)
    buckets = max(1, min(buckets, n))
    edges = np.linspace(0, n, buckets + 1, dtype=int)
    mins = np.empty(buckets)
    maxs = np.empty(buckets)
    for i in range(buckets):
        lo, hi = edges[i], max(edges[i + 1], edges[i] + 1)
        seg = samples[lo:hi]
        mins[i] = seg.min()
        maxs[i] = seg.max()
    return mins, maxs


class WaveformView(tk.Canvas):
    """A single min/max amplitude envelope, scaled against a shared peak so
    cover and stego panels drawn side by side are visually comparable."""

    def __init__(self, master, width=460, height=90, color=None):
        super().__init__(master, width=width, height=height,
                         background=theme.COLORS["card"], highlightthickness=1,
                         highlightbackground=theme.COLORS["border"])
        # NOTE: cannot be named self._w / self._h - Tkinter widgets already
        # use self._w internally for their own Tcl widget path name.
        self._plot_w, self._plot_h = width, height
        self._color = color or theme.COLORS["accent"]

    def draw(self, samples: np.ndarray, peak: float | None = None):
        self.delete("all")
        if samples is None or len(samples) == 0:
            self.create_text(self._plot_w // 2, self._plot_h // 2, text="(no audio)",
                             fill=theme.COLORS["muted"])
            return
        buckets = max(1, self._plot_w // 2)
        mins, maxs = _downsample_minmax(samples.astype(np.float64), buckets)
        peak = peak or max(1.0, float(np.max(np.abs(samples))))
        mid = self._plot_h / 2
        scale = (self._plot_h / 2 - 4) / peak
        step = self._plot_w / buckets
        self.create_line(0, mid, self._plot_w, mid, fill=theme.COLORS["border"])
        for i in range(buckets):
            x = i * step + step / 2
            y0 = mid - maxs[i] * scale
            y1 = mid - mins[i] * scale
            self.create_line(x, y0, x, y1, fill=self._color)


class AudioPlayButton(ttk.Frame):
    """Play/Stop for one raw-PCM audio view. Disabled if sounddevice is absent."""

    def __init__(self, master, get_pcm):
        super().__init__(master)
        self._get_pcm = get_pcm          # callable -> (bytes, n_channels, sampwidth, framerate) | None
        state = "normal" if PLAYBACK_AVAILABLE else "disabled"
        self.play_btn = ttk.Button(self, text="Play", command=self._play, state=state)
        self.play_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(self, text="Stop", command=self._stop, state=state)
        self.stop_btn.pack(side="left", padx=2)
        if not PLAYBACK_AVAILABLE:
            ttk.Label(self, text="(install sounddevice to enable playback)",
                     foreground=theme.COLORS["muted"]).pack(side="left", padx=4)

    def _play(self):
        if not PLAYBACK_AVAILABLE:
            return
        pcm = self._get_pcm()
        if pcm is None:
            return
        data, n_channels, sampwidth, framerate = pcm
        try:
            self._stop()
            arr = _pcm_bytes_to_array(data, sampwidth)
            if n_channels > 1:
                arr = arr.reshape(-1, n_channels)
            sd.play(arr, framerate)
        except Exception as exc:  # e.g. no audio output device on a lab/projector PC
            messagebox.showerror("Audio playback failed",
                                 "Could not play this clip: {}".format(exc))

    def _stop(self):
        if PLAYBACK_AVAILABLE:
            sd.stop()


# =============================================================================
# capacity bar
# =============================================================================
class CapacityBar(ttk.LabelFrame):
    def __init__(self, master):
        super().__init__(master, text="Capacity check (cover vs payload) - FR mandatory case")
        self.bar = ttk.Progressbar(self, maximum=100, length=460,
                                   style="Horizontal.TProgressbar")
        self.bar.pack(side="left", padx=10, pady=10)
        self.text = tk.StringVar(value="load a cover to see capacity")
        self.label = tk.Label(self, textvariable=self.text, font=theme.font(11, "bold"),
                              background=theme.COLORS["bg"], foreground=theme.COLORS["muted"])
        self.label.pack(side="left", padx=8)

    def update_report(self, report: dict):
        pct = report["utilisation_percent"]
        self.bar["value"] = min(pct, 100)
        fits = report["fits"]
        self.bar.configure(style="Good.Horizontal.TProgressbar" if fits
                           else "Bad.Horizontal.TProgressbar")
        mark = "FITS" if fits else "TOO BIG - would be BLOCKED"
        self.text.set("need {:,} bits / {:,} usable ({}%)  [{}]".format(
            report["needed_bits"], report["usable_bits"], pct, mark))
        self.label.configure(foreground=theme.COLORS["good"] if fits else theme.COLORS["bad"])

    def set_message(self, text: str):
        self.text.set(text)
        self.bar["value"] = 0
        self.bar.configure(style="Horizontal.TProgressbar")
        self.label.configure(foreground=theme.COLORS["muted"])


# =============================================================================
# verdict banner
# =============================================================================
class VerdictBanner(tk.Frame):
    def __init__(self, master):
        super().__init__(master, background=theme.COLORS["bg"], highlightthickness=1,
                         highlightbackground=theme.COLORS["border"])
        self._idle_bg = theme.COLORS["idle_bg"]
        self._idle_fg = theme.COLORS["idle_fg"]
        self.banner = tk.Label(self, text="NO VERDICT YET", font=theme.font(18, "bold"),
                               bg=self._idle_bg, fg=self._idle_fg, height=2)
        self.banner.pack(fill="x")
        self.reason = tk.Label(self, text="Run Protect then Verify (or an attack) to see a "
                                          "result here.", wraplength=1000, justify="left",
                               background=theme.COLORS["bg"], foreground=theme.COLORS["muted"],
                               font=theme.font(10), padx=10, pady=6)
        self.reason.pack(fill="x")

    def show(self, verdict, replay_of: str | None = None):
        if replay_of:
            self.banner.configure(text="{} - REPLAY DETECTED".format(str(verdict.code).upper()),
                                  bg=theme.COLORS["warn"], fg=theme.COLORS["bg"])
            self.reason.configure(
                text="The signature and hash check out, but this exact payload (same signed "
                     "nonce) was already accepted earlier this session, from: {}. A genuine "
                     "file being delivered again is a replay - treat it as suspicious. "
                     "(Remembered only while the app is open.)".format(replay_of),
                foreground=theme.COLORS["text"])
            return
        self.banner.configure(text=str(verdict.code).upper(), bg=verdict.colour, fg="white")
        self.reason.configure(text=verdict.reason, foreground=theme.COLORS["text"])

    def clear(self):
        self.banner.configure(text="NO VERDICT YET", bg=self._idle_bg, fg=self._idle_fg)
        self.reason.configure(text="", foreground=theme.COLORS["muted"])
