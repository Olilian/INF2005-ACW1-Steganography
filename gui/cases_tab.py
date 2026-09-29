"""
gui/cases_tab.py - the image and audio required test cases, run from
the GUI with an expected-vs-actual evidence log (same idea as the Attack tab).

Mirrors the cases in tests/test_image_codec.py and tests/test_audio_codec.py:
a positive protect + verify, tampering, wrong passphrase, wrong public key,
the capacity check, the three payload sizes and the LSB 1-8 sweep. Each case
protects a fresh copy of the chosen cover in memory; nothing is written into
the repo, and the session's replay memory is not touched.
"""
from __future__ import annotations

import os
import tempfile
import tkinter as tk
import wave
from tkinter import messagebox, ttk

import numpy as np
from PIL import Image

import a2_crypto as a2

from . import session as sess
from . import theme
from .widgets import FileLoadRow, ScrollableFrame

N_LSB = 2
ALGO = a2.DEFAULT_SIGN_ALGO
AUTHENTIC = str(a2.VerdictCode.AUTHENTIC)
BLOCKED = "Blocked (capacity check)"

CASES = (
    ("positive", "Positive: protect + verify"),
    ("tamper", "Tampered content"),
    ("passphrase", "Wrong passphrase"),
    ("wrongkey", "Wrong public key"),
    ("capacity", "Capacity check (tiny cover)"),
    ("sizes", "Payload sizes (short / large / custom)"),
    ("sweep", "LSB sweep 1-8"),
)
EXPECTED_CAPTION = {
    "positive": "-> Authentic",
    "tamper": "-> Tampered",
    "passphrase": "-> Wrong Start Location",
    "wrongkey": "-> Signature Invalid",
    "capacity": "-> Blocked",
    "sizes": "-> Authentic x3",
    "sweep": "-> Authentic x8",
}


class TestCasesTab(ttk.Frame):
    def __init__(self, master, session: sess.SessionState):
        super().__init__(master)
        self.session = session
        self._media, self._path = "image", sess.SAMPLE_COVERS["image"]
        self._jobs: list = []
        self._buttons: list = []
        self._build()
        self._set_cover(self._media, self._path)   # start on the sample image

    # ------------------------------------------------------------------ ui
    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        body = scroll.body
        c = theme.COLORS

        ttk.Label(body, text="The required image and audio test cases (same as "
                             "tests/test_image_codec.py and tests/test_audio_codec.py), run "
                             "on the chosen cover. Each case protects a fresh in-memory copy, "
                             "verifies it, and logs the expected verdict against the actual one.",
                 foreground=c["muted"], wraplength=1080).pack(fill="x", padx=8, pady=(8, 4))

        cov = ttk.LabelFrame(body, text="Cover object (load an ORIGINAL file, not a stego file)")
        cov.pack(fill="x", padx=8, pady=6)
        self.loader = FileLoadRow(cov, self._set_cover, dialog_title="Select cover",
                                  empty_text="", samples=True)
        self.loader.pack(fill="x")

        tb = ttk.LabelFrame(body, text="Test cases")
        tb.pack(fill="x", padx=8, pady=6)
        for i, (key, label) in enumerate(CASES):
            cell = ttk.Frame(tb)
            cell.grid(row=i // 4, column=i % 4, padx=4, pady=4, sticky="ew")
            b = ttk.Button(cell, text=label, command=lambda k=key: self._run([k]))
            b.pack(fill="x")
            self._buttons.append(b)
            ttk.Label(cell, text=EXPECTED_CAPTION[key], foreground=c["muted"], anchor="center",
                      font=theme.font(9)).pack(fill="x")
        for col in range(4):
            tb.columnconfigure(col, weight=1)

        actions = ttk.Frame(body)
        actions.pack(fill="x", padx=8, pady=4)
        run_all = ttk.Button(actions, text="Run all cases", style="Accent.TButton",
                             command=lambda: self._run([k for k, _l in CASES]))
        run_all.pack(side="left")
        self._buttons.append(run_all)
        clear = ttk.Button(actions, text="Clear log", command=self._clear_log)
        clear.pack(side="left", padx=6)
        self._buttons.append(clear)

        self.status = tk.Label(body, text="Pick a case, or Run all cases.", anchor="w",
                               background=c["idle_bg"], foreground=c["idle_fg"],
                               font=theme.font(12, "bold"), padx=10, pady=8)
        self.status.pack(fill="x", padx=8, pady=(6, 0))

        log_frame = ttk.LabelFrame(body, text="Evidence log (screenshot this for the submission)")
        log_frame.pack(fill="both", expand=True, padx=8, pady=6)
        cols = ("case", "media", "expected", "actual", "match", "details")
        self.log = ttk.Treeview(log_frame, columns=cols, show="headings", height=14)
        for col, w in zip(cols, (230, 70, 190, 190, 60, 380)):
            self.log.heading(col, text=col)
            self.log.column(col, width=w, anchor="w")
        self.log.pack(fill="both", expand=True)

    def _set_status(self, text, kind):
        c = theme.COLORS
        bg, fg = {"idle": (c["idle_bg"], c["idle_fg"]), "run": (c["accent_soft"], c["accent_dark"]),
                  "pass": (c["good_bg"], c["good"]), "fail": (c["bad_bg"], c["bad"])}[kind]
        self.status.configure(text=text, background=bg, foreground=fg)

    # --------------------------------------------------------------- cover
    def _set_cover(self, media_type: str, path: str):
        """Checked by loading it once here, so a bad file is reported
        straight away rather than in the middle of a run."""
        try:
            self.session.codec_for(media_type).load(path)
        except Exception as exc:
            messagebox.showerror("Load failed", "{}: {}".format(type(exc).__name__, exc))
            return
        self._media, self._path = media_type, path
        self.loader.set_loaded("Loaded: {}   ({} - media ID {}, {} LSBs, default passphrase, "
                               "{})".format(os.path.basename(path), media_type,
                                            sess.DEFAULT_MEDIA_ID[media_type], N_LSB, ALGO))

    def _clear_log(self):
        self.log.delete(*self.log.get_children())
        self._set_status("Pick a case, or Run all cases.", "idle")

    # ------------------------------------------------------------- running
    def _run(self, keys):
        if self._jobs:
            return
        m = self._media
        codec = self.session.codec_for(m)
        try:
            view = codec.load(self._path)
        except Exception as exc:
            messagebox.showerror("Cover failed to load", "{}: {}".format(type(exc).__name__, exc))
            return
        priv, pub, _pub_path = self.session.keys_for(ALGO)
        impostor = a2.load_public(self.session.impostor_public_path(ALGO))
        self._ctx = dict(media=m, codec=codec, view=view, priv=priv, pub=pub, impostor=impostor,
                         media_id=sess.DEFAULT_MEDIA_ID[m])
        self._jobs = []
        for key in keys:
            if key == "sizes":
                self._jobs += [(key, size) for size in ("short", "large", "custom")]
            elif key == "sweep":
                self._jobs += [(key, n) for n in range(1, 9)]
            else:
                self._jobs.append((key, None))
        self._run_matched = self._run_total = 0
        for b in self._buttons:
            b.configure(state="disabled")
        self._step()

    def _step(self):
        if not self.winfo_exists():   # tab rebuilt by the theme toggle mid-run
            return
        if not self._jobs:
            self._finish()
            return
        key, arg = self._jobs.pop(0)
        self._set_status("Running: {} ...".format(dict(CASES)[key]), "run")
        self.update_idletasks()
        try:
            case, expected, actual, detail = getattr(self, "_case_" + key)(arg, **self._ctx)
        except Exception as exc:
            case, expected, actual, detail = dict(CASES)[key], "-", "ERROR", "{}: {}".format(
                type(exc).__name__, exc)
        match = actual == expected
        self._run_total += 1
        self._run_matched += match
        row = self.log.insert("", "end", values=(case, self._ctx["media"], expected, actual,
                                                 "yes" if match else "no", detail))
        self.log.see(row)
        self.after(10, self._step)

    def _finish(self):
        for b in self._buttons:
            b.configure(state="normal")
        ok = self._run_matched == self._run_total
        self._set_status("{} of {} cases matched the expected result".format(
            self._run_matched, self._run_total), "pass" if ok else "fail")

    # ------------------------------------------------------------- helpers
    def _protect(self, message, n_lsb=N_LSB, *, codec, view, priv, media_id, media, **_):
        return a2.protect(view, message, media_id, n_lsb, sess.DEFAULT_PASSPHRASE, priv,
                          codec=codec, bits=self.session.bits, media_type=media, algo=ALGO)

    def _verify(self, stego_view, key, n_lsb=N_LSB, passphrase=sess.DEFAULT_PASSPHRASE, *,
                codec, media_id, **_):
        return a2.verify(stego_view, media_id, n_lsb, passphrase, key, codec=codec,
                         bits=self.session.bits, algo=ALGO)

    @staticmethod
    def _change_detail(stats) -> str:
        if "max_channel_delta" in stats:
            return "{:,} px changed ({}%), max delta {}".format(
                stats["changed_pixels"], stats["percent_changed"], stats["max_channel_delta"])
        return "{:,} bytes changed ({}%), max delta {}".format(
            stats["changed_bytes"], stats["percent_changed"], stats["max_byte_delta"])

    # --------------------------------------------------------------- cases
    def _case_positive(self, _arg, **ctx):
        message = sess.MESSAGE_PRESETS["short"]()
        res = self._protect(message, **ctx)
        v = self._verify(res.stego_view, ctx["pub"], **ctx)
        actual = str(v.code)
        if v.code is a2.VerdictCode.AUTHENTIC and v.message_text() != message:
            actual += " (wrong message)"
        detail = "message recovered; start unit {:,}; {}".format(
            res.start_unit, self._change_detail(ctx["codec"].compare(ctx["view"], res.stego_view)))
        return "Positive: protect + verify", AUTHENTIC, actual, detail

    def _case_tamper(self, _arg, **ctx):
        codec = ctx["codec"]
        res = self._protect(sess.MESSAGE_PRESETS["short"](), **ctx)
        samples = bytearray(codec.read_samples(res.stego_view))
        for i in range(max(0, len(samples) - 3000), len(samples)):
            samples[i] ^= 0xFF
        tampered = codec.write_samples(res.stego_view, bytes(samples))
        v = self._verify(tampered, ctx["pub"], **ctx)
        return ("Tampered content", str(a2.VerdictCode.TAMPERED), str(v.code),
                "every bit of the last 3,000 cover bytes flipped after signing")

    def _case_passphrase(self, _arg, **ctx):
        res = self._protect(sess.MESSAGE_PRESETS["short"](), **ctx)
        v = self._verify(res.stego_view, ctx["pub"], passphrase="wrong-passphrase", **ctx)
        return ("Wrong passphrase", str(a2.VerdictCode.WRONG_START_LOCATION), str(v.code),
                "verified with 'wrong-passphrase' - start location derived elsewhere")

    def _case_wrongkey(self, _arg, **ctx):
        res = self._protect(sess.MESSAGE_PRESETS["short"](), **ctx)
        v = self._verify(res.stego_view, ctx["impostor"], **ctx)
        return ("Wrong public key", str(a2.VerdictCode.SIGNATURE_INVALID), str(v.code),
                "verified with an impostor's public key")

    def _case_capacity(self, _arg, **ctx):
        codec, media = ctx["codec"], ctx["media"]
        path = os.path.join(tempfile.gettempdir(),
                            "acw1_tiny_cover" + (".png" if media == "image" else ".wav"))
        if media == "image":
            Image.fromarray(np.zeros((2, 2, 3), dtype=np.uint8)).save(path)
        else:
            with wave.open(path, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(8000)
                wf.writeframes(np.zeros(4, dtype=np.int16).tobytes())
        tiny = dict(ctx, view=codec.load(path))
        try:
            self._protect(sess.MESSAGE_PRESETS["short"](), **tiny)
        except a2.CapacityError as exc:
            return "Capacity check (tiny cover)", BLOCKED, BLOCKED, str(exc)
        return "Capacity check (tiny cover)", BLOCKED, "Embedded (not blocked)", \
            "a payload larger than the cover was accepted"

    def _case_sizes(self, size, **ctx):
        message = sess.MESSAGE_PRESETS[size]()
        res = self._protect(message, **ctx)
        v = self._verify(res.stego_view, ctx["pub"], **ctx)
        actual = str(v.code)
        if v.code is a2.VerdictCode.AUTHENTIC and v.message_text() != message:
            actual += " (wrong message)"
        return ("Payload size: " + size, AUTHENTIC, actual,
                "{:,} chars -> {:,} bytes embedded".format(len(message), res.stream_bytes))

    def _case_sweep(self, n_lsb, **ctx):
        res = self._protect(sess.MESSAGE_PRESETS["short"](), n_lsb, **ctx)
        v = self._verify(res.stego_view, ctx["pub"], n_lsb, **ctx)
        return ("LSB sweep: {} bit{}".format(n_lsb, "" if n_lsb == 1 else "s"), AUTHENTIC,
                str(v.code), self._change_detail(ctx["codec"].compare(ctx["view"], res.stego_view)))
