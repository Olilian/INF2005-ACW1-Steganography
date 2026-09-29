"""
gui/cases_tab.py - the image and audio required test cases, run from
the GUI with an expected-vs-actual evidence log (same idea as the Attack tab).

Mirrors the cases in tests/test_image_codec.py and tests/test_audio_codec.py:
a positive protect + verify, tampering, wrong passphrase, wrong public key,
the capacity check, the three payload sizes and the LSB 1-8 sweep.

Nothing is pre-computed: every input (media ID, LSBs, passphrase, algorithm,
message) is editable, each case protects a fresh in-memory copy of the cover
with those values and verifies it, and clicking a log row shows exactly what
went in and what came out - including the payload's nonce and timestamp,
which differ on every run. Nothing is written into the repo, and the
session's replay memory is not touched.
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
from .widgets import FileLoadRow, ScrollableFrame, read_n_lsb

AUTHENTIC = str(a2.VerdictCode.AUTHENTIC)
BLOCKED = "Blocked (capacity check)"
TAMPER_BYTES = 3000

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


def _preview(text: str, n: int = 70) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= n else one_line[:n] + "..."


class TestCasesTab(ttk.Frame):
    def __init__(self, master, session: sess.SessionState):
        super().__init__(master)
        self.session = session
        self._media, self._path = "image", sess.SAMPLE_COVERS["image"]
        self.media_id = tk.StringVar(value=sess.DEFAULT_MEDIA_ID["image"])
        self.n_lsb = tk.IntVar(value=2)
        self.passphrase = tk.StringVar(value=sess.DEFAULT_PASSPHRASE)
        self.algo = tk.StringVar(value=a2.DEFAULT_SIGN_ALGO)
        self._jobs: list = []
        self._buttons: list = []
        self._records: dict = {}       # log row id -> everything that case used/produced
        self._build()
        self._set_cover(self._media, self._path)   # start on the sample image

    # ------------------------------------------------------------------ ui
    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        body = scroll.body
        c = theme.COLORS

        ttk.Label(body, text="The required image and audio test cases (same as "
                             "tests/test_image_codec.py and tests/test_audio_codec.py). Every "
                             "input below is editable - change any of them and re-run. Each case "
                             "protects a fresh copy of the cover with those inputs and verifies "
                             "it live; click a log row to see exactly what went in and came out.",
                 foreground=c["muted"], wraplength=1080).pack(fill="x", padx=8, pady=(8, 4))

        cov = ttk.LabelFrame(body, text="Cover object (load an ORIGINAL file, not a stego file)")
        cov.pack(fill="x", padx=8, pady=6)
        self.loader = FileLoadRow(cov, self._set_cover, dialog_title="Select cover",
                                  empty_text="", samples=True)
        self.loader.pack(fill="x")

        inp = ttk.LabelFrame(body, text="Test inputs (editable - the cases use exactly these values)")
        inp.pack(fill="x", padx=8, pady=6)
        ttk.Label(inp, text="Media ID:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(inp, textvariable=self.media_id, width=16).grid(row=0, column=1, sticky="w")
        ttk.Label(inp, text="LSBs:").grid(row=0, column=2, sticky="e", padx=(12, 4))
        ttk.Spinbox(inp, from_=1, to=8, textvariable=self.n_lsb, width=5).grid(
            row=0, column=3, sticky="w")
        ttk.Label(inp, text="Passphrase:").grid(row=0, column=4, sticky="e", padx=(12, 4))
        ttk.Entry(inp, textvariable=self.passphrase, width=28).grid(row=0, column=5, sticky="w")
        ttk.Label(inp, text="Signature:").grid(row=0, column=6, sticky="e", padx=(12, 4))
        ttk.Combobox(inp, textvariable=self.algo, width=12, state="readonly",
                     values=list(a2.SIGNERS)).grid(row=0, column=7, sticky="w")

        ttk.Label(inp, text="Message:").grid(row=1, column=0, sticky="ne", padx=4, pady=4)
        self.msg_text = tk.Text(inp, height=3, wrap="word", font=theme.mono_font(10),
                                background=c["field"], foreground=c["text"],
                                insertbackground=c["text"], relief="flat",
                                highlightthickness=1, highlightbackground=c["border"])
        self.msg_text.grid(row=1, column=1, columnspan=7, sticky="ew", pady=4)
        self.msg_text.insert("1.0", sess.MESSAGE_PRESETS["short"]())
        ttk.Button(inp, text="Reset to short preset", command=self._reset_message).grid(
            row=1, column=8, sticky="n", padx=6, pady=4)
        inp.columnconfigure(7, weight=1)
        ttk.Label(inp, text="Payload sizes always uses the brief's short / large / custom "
                            "messages, and the LSB sweep runs every depth from 1 to 8 - "
                            "everything else uses the values above.",
                  foreground=c["muted"]).grid(row=2, column=0, columnspan=9, sticky="w",
                                              padx=4, pady=(0, 4))

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

        log_frame = ttk.LabelFrame(body, text="Evidence log")
        log_frame.pack(fill="both", expand=True, padx=8, pady=6)
        cols = ("case", "media", "expected", "actual", "match", "details")
        self.log = ttk.Treeview(log_frame, columns=cols, show="headings", height=10)
        for col, w in zip(cols, (230, 70, 190, 190, 60, 380)):
            self.log.heading(col, text=col)
            self.log.column(col, width=w, anchor="w")
        self.log.pack(fill="both", expand=True)
        self.log.bind("<<TreeviewSelect>>", self._show_selected)

        det = ttk.LabelFrame(body, text="Case details - click a row above (inputs used, what "
                                        "was changed, outputs computed live)")
        det.pack(fill="both", expand=True, padx=8, pady=6)
        self.details = tk.Text(det, height=16, wrap="word", font=theme.mono_font(10),
                               background=c["field"], foreground=c["text"], relief="flat",
                               highlightthickness=0, state="disabled")
        self.details.pack(fill="both", expand=True, padx=2, pady=2)

    def _set_status(self, text, kind):
        c = theme.COLORS
        bg, fg = {"idle": (c["idle_bg"], c["idle_fg"]), "run": (c["accent_soft"], c["accent_dark"]),
                  "pass": (c["good_bg"], c["good"]), "fail": (c["bad_bg"], c["bad"])}[kind]
        self.status.configure(text=text, background=bg, foreground=fg)

    # --------------------------------------------------------------- inputs
    def _set_cover(self, media_type: str, path: str):
        """Checked by loading it once here, so a bad file is reported
        straight away rather than in the middle of a run."""
        codec = self.session.codec_for(media_type)
        try:
            view = codec.load(path)
        except Exception as exc:
            messagebox.showerror("Load failed", "{}: {}".format(type(exc).__name__, exc))
            return
        self._media, self._path = media_type, path
        self.media_id.set(sess.DEFAULT_MEDIA_ID[media_type])
        self.loader.set_loaded("Loaded: {}   ({}, {:,} units)".format(
            os.path.basename(path), codec.name, len(codec.read_samples(view))))

    def _reset_message(self):
        self.msg_text.delete("1.0", "end")
        self.msg_text.insert("1.0", sess.MESSAGE_PRESETS["short"]())

    def _clear_log(self):
        self.log.delete(*self.log.get_children())
        self._records.clear()
        self._write_details("")
        self._set_status("Pick a case, or Run all cases.", "idle")

    # ------------------------------------------------------------- running
    def _run(self, keys):
        if self._jobs:
            return
        n_lsb = read_n_lsb(self.n_lsb)
        if n_lsb is None:
            return
        media_id, passphrase = self.media_id.get().strip(), self.passphrase.get()
        message = self.msg_text.get("1.0", "end-1c")
        if not media_id or not passphrase or not message:
            messagebox.showwarning("Missing input",
                                   "Media ID, passphrase and message all need a value.")
            return
        m = self._media
        codec = self.session.codec_for(m)
        try:
            view = codec.load(self._path)
        except Exception as exc:
            messagebox.showerror("Cover failed to load", "{}: {}".format(type(exc).__name__, exc))
            return
        algo = self.algo.get()
        priv, pub, _pub_path = self.session.keys_for(algo)
        impostor = a2.load_public(self.session.impostor_public_path(algo))
        self._ctx = dict(media=m, codec=codec, view=view, cover_name=os.path.basename(self._path),
                         priv=priv, pub=pub, impostor=impostor, algo=algo, media_id=media_id,
                         n_lsb=n_lsb, passphrase=passphrase, message=message)
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
            rec = getattr(self, "_case_" + key)(arg, self._ctx)
        except Exception as exc:
            rec = dict(case=dict(CASES)[key], expected="-", actual="ERROR",
                       detail="{}: {}".format(type(exc).__name__, exc), inputs=[], outputs=[])
        rec["match"] = rec["actual"] == rec["expected"]
        self._run_total += 1
        self._run_matched += rec["match"]
        row = self.log.insert("", "end", values=(rec["case"], self._ctx["media"], rec["expected"],
                                                 rec["actual"], "yes" if rec["match"] else "no",
                                                 rec["detail"]))
        self._records[row] = rec
        self.log.selection_set(row)    # show the newest case's details as it lands
        self.log.see(row)
        self._write_details(self._format(rec))
        self.after(10, self._step)

    def _finish(self):
        for b in self._buttons:
            b.configure(state="normal")
        ok = self._run_matched == self._run_total
        self._set_status("{} of {} cases matched the expected result".format(
            self._run_matched, self._run_total), "pass" if ok else "fail")

    # ------------------------------------------------------------- details
    def _show_selected(self, _event=None):
        sel = self.log.selection()
        if sel and sel[0] in self._records:
            self._write_details(self._format(self._records[sel[0]]))

    def _write_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    @staticmethod
    def _format(rec) -> str:
        lines = ["{}".format(rec["case"]),
                 "expected: {}   actual: {}   match: {}".format(
                     rec["expected"], rec["actual"], "yes" if rec["match"] else "no"), ""]
        lines.append("INPUTS")
        lines += ["  {:<24}: {}".format(k, v) for k, v in rec["inputs"]]
        if rec.get("change"):
            lines += ["", "WHAT THIS CASE CHANGED", "  " + rec["change"]]
        lines += ["", "OUTPUTS (computed live - the nonce and timestamp are new on every run)"]
        lines += ["  {:<24}: {}".format(k, v) for k, v in rec["outputs"]]
        if rec.get("note"):
            lines += ["", "NOTE: " + rec["note"]]
        return "\n".join(lines)

    # ------------------------------------------------------------- helpers
    def _protect(self, ctx, message, n_lsb=None, view=None):
        return a2.protect(ctx["view"] if view is None else view, message, ctx["media_id"],
                          n_lsb or ctx["n_lsb"], ctx["passphrase"], ctx["priv"],
                          codec=ctx["codec"], bits=self.session.bits, media_type=ctx["media"],
                          algo=ctx["algo"])

    def _verify(self, ctx, stego_view, key=None, n_lsb=None, passphrase=None):
        return a2.verify(stego_view, ctx["media_id"], n_lsb or ctx["n_lsb"],
                         passphrase or ctx["passphrase"], key or ctx["pub"],
                         codec=ctx["codec"], bits=self.session.bits, algo=ctx["algo"])

    @staticmethod
    def _change_detail(stats) -> str:
        if "max_channel_delta" in stats:
            return "{:,} px changed ({}%), max delta {}".format(
                stats["changed_pixels"], stats["percent_changed"], stats["max_channel_delta"])
        return "{:,} bytes changed ({}%), max delta {}".format(
            stats["changed_bytes"], stats["percent_changed"], stats["max_byte_delta"])

    def _inputs(self, ctx, message, n_lsb=None, verify_passphrase=None, verify_key=None,
                cover=None):
        verify_key = verify_key or ctx["pub"]
        key_note = " (IMPOSTOR key)" if verify_key is ctx["impostor"] else " (matches signer)"
        return [
            ("Cover", cover or "{} ({})".format(ctx["cover_name"], ctx["media"])),
            ("Media ID", ctx["media_id"]),
            ("LSBs", n_lsb or ctx["n_lsb"]),
            ("Passphrase at protect", ctx["passphrase"]),
            ("Passphrase at verify", verify_passphrase or ctx["passphrase"]),
            ("Signature algorithm", ctx["algo"]),
            ("Signer's public key", a2.public_fingerprint(ctx["pub"])),
            ("Verified with key", a2.public_fingerprint(verify_key) + key_note),
            ("Message", "{:,} chars: {}".format(len(message), _preview(message))),
        ]

    def _outputs(self, ctx, res, v):
        out = [("Derived start unit", "{:,}".format(res.start_unit)),
               ("Bytes embedded", "{:,}".format(res.stream_bytes)),
               ("Payload timestamp", res.payload.ts),
               ("Payload nonce", res.payload.nonce),
               ("Cover change", self._change_detail(ctx["codec"].compare(ctx["view"],
                                                                         res.stego_view))),
               ("Verdict", str(v.code)),
               ("Verdict reason", v.reason)]
        recovered = v.message_text() if v.message is not None else None
        out.append(("Recovered message", _preview(recovered) if recovered else "(none)"))
        return out

    @staticmethod
    def _recovered_ok(v, message) -> str:
        actual = str(v.code)
        if v.code is a2.VerdictCode.AUTHENTIC and v.message_text() != message:
            actual += " (wrong message)"
        return actual

    # --------------------------------------------------------------- cases
    def _case_positive(self, _arg, ctx):
        message = ctx["message"]
        res = self._protect(ctx, message)
        v = self._verify(ctx, res.stego_view)
        return dict(case="Positive: protect + verify", expected=AUTHENTIC,
                    actual=self._recovered_ok(v, message),
                    detail="message recovered; start unit {:,}".format(res.start_unit),
                    inputs=self._inputs(ctx, message), outputs=self._outputs(ctx, res, v))

    def _case_tamper(self, _arg, ctx):
        codec, message = ctx["codec"], ctx["message"]
        res = self._protect(ctx, message)
        samples = bytearray(codec.read_samples(res.stego_view))
        first = max(0, len(samples) - TAMPER_BYTES)
        for i in range(first, len(samples)):
            samples[i] ^= 0xFF
        tampered = codec.write_samples(res.stego_view, bytes(samples))
        v = self._verify(ctx, tampered)
        note = ("at 8 LSBs every bit carries payload, so content tampering cannot be "
                "detected - a documented limitation." if ctx["n_lsb"] == 8 else None)
        return dict(case="Tampered content", expected=str(a2.VerdictCode.TAMPERED),
                    actual=str(v.code), detail="last {:,} cover bytes flipped after signing".format(
                        TAMPER_BYTES),
                    inputs=self._inputs(ctx, message),
                    change="after protecting, flipped every bit of cover bytes {:,}-{:,} "
                           "(the last {:,}) - the payload itself was not touched".format(
                               first, len(samples) - 1, TAMPER_BYTES),
                    outputs=self._outputs(ctx, res, v), note=note)

    def _case_passphrase(self, _arg, ctx):
        message = ctx["message"]
        wrong = ctx["passphrase"] + "-wrong"
        res = self._protect(ctx, message)
        v = self._verify(ctx, res.stego_view, passphrase=wrong)
        return dict(case="Wrong passphrase", expected=str(a2.VerdictCode.WRONG_START_LOCATION),
                    actual=str(v.code), detail="verified with '{}'".format(wrong),
                    inputs=self._inputs(ctx, message, verify_passphrase=wrong),
                    change="verify used '{}' instead of '{}', so it derived a different start "
                           "location".format(wrong, ctx["passphrase"]),
                    outputs=self._outputs(ctx, res, v))

    def _case_wrongkey(self, _arg, ctx):
        message = ctx["message"]
        res = self._protect(ctx, message)
        v = self._verify(ctx, res.stego_view, key=ctx["impostor"])
        return dict(case="Wrong public key", expected=str(a2.VerdictCode.SIGNATURE_INVALID),
                    actual=str(v.code), detail="verified with an impostor's public key",
                    inputs=self._inputs(ctx, message, verify_key=ctx["impostor"]),
                    change="verify used the impostor public key {} instead of the signer's "
                           "{}".format(a2.public_fingerprint(ctx["impostor"]),
                                       a2.public_fingerprint(ctx["pub"])),
                    outputs=self._outputs(ctx, res, v))

    def _case_capacity(self, _arg, ctx):
        codec, media, message = ctx["codec"], ctx["media"], ctx["message"]
        path = os.path.join(tempfile.gettempdir(),
                            "acw1_tiny_cover" + (".png" if media == "image" else ".wav"))
        if media == "image":
            Image.fromarray(np.zeros((2, 2, 3), dtype=np.uint8)).save(path)
            tiny_name = "generated 2x2 PNG (4 pixels)"
        else:
            with wave.open(path, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(8000)
                wf.writeframes(np.zeros(4, dtype=np.int16).tobytes())
            tiny_name = "generated 4-sample WAV"
        inputs = self._inputs(ctx, message, cover=tiny_name)
        change = "the cover was swapped for a tiny {} before protecting".format(tiny_name)
        try:
            self._protect(ctx, message, view=codec.load(path))
        except a2.CapacityError as exc:
            return dict(case="Capacity check (tiny cover)", expected=BLOCKED, actual=BLOCKED,
                        detail=str(exc), inputs=inputs, change=change,
                        outputs=[("Result", "protect() refused to embed"),
                                 ("Reason", str(exc))])
        return dict(case="Capacity check (tiny cover)", expected=BLOCKED,
                    actual="Embedded (not blocked)", detail="payload larger than the cover accepted",
                    inputs=inputs, change=change, outputs=[("Result", "embedded - check FAILED")])

    def _case_sizes(self, size, ctx):
        message = sess.MESSAGE_PRESETS[size]()
        res = self._protect(ctx, message)
        v = self._verify(ctx, res.stego_view)
        return dict(case="Payload size: " + size, expected=AUTHENTIC,
                    actual=self._recovered_ok(v, message),
                    detail="{:,} chars -> {:,} bytes embedded".format(len(message),
                                                                       res.stream_bytes),
                    inputs=self._inputs(ctx, message),
                    change="message replaced with the brief's '{}' preset".format(size),
                    outputs=self._outputs(ctx, res, v))

    def _case_sweep(self, n_lsb, ctx):
        message = ctx["message"]
        res = self._protect(ctx, message, n_lsb=n_lsb)
        v = self._verify(ctx, res.stego_view, n_lsb=n_lsb)
        return dict(case="LSB sweep: {} bit{}".format(n_lsb, "" if n_lsb == 1 else "s"),
                    expected=AUTHENTIC, actual=self._recovered_ok(v, message),
                    detail=self._change_detail(ctx["codec"].compare(ctx["view"], res.stego_view)),
                    inputs=self._inputs(ctx, message, n_lsb=n_lsb),
                    change="protected and verified at {} LSB{} (the input's LSB value is "
                           "overridden for this sweep)".format(n_lsb, "" if n_lsb == 1 else "s"),
                    outputs=self._outputs(ctx, res, v))
