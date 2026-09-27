"""
gui/verify_tab.py - Verify screen: extract, check the signature and hash,
show a verdict.

Covers FR8 (extraction), FR9 (hash verification), FR10 (verdict) and FR11
(positive case - AUTHENTIC is one of the two required demo cases).
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import a2_crypto as a2
from a2_crypto import Trace

from . import session as sess
from . import theme
from .session import CoverHandle, SessionState
from .widgets import (AudioPlayButton, ImagePreview, ScrollableFrame, VerdictBanner,
                      WaveformView, read_n_lsb)

MONO = theme.mono_font(10)


class VerifyTab(ttk.Frame):
    def __init__(self, master, session: SessionState):
        super().__init__(master)
        self.session = session
        self.stego: CoverHandle | None = None
        self._build()

    # ------------------------------------------------------------------ ui
    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        body = scroll.body

        src = ttk.LabelFrame(body, text="1. Stego object under test (FR8 extraction)")
        src.pack(fill="x", padx=8, pady=6)
        ttk.Button(src, text="Load stego PNG...",
                  command=lambda: self._load_file("image")).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(src, text="Load stego WAV...",
                  command=lambda: self._load_file("audio")).grid(row=0, column=1, padx=6)
        ttk.Button(src, text="Use last Protect result ->",
                  command=self.load_from_protect).grid(row=0, column=2, padx=6)
        self.src_info = tk.StringVar(value="No file loaded yet - click one of the buttons above.")
        self.src_label = tk.Label(src, textvariable=self.src_info, foreground=theme.COLORS["warn"],
                                  background=theme.COLORS["bg"], font=theme.font(11, "bold"),
                                  anchor="w")
        self.src_label.grid(row=1, column=0, columnspan=4, sticky="ew", padx=6, pady=(2, 6))
        self.play_holder = ttk.Frame(src)
        self.play_holder.grid(row=2, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 2))
        self.preview_frame = ttk.Frame(src)
        self.preview_frame.grid(row=3, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 6))

        par = ttk.LabelFrame(body, text="2. Verification parameters (must match the embed side)")
        par.pack(fill="x", padx=8, pady=6)
        self.media_id = tk.StringVar(value="IMG-0007")
        self.n_lsb = tk.IntVar(value=2)
        self.passphrase = tk.StringVar(value=sess.DEFAULT_PASSPHRASE)
        self.algo = tk.StringVar(value=a2.DEFAULT_SIGN_ALGO)
        self.pub_path = tk.StringVar(value="")
        ttk.Label(par, text="Media ID:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(par, textvariable=self.media_id, width=16).grid(row=0, column=1, sticky="w")
        ttk.Label(par, text="LSBs:").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Spinbox(par, from_=1, to=8, textvariable=self.n_lsb, width=5).grid(
            row=0, column=3, sticky="w")
        ttk.Label(par, text="Passphrase:").grid(row=0, column=4, sticky="e", padx=4)
        ttk.Entry(par, textvariable=self.passphrase, width=26, show="*").grid(
            row=0, column=5, sticky="w")
        ttk.Label(par, text="Signature algo:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        cb = ttk.Combobox(par, textvariable=self.algo, width=14, state="readonly",
                          values=list(a2.SIGNERS))
        cb.grid(row=1, column=1, sticky="w")
        cb.bind("<<ComboboxSelected>>", lambda _e: self._use_demo_key())
        ttk.Label(par, text="Public key:").grid(row=1, column=2, sticky="e", padx=4)
        ttk.Entry(par, textvariable=self.pub_path, width=40).grid(
            row=1, column=3, columnspan=2, sticky="w")
        ttk.Button(par, text="Browse...", command=self._pick_pub).grid(row=1, column=5, sticky="w")
        ttk.Button(par, text="Use demo public key for this algo",
                  command=self._use_demo_key).grid(row=2, column=0, columnspan=3,
                                                    sticky="w", padx=4, pady=(0, 4))
        self._use_demo_key()

        actions = ttk.Frame(body)
        actions.pack(pady=8)
        ttk.Button(actions, text="Verify", command=self.do_verify,
                  style="Accent.TButton").pack(side="left")
        ttk.Button(actions, text="Clear replay memory",
                  command=self._clear_replay).pack(side="left", padx=8)

        self.verdict = VerdictBanner(body)
        self.verdict.pack(fill="x", padx=8, pady=4)

        res = ttk.Frame(body)
        res.pack(fill="both", expand=True, padx=8, pady=6)
        left = ttk.LabelFrame(res, text="Checks (FR9 hash + signature)")
        left.pack(side="left", fill="both", expand=True)
        self.checks = tk.Text(left, height=16, wrap="none", font=MONO)
        self.checks.pack(fill="both", expand=True)
        right = ttk.LabelFrame(res, text="Recovered message + payload record")
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        self.recovered = tk.Text(right, height=16, wrap="word", font=MONO)
        self.recovered.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ src
    def _load_file(self, media_type: str):
        ft = [("PNG", "*.png")] if media_type == "image" else [("WAV", "*.wav")]
        path = filedialog.askopenfilename(title="Select stego object", filetypes=ft)
        if not path:
            return
        codec = self.session.codec_for(media_type)
        try:
            view = codec.load(path)
        except Exception as exc:
            messagebox.showerror("Load failed", "{}: {}".format(type(exc).__name__, exc))
            return
        self._set_stego(CoverHandle(media_type, codec, view, os.path.basename(path)))

    def load_from_protect(self):
        if self.session.last_protect_stego is None:
            messagebox.showwarning("Nothing to load", "Run Protect first.")
            return
        self._set_stego(self.session.last_protect_stego)
        params = self.session.last_protect_params
        if params:
            self.media_id.set(params["media_id"])
            self.n_lsb.set(params["n_lsb"])
            self.passphrase.set(params["passphrase"])
            self.algo.set(params["algo"])
            self._use_demo_key()

    def _set_stego(self, stego: CoverHandle):
        self.stego = stego
        # don't leave the previous file's verdict showing next to a new file
        self.verdict.clear()
        self.checks.delete("1.0", "end")
        self.recovered.delete("1.0", "end")
        for child in self.play_holder.winfo_children():
            child.destroy()
        for child in self.preview_frame.winfo_children():
            child.destroy()

        if stego.media_type == "image":
            h, w = stego.view.shape[0], stego.view.shape[1]
            detail = "{} x {} px".format(w, h)
            preview = ImagePreview(self.preview_frame, "Loaded stego (preview)", size=(180, 180))
            preview.pack(side="left")
            preview.show_array(stego.view)
        else:
            arr, params = stego.view
            duration = params.n_frames / float(params.framerate or 1)
            detail = "{:.1f}s, {} ch, {}-bit, {} Hz".format(
                duration, params.n_channels, params.sampwidth * 8, params.framerate)
            ttk.Label(self.play_holder, text="Loaded audio:").pack(side="left")
            AudioPlayButton(self.play_holder, lambda: (
                arr.tobytes(), params.n_channels, params.sampwidth, params.framerate)
                           ).pack(side="left", padx=6)
            wv = WaveformView(self.preview_frame, width=460, height=70)
            wv.pack(side="left")
            wv.draw(stego.codec.waveform(stego.view))

        self.src_info.set("Loaded: {}   ({}, {})".format(
            stego.source, stego.codec.name, detail))
        self.src_label.configure(foreground=theme.COLORS["good"])

    def _pick_pub(self):
        path = filedialog.askopenfilename(title="Public key", filetypes=[("PEM", "*.pem")])
        if path:
            self.pub_path.set(path)

    def _use_demo_key(self):
        _priv, _pub, pub_path = self.session.keys_for(self.algo.get())
        self.pub_path.set(pub_path)

    # --------------------------------------------------------------- verify
    def do_verify(self):
        if self.stego is None:
            messagebox.showwarning("No stego object", "Load a stego file first.")
            return
        n_lsb = read_n_lsb(self.n_lsb)
        if n_lsb is None:
            return
        try:
            pub = a2.load_public(self.pub_path.get())
        except a2.KeyError_ as exc:
            self.verdict.show(a2.Verdict(a2.VerdictCode.CANNOT_VERIFY, str(exc)))
            return

        tr = Trace("verify")
        v = a2.verify(self.stego.view, self.media_id.get(), n_lsb,
                     self.passphrase.get(), pub, codec=self.stego.codec,
                     bits=self.session.bits, algo=self.algo.get(), trace=tr)
        self._show(v, self.session.check_replay(v, self.stego.source))

    def _clear_replay(self):
        n = self.session.clear_replay_memory()
        messagebox.showinfo("Replay memory cleared",
                            "Forgot {} accepted payload(s). The next verification of any of "
                            "them counts as a first delivery again.".format(n))

    def _show(self, v, replay_of=None):
        self.verdict.show(v, replay_of)
        if replay_of:
            replay_line = "REPLAY - first accepted from: {}".format(replay_of)
        elif v.code is a2.VerdictCode.AUTHENTIC:
            replay_line = "first delivery of this payload (nonce remembered)"
        else:
            replay_line = "n/a (payload not accepted)"
        lines = ["source        : {}".format(self.stego.source if self.stego else "-"),
                 "meaning       : {}".format(a2.VERDICT_MEANING[v.code]),
                 "replay check  : {}".format(replay_line), ""]
        for k, val in (v.details or {}).items():
            lines.append("{:<20}: {}".format(k, val))
        if v.payload is not None:
            lines += ["", "PAYLOAD RECORD:", v.payload.pretty()]
        self.checks.delete("1.0", "end")
        self.checks.insert("1.0", "\n".join(lines))

        self.recovered.delete("1.0", "end")
        if v.message is not None:
            self.recovered.insert("1.0", v.message_text())
        else:
            self.recovered.insert("1.0", "(no message recovered - verdict was {})".format(v.code))
