"""
gui/attack_tab.py - negative-case / attack-simulation toolbar.

Takes the most recent Protect result, applies one deliberate mutation at a
time to an in-memory copy, re-verifies, and logs whether the verdict matches
what that mutation is supposed to produce. This is where the spec's "at
least three negative cases" live on demand for the live demo, and it doubles
as the optional "attack simulation module" challenge.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

import a2_crypto as a2

from . import theme
from .session import CoverHandle, SessionState
from .widgets import ScrollableFrame, VerdictBanner

EXPECTED = {
    "content": a2.VerdictCode.TAMPERED,
    "payload": a2.VerdictCode.SIGNATURE_INVALID,
    "passphrase": a2.VerdictCode.WRONG_START_LOCATION,
    "wrongkey": a2.VerdictCode.SIGNATURE_INVALID,
    "clean": a2.VerdictCode.PAYLOAD_MISSING,
    "wronglsb": a2.VerdictCode.WRONG_START_LOCATION,
    "header": a2.VerdictCode.CANNOT_VERIFY,
}


class AttackTab(ttk.Frame):
    def __init__(self, master, session: SessionState):
        super().__init__(master)
        self.session = session
        self.working_stego: CoverHandle | None = None
        self._clean_stego: CoverHandle | None = None
        self._build()

    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        body = scroll.body

        ttk.Label(body, text="Run Protect first, then load its result here and try each "
                             "attack. Every button mutates an in-memory copy of the clean "
                             "stego - the file on disk from Protect/Exchange is untouched.",
                 foreground=theme.COLORS["muted"], wraplength=1080).pack(fill="x", padx=8, pady=(8, 4))

        top = ttk.Frame(body)
        top.pack(fill="x", padx=8, pady=4)
        ttk.Button(top, text="Load last Protect result", command=self.load_source).pack(
            side="left")
        self.src_info = tk.StringVar(value="(nothing loaded - run Protect first)")
        ttk.Label(top, textvariable=self.src_info, foreground=theme.COLORS["muted"]).pack(
            side="left", padx=10)

        par = ttk.LabelFrame(body, text="Verification parameters used for every attack below")
        par.pack(fill="x", padx=8, pady=6)
        self.media_id = tk.StringVar(value="-")
        self.n_lsb = tk.IntVar(value=2)
        self.passphrase = tk.StringVar(value="-")
        self.algo = tk.StringVar(value=a2.DEFAULT_SIGN_ALGO)
        self.pub_path = tk.StringVar(value="")
        ttk.Label(par, text="Media ID:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Label(par, textvariable=self.media_id).grid(row=0, column=1, sticky="w")
        ttk.Label(par, text="LSBs:").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Label(par, textvariable=self.n_lsb).grid(row=0, column=3, sticky="w")
        ttk.Label(par, text="Public key in use:").grid(row=1, column=0, sticky="e", padx=4)
        ttk.Label(par, textvariable=self.pub_path, foreground=theme.COLORS["muted"]).grid(
            row=1, column=1, columnspan=3, sticky="w")

        tam = ttk.LabelFrame(body, text="Attack toolbar")
        tam.pack(fill="x", padx=8, pady=6)
        # Two separate widgets per cell (button + caption label) rather than a
        # single button with an embedded "\n" - ttk buttons on some themes
        # (notably macOS Aqua) don't grow to fit a second line, so the text
        # overflows the button's fixed-height chrome instead of wrapping.
        buttons = [
            ("Flip content bit", "-> Tampered", self.t_content),
            ("Flip payload bit", "-> Signature Invalid", self.t_payload),
            ("Wrong passphrase", "-> Wrong Start Location", self.t_passphrase),
            ("Wrong public key", "-> Signature Invalid", self.t_wrongkey),
            ("Use clean cover", "-> Payload Missing", self.t_clean),
            ("Wrong n_lsb", "-> Wrong Start Location", self.t_wronglsb),
            ("Corrupt header", "-> Cannot Verify", self.t_header),
            ("Reset to clean stego", "", self.t_reset),
        ]
        for i, (label, caption, cmd) in enumerate(buttons):
            cell = ttk.Frame(tam)
            cell.grid(row=i // 4, column=i % 4, padx=4, pady=4, sticky="ew")
            ttk.Button(cell, text=label, command=cmd).pack(fill="x")
            ttk.Label(cell, text=caption, foreground=theme.COLORS["muted"], anchor="center",
                     font=theme.font(9), justify="center").pack(fill="x")
        for c in range(4):
            tam.columnconfigure(c, weight=1)

        self.verdict = VerdictBanner(body)
        self.verdict.pack(fill="x", padx=8, pady=4)

        log_frame = ttk.LabelFrame(body, text="Evidence log (screenshot this for the submission)")
        log_frame.pack(fill="both", expand=True, padx=8, pady=6)
        cols = ("attack", "expected verdict", "actual verdict", "match")
        self.log = ttk.Treeview(log_frame, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (260, 180, 180, 60)):
            self.log.heading(c, text=c)
            self.log.column(c, width=w, anchor="w")
        self.log.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ src
    def load_source(self):
        if self.session.last_protect is None or self.session.last_protect_stego is None:
            messagebox.showwarning("Nothing protected yet",
                                   "Go to the Protect tab and protect a cover first.")
            return
        self._clean_stego = self.session.last_protect_stego
        self.working_stego = self._clean_stego
        params = self.session.last_protect_params
        self.media_id.set(params["media_id"])
        self.n_lsb.set(params["n_lsb"])
        self.passphrase.set(params["passphrase"])
        self.algo.set(params["algo"])
        _priv, _pub, pub_path = self.session.keys_for(self.algo.get())
        self.pub_path.set(pub_path)
        self.src_info.set("attacking: {}".format(self._clean_stego.source))
        self.log.delete(*self.log.get_children())

    def _reset_only(self):
        if self._clean_stego is None:
            return False
        self.working_stego = self._clean_stego
        self.src_info.set("clean stego from last Protect: {}".format(self._clean_stego.source))
        return True

    # -------------------------------------------------------------- attacks
    def _mutate(self, fn, note: str, key: str):
        if self._clean_stego is None:
            messagebox.showwarning("Nothing loaded", "Load the last Protect result first.")
            return
        codec = self._clean_stego.codec
        sam = bytearray(codec.read_samples(self._clean_stego.view))
        fn(sam)
        new_view = codec.write_samples(self._clean_stego.view, bytes(sam))
        self.working_stego = CoverHandle(self._clean_stego.media_type, codec,
                                         new_view, "tampered: " + note)
        self.src_info.set(self.working_stego.source)
        self._run_verify(key, note)

    def t_content(self):
        if self.session.last_protect is None:
            return
        start = self.session.last_protect.start_unit

        def fn(sam):
            i = (start + len(sam) // 3) % len(sam)
            sam[i] ^= 0x80
        self._mutate(fn, "flipped one high-order content bit", "content")

    def t_payload(self):
        if self.session.last_protect is None:
            return
        start = self.session.last_protect.start_unit

        def fn(sam):
            sam[start + 200] ^= 0x01
        self._mutate(fn, "flipped one bit inside the embedded payload", "payload")

    def t_header(self):
        if self.session.last_protect is None:
            return
        start = self.session.last_protect.start_unit
        n = self.session.last_protect.n_lsb

        def fn(sam):
            for i in range(9 * 8 // n, 13 * 8 // n):
                sam[start + i] |= (1 << n) - 1
        self._mutate(fn, "corrupted the header length fields", "header")

    def t_passphrase(self):
        if not self._reset_only():
            return
        self.passphrase.set("definitely-the-wrong-passphrase")
        self._run_verify("passphrase", "wrong passphrase supplied to Verify")

    def t_wrongkey(self):
        if not self._reset_only():
            return
        self.pub_path.set(self.session.impostor_public_path(self.algo.get()))
        self._run_verify("wrongkey", "impostor public key supplied to Verify")

    def t_wronglsb(self):
        if not self._reset_only():
            return
        cur = int(self.n_lsb.get())
        self.n_lsb.set(cur + 1 if cur < 8 else 1)
        self._run_verify("wronglsb", "LSB count changed to {}".format(self.n_lsb.get()))

    def t_clean(self):
        cover = self.session.last_protect_cover
        if cover is None:
            return
        self.working_stego = cover
        self.src_info.set("original clean cover (no payload embedded)")
        self._run_verify("clean", "used the clean cover, no payload embedded")

    def t_reset(self):
        self._reset_only()
        self.n_lsb.set(self.session.last_protect_params["n_lsb"])
        self.passphrase.set(self.session.last_protect_params["passphrase"])
        _priv, _pub, pub_path = self.session.keys_for(self.algo.get())
        self.pub_path.set(pub_path)

    # -------------------------------------------------------------- verify
    def _run_verify(self, key: str, note: str):
        if self.working_stego is None:
            return
        try:
            pub = a2.load_public(self.pub_path.get())
        except a2.KeyError_ as exc:
            v = a2.Verdict(a2.VerdictCode.CANNOT_VERIFY, str(exc))
        else:
            v = a2.verify(self.working_stego.view, self.media_id.get(), int(self.n_lsb.get()),
                         self.passphrase.get(), pub, codec=self.working_stego.codec,
                         bits=self.session.bits, algo=self.algo.get())
        self.verdict.show(v)
        expected = EXPECTED.get(key)
        match = "yes" if (expected is None or v.code == expected) else "no"
        self.log.insert("", "end", values=(note, str(expected) if expected else "-",
                                           str(v.code), match))
