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

import numpy as np

import a2_crypto as a2

from . import theme
from .session import CoverHandle, SessionState
from .widgets import ScrollableFrame, VerdictBanner

REPLAY_FLAG = " + replay flagged"

EXPECTED = {
    "content": str(a2.VerdictCode.TAMPERED),
    "payload": str(a2.VerdictCode.SIGNATURE_INVALID),
    "passphrase": str(a2.VerdictCode.WRONG_START_LOCATION),
    "wrongkey": str(a2.VerdictCode.SIGNATURE_INVALID),
    "clean": str(a2.VerdictCode.PAYLOAD_MISSING),
    "wronglsb": str(a2.VerdictCode.WRONG_START_LOCATION),
    "header": str(a2.VerdictCode.CANNOT_VERIFY),
    # the signature is still valid, but the cover it's bound to is not this one
    "substitute": str(a2.VerdictCode.TAMPERED),
    # cryptographically genuine, so a2.verify() says Authentic; the GUI's
    # nonce memory (SessionState.check_replay) is what catches it
    "replay": str(a2.VerdictCode.AUTHENTIC) + REPLAY_FLAG,
}


class AttackTab(ttk.Frame):
    def __init__(self, master, session: SessionState):
        super().__init__(master)
        self.session = session
        self.working_stego: CoverHandle | None = None
        # snapshot of the Protect result being attacked, so protecting
        # something new mid-session can't mix two results' parameters
        self._clean_stego: CoverHandle | None = None
        self._clean_cover: CoverHandle | None = None
        self._clean_result = None
        self._clean_params: dict | None = None
        self._build()

    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        body = scroll.body

        ttk.Label(body, text="Run Protect first, then load its result here and try each "
                             "attack. Every button mutates an in-memory copy of the clean "
                             "stego - the file saved from Protect is untouched.",
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
            ("Substitute into other cover", "-> Tampered", self.t_substitute),
            ("Replay (resend same file)", "-> Authentic + replay flagged", self.t_replay),
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

        actions = ttk.Frame(body)
        actions.pack(fill="x", padx=8, pady=4)
        ttk.Button(actions, text="Clear log", command=self._clear_log).pack(side="left")

        self.verdict = VerdictBanner(body)
        self.verdict.pack(fill="x", padx=8, pady=4)

        log_frame = ttk.LabelFrame(body, text="Evidence log (screenshot this for the submission)")
        log_frame.pack(fill="both", expand=True, padx=8, pady=6)
        cols = ("attack", "expected verdict", "actual verdict", "match")
        self.log = ttk.Treeview(log_frame, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (320, 220, 220, 60)):
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
        self._clean_cover = self.session.last_protect_cover
        self._clean_result = self.session.last_protect
        self._clean_params = dict(self.session.last_protect_params)
        self.media_id.set(self._clean_params["media_id"])
        self.algo.set(self._clean_params["algo"])
        self._restore()
        self.src_info.set("attacking: {}".format(self._clean_stego.source))
        self.log.delete(*self.log.get_children())
        self.verdict.clear()

    def _restore(self) -> bool:
        """Back to the clean stego AND the original verification parameters.
        Every attack starts here, so one attack's wrong passphrase / key / LSB
        count can't leak into the next attack and skew its verdict."""
        if self._clean_stego is None:
            messagebox.showwarning("Nothing loaded", "Load the last Protect result first.")
            return False
        self.working_stego = self._clean_stego
        self.n_lsb.set(self._clean_params["n_lsb"])
        self.passphrase.set(self._clean_params["passphrase"])
        _priv, _pub, pub_path = self.session.keys_for(self.algo.get())
        self.pub_path.set(pub_path)
        self.src_info.set("clean stego from last Protect: {}".format(self._clean_stego.source))
        return True

    # -------------------------------------------------------------- attacks
    def _mutate(self, fn, note: str, key: str):
        codec = self._clean_stego.codec
        sam = bytearray(codec.read_samples(self._clean_stego.view))
        fn(sam)
        new_view = codec.write_samples(self._clean_stego.view, bytes(sam))
        self.working_stego = CoverHandle(self._clean_stego.media_type, codec,
                                         new_view, "tampered: " + note)
        self.src_info.set(self.working_stego.source)
        self._run_verify(key, note)

    def t_content(self):
        if not self._restore():
            return
        start = self._clean_result.start_unit

        def fn(sam):
            i = (start + len(sam) // 3) % len(sam)
            sam[i] ^= 0x80
        self._mutate(fn, "flipped one high-order content bit", "content")

    def t_payload(self):
        if not self._restore():
            return
        start = self._clean_result.start_unit

        def fn(sam):
            sam[start + 200] ^= 0x01
        self._mutate(fn, "flipped one bit inside the embedded payload", "payload")

    def t_header(self):
        if not self._restore():
            return
        start = self._clean_result.start_unit
        n = self._clean_result.n_lsb

        def fn(sam):
            for i in range(9 * 8 // n, 13 * 8 // n):
                sam[start + i] |= (1 << n) - 1
        self._mutate(fn, "corrupted the header length fields", "header")

    def t_passphrase(self):
        if not self._restore():
            return
        self.passphrase.set("definitely-the-wrong-passphrase")
        self._run_verify("passphrase", "wrong passphrase supplied to Verify")

    def t_wrongkey(self):
        if not self._restore():
            return
        self.pub_path.set(self.session.impostor_public_path(self.algo.get()))
        self._run_verify("wrongkey", "impostor public key supplied to Verify")

    def t_wronglsb(self):
        if not self._restore():
            return
        cur = int(self.n_lsb.get())
        self.n_lsb.set(cur + 1 if cur < 8 else 1)
        self._run_verify("wronglsb", "LSB count changed to {}".format(self.n_lsb.get()))

    def t_clean(self):
        if not self._restore():
            return
        self.working_stego = self._clean_cover
        self.src_info.set("original clean cover (no payload embedded)")
        self._run_verify("clean", "used the clean cover, no payload embedded")

    def t_substitute(self):
        """Lift the whole embedded LSB plane (payload included) out of this
        stego and plant it into a different cover of the same size. The
        stand-in "different cover" is the original cover reversed - same
        size, so the keyed start location still lines up, but different
        content. The signature over the payload is still perfectly valid; it
        fails because the payload's signed cover hash belongs to the old
        cover. (At n_lsb = 8 there are no content bits left to compare, so
        this can't be detected - same limit as content tampering.)"""
        if not self._restore():
            return
        cover = self._clean_cover
        other = np.frombuffer(bytes(cover.codec.read_samples(cover.view)), np.uint8)[::-1]
        low = np.uint8((1 << int(self.n_lsb.get())) - 1)
        high = np.uint8(0xFF) ^ low

        def fn(sam):
            planted = (other & high) | (np.frombuffer(bytes(sam), np.uint8) & low)
            sam[:] = planted.tobytes()
        self._mutate(fn, "signed payload lifted out and planted into a different cover",
                     "substitute")

    def t_replay(self):
        """Deliver the same untouched stego twice. The first delivery is
        accepted (unless this payload was already accepted earlier this
        session - which is itself a replay); the second must be flagged."""
        if not self._restore():
            return
        self.src_info.set("resending the clean stego a second time")
        self.session.check_replay(self._verify(), self.working_stego.source)
        self._run_verify("replay", "resent a stego that was already accepted once")

    def t_reset(self):
        self._restore()

    def _clear_log(self):
        self.log.delete(*self.log.get_children())
        self.verdict.clear()

    # -------------------------------------------------------------- verify
    def _verify(self):
        try:
            pub = a2.load_public(self.pub_path.get())
        except a2.KeyError_ as exc:
            return a2.Verdict(a2.VerdictCode.CANNOT_VERIFY, str(exc))
        return a2.verify(self.working_stego.view, self.media_id.get(), int(self.n_lsb.get()),
                         self.passphrase.get(), pub, codec=self.working_stego.codec,
                         bits=self.session.bits, algo=self.algo.get())

    def _run_verify(self, key: str, note: str):
        v = self._verify()
        replay_of = self.session.check_replay(v, self.working_stego.source)
        self.verdict.show(v, replay_of)
        actual = str(v.code) + (REPLAY_FLAG if replay_of else "")
        expected = EXPECTED[key]
        self.log.insert("", "end", values=(note, expected, actual,
                                           "yes" if actual == expected else "no"))
