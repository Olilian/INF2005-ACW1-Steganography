"""
a2_debug_gui.py - standalone Tkinter test bench for the A2 crypto layer.

    python a2_debug_gui.py

This is NOT the production GUI. Person 5's application calls the same
protect() and verify() functions; this window exists so the A2 layer can be
driven, broken on purpose and inspected without waiting for anyone else, and
it is what person 2 demonstrates during their individual air time.

It imports a2_crypto, and a2_integration only when a real PNG or WAV is
loaded, so it still runs with nothing but stdlib plus `cryptography` present.

THREE TABS
    Protect  build and embed a payload, with a live capacity check
    Verify   extract and judge, with a tamper toolbar that triggers every
             verdict code on demand
    Trace    every pipeline step, its detail dict and a hex dump of its blob
"""
from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import a2_crypto as a2
from a2_crypto import MemoryCodec, ReferenceBitstream, Trace, VerdictCode, hexdump

HERE = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(HERE, "a2_crypto", "testdata")
KEYS_DIR = os.path.join(HERE, "keys")
OUT_DIR = os.path.join(HERE, "a2_out")

MONO = ("Consolas", 9)
BOLD = ("Segoe UI", 10, "bold")


def _read(name: str) -> str:
    try:
        with open(os.path.join(TESTDATA, name), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


class A2DebugGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("A2 Crypto & Verdict - debug bench (INF2005 ACW1)")
        self.geometry("1180x820")

        # -- shared state ---------------------------------------------------
        self.bits = ReferenceBitstream()
        self.mock_codec = MemoryCodec(seed=42)
        self.codec = self.mock_codec          # swapped when a real file loads
        self.cover_view = None                # what protect() embeds into
        self.stego_view = None                # what verify() reads
        self.stego_source = "(nothing loaded)"
        self.last_protect = None
        self.traces: dict[str, Trace] = {}
        self.priv = None
        self.pub = None

        self._build_widgets()
        self._ensure_keys()
        self._new_mock_cover()
        self._update_capacity()

    # =====================================================================
    # layout
    # =====================================================================
    def _build_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_protect = ttk.Frame(nb)
        self.tab_verify = ttk.Frame(nb)
        self.tab_trace = ttk.Frame(nb)
        nb.add(self.tab_protect, text="  1. Protect  ")
        nb.add(self.tab_verify, text="  2. Verify  ")
        nb.add(self.tab_trace, text="  3. Trace  ")
        self.nb = nb

        self.status = tk.StringVar(value="ready")
        ttk.Label(self, textvariable=self.status, relief="sunken",
                  anchor="w").pack(fill="x", side="bottom")

        self._build_protect_tab()
        self._build_verify_tab()
        self._build_trace_tab()

    # ---------------------------------------------------------------- protect
    def _build_protect_tab(self):
        f = self.tab_protect

        # cover source
        cov = ttk.LabelFrame(f, text="Cover object")
        cov.pack(fill="x", padx=8, pady=6)
        self.cover_kind = tk.StringVar(value="mock")
        ttk.Radiobutton(cov, text="Mock cover", variable=self.cover_kind,
                        value="mock", command=self._new_mock_cover).grid(
                            row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Label(cov, text="units:").grid(row=0, column=1, sticky="e")
        self.mock_size = tk.IntVar(value=200_000)
        e = ttk.Entry(cov, textvariable=self.mock_size, width=10)
        e.grid(row=0, column=2, sticky="w", padx=4)
        e.bind("<FocusOut>", lambda _e: self._new_mock_cover())
        e.bind("<Return>", lambda _e: self._new_mock_cover())
        ttk.Button(cov, text="Regenerate", command=self._new_mock_cover).grid(
            row=0, column=3, padx=4)
        ttk.Button(cov, text="Load PNG...",
                   command=lambda: self._load_real("image")).grid(row=0, column=4, padx=4)
        ttk.Button(cov, text="Load WAV...",
                   command=lambda: self._load_real("audio")).grid(row=0, column=5, padx=4)
        self.cover_info = tk.StringVar(value="-")
        ttk.Label(cov, textvariable=self.cover_info, foreground="#444").grid(
            row=1, column=0, columnspan=6, sticky="w", padx=6, pady=(0, 6))

        # message source
        msg = ttk.LabelFrame(f, text="Hidden message (payload content)")
        msg.pack(fill="both", padx=8, pady=6)
        self.msg_kind = tk.StringVar(value="short")
        for i, (val, label) in enumerate([
            ("short", "Short - one Learning Outcome"),
            ("large", "Large - Project Overview paragraph"),
            ("custom", "Custom - team JSON record"),
            ("free", "Free text below"),
        ]):
            ttk.Radiobutton(msg, text=label, variable=self.msg_kind, value=val,
                            command=self._on_message_change).grid(
                                row=0, column=i, sticky="w", padx=6, pady=4)
        self.msg_text = tk.Text(msg, height=6, wrap="word", font=MONO)
        self.msg_text.grid(row=1, column=0, columnspan=4, sticky="ew", padx=6, pady=4)
        self.msg_text.bind("<KeyRelease>", lambda _e: self._update_capacity())
        msg.columnconfigure(3, weight=1)

        # controls
        ctl = ttk.LabelFrame(f, text="Embedding parameters")
        ctl.pack(fill="x", padx=8, pady=6)
        self.n_lsb = tk.IntVar(value=2)
        self.media_id = tk.StringVar(value="IMG-0007")
        self.passphrase = tk.StringVar(value="team-P1-4-shared-passphrase")
        self.encrypt = tk.BooleanVar(value=True)
        self.algo = tk.StringVar(value=a2.DEFAULT_SIGN_ALGO)

        ttk.Label(ctl, text="LSBs (1-8):").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        sp = ttk.Spinbox(ctl, from_=1, to=8, textvariable=self.n_lsb, width=5,
                         command=self._update_capacity)
        sp.grid(row=0, column=1, sticky="w")
        sp.bind("<KeyRelease>", lambda _e: self._update_capacity())
        ttk.Label(ctl, text="Media ID:").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Entry(ctl, textvariable=self.media_id, width=16).grid(row=0, column=3, sticky="w")
        ttk.Label(ctl, text="Passphrase:").grid(row=0, column=4, sticky="e", padx=4)
        ttk.Entry(ctl, textvariable=self.passphrase, width=30).grid(row=0, column=5, sticky="w")
        ttk.Checkbutton(ctl, text="Encrypt message (AES-256-GCM)",
                        variable=self.encrypt,
                        command=self._update_capacity).grid(row=1, column=0, columnspan=2,
                                                            sticky="w", padx=4)
        ttk.Label(ctl, text="Signature:").grid(row=1, column=2, sticky="e", padx=4)
        cb = ttk.Combobox(ctl, textvariable=self.algo, width=14, state="readonly",
                          values=list(a2.SIGNERS))
        cb.grid(row=1, column=3, sticky="w")
        cb.bind("<<ComboboxSelected>>", lambda _e: self._on_algo_change())

        # capacity bar
        cap = ttk.LabelFrame(f, text="Capacity check (cover vs payload)")
        cap.pack(fill="x", padx=8, pady=6)
        self.cap_bar = ttk.Progressbar(cap, maximum=100, length=520)
        self.cap_bar.pack(side="left", padx=8, pady=8)
        self.cap_text = tk.StringVar(value="-")
        self.cap_label = ttk.Label(cap, textvariable=self.cap_text, font=BOLD)
        self.cap_label.pack(side="left", padx=8)

        # action
        act = ttk.Frame(f)
        act.pack(fill="x", padx=8, pady=4)
        ttk.Button(act, text="Protect  ->  embed payload",
                   command=self.do_protect).pack(side="left")
        ttk.Button(act, text="Save stego to file...",
                   command=self.save_stego).pack(side="left", padx=6)
        ttk.Button(act, text="Send stego to Verify tab",
                   command=self.push_to_verify).pack(side="left", padx=6)

        self.protect_out = tk.Text(f, height=13, wrap="word", font=MONO)
        self.protect_out.pack(fill="both", expand=True, padx=8, pady=6)

        self._on_message_change()

    # ----------------------------------------------------------------- verify
    def _build_verify_tab(self):
        f = self.tab_verify

        src = ttk.LabelFrame(f, text="Stego object under test")
        src.pack(fill="x", padx=8, pady=6)
        self.verify_src = tk.StringVar(value="(nothing loaded)")
        ttk.Label(src, textvariable=self.verify_src, foreground="#444").grid(
            row=0, column=0, columnspan=4, sticky="w", padx=6, pady=4)
        ttk.Button(src, text="Load stego PNG...",
                   command=lambda: self._load_stego("image")).grid(row=1, column=0, padx=6, pady=4)
        ttk.Button(src, text="Load stego WAV...",
                   command=lambda: self._load_stego("audio")).grid(row=1, column=1, padx=6)
        ttk.Button(src, text="Load raw mock file...",
                   command=lambda: self._load_stego("mock")).grid(row=1, column=2, padx=6)

        par = ttk.LabelFrame(f, text="Verification parameters (must match the embed side)")
        par.pack(fill="x", padx=8, pady=6)
        self.v_media_id = tk.StringVar(value="IMG-0007")
        self.v_n_lsb = tk.IntVar(value=2)
        self.v_pass = tk.StringVar(value="team-P1-4-shared-passphrase")
        self.v_pub = tk.StringVar(value=os.path.join(KEYS_DIR, "demo_public.pem"))
        ttk.Label(par, text="Media ID:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(par, textvariable=self.v_media_id, width=16).grid(row=0, column=1, sticky="w")
        ttk.Label(par, text="LSBs:").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Spinbox(par, from_=1, to=8, textvariable=self.v_n_lsb, width=5).grid(
            row=0, column=3, sticky="w")
        ttk.Label(par, text="Passphrase:").grid(row=0, column=4, sticky="e", padx=4)
        ttk.Entry(par, textvariable=self.v_pass, width=30).grid(row=0, column=5, sticky="w")
        ttk.Label(par, text="Public key:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(par, textvariable=self.v_pub, width=58).grid(
            row=1, column=1, columnspan=4, sticky="w")
        ttk.Button(par, text="Browse...", command=self._pick_pub).grid(row=1, column=5, sticky="w")

        # tamper toolbar
        tam = ttk.LabelFrame(f, text="Tamper toolbar - trigger each verdict on demand "
                                     "(acts on the in-memory stego copy)")
        tam.pack(fill="x", padx=8, pady=6)
        buttons = [
            ("Flip content bit\n-> Tampered", self.t_content),
            ("Flip payload bit\n-> Signature Invalid", self.t_payload),
            ("Wrong passphrase\n-> Wrong Start Location", self.t_passphrase),
            ("Wrong public key\n-> Signature Invalid", self.t_wrongkey),
            ("Use clean cover\n-> Payload Missing", self.t_clean),
            ("Wrong n_lsb\n-> Wrong Start Location", self.t_wronglsb),
            ("Corrupt header\n-> Cannot Verify", self.t_header),
            ("Reset to clean stego", self.t_reset),
        ]
        for i, (label, cmd) in enumerate(buttons):
            ttk.Button(tam, text=label, command=cmd, width=26).grid(
                row=i // 4, column=i % 4, padx=4, pady=4, sticky="ew")
        for c in range(4):
            tam.columnconfigure(c, weight=1)

        ttk.Button(f, text="Verify", command=self.do_verify).pack(pady=4)

        # verdict banner
        self.banner = tk.Label(f, text="no verdict yet", font=("Segoe UI", 16, "bold"),
                               bg="#dddddd", fg="#222", height=2)
        self.banner.pack(fill="x", padx=8, pady=4)
        self.reason = tk.Label(f, text="", wraplength=1100, justify="left", fg="#333")
        self.reason.pack(fill="x", padx=10)

        res = ttk.Frame(f)
        res.pack(fill="both", expand=True, padx=8, pady=6)
        left = ttk.LabelFrame(res, text="Checks")
        left.pack(side="left", fill="both", expand=True)
        self.checks = tk.Text(left, height=14, wrap="none", font=MONO)
        self.checks.pack(fill="both", expand=True)
        right = ttk.LabelFrame(res, text="Recovered message")
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        self.recovered = tk.Text(right, height=14, wrap="word", font=MONO)
        self.recovered.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ trace
    def _build_trace_tab(self):
        f = self.tab_trace
        top = ttk.Frame(f)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="Trace:").pack(side="left")
        self.trace_pick = tk.StringVar(value="")
        self.trace_combo = ttk.Combobox(top, textvariable=self.trace_pick, width=24,
                                        state="readonly", values=[])
        self.trace_combo.pack(side="left", padx=6)
        self.trace_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_trace())
        ttk.Button(top, text="Copy trace", command=self.copy_trace).pack(side="left", padx=4)
        ttk.Button(top, text="Export trace.json...", command=self.export_trace).pack(
            side="left", padx=4)
        ttk.Button(top, text="Run selftest (18 cases)",
                   command=self.run_selftest).pack(side="left", padx=16)

        body = ttk.Frame(f)
        body.pack(fill="both", expand=True, padx=8, pady=6)
        cols = ("stage", "label", "ms", "ok")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (130, 520, 70, 50)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_step())

        det = ttk.LabelFrame(f, text="Selected step - detail and blob hex dump")
        det.pack(fill="both", expand=True, padx=8, pady=6)
        self.step_out = tk.Text(det, height=14, wrap="none", font=MONO)
        self.step_out.pack(fill="both", expand=True)

    # =====================================================================
    # cover / key handling
    # =====================================================================
    def _ensure_keys(self):
        priv_path = os.path.join(KEYS_DIR, "demo_private.pem")
        pub_path = os.path.join(KEYS_DIR, "demo_public.pem")
        if not os.path.exists(priv_path):
            kb = a2.generate_keypair(self.algo.get())
            a2.save_keypair(kb, priv_path, pub_path)
        try:
            self.priv = a2.load_private(priv_path)
            self.pub = a2.load_public(pub_path)
        except a2.KeyError_ as exc:
            messagebox.showerror("Key error", str(exc))

    def _on_algo_change(self):
        """Each scheme needs its own keypair - regenerate and reload."""
        algo = self.algo.get()
        priv_path = os.path.join(KEYS_DIR, "demo_private_{}.pem".format(algo))
        pub_path = os.path.join(KEYS_DIR, "demo_public_{}.pem".format(algo))
        if not os.path.exists(priv_path):
            self.status.set("generating {} keypair...".format(algo))
            self.update_idletasks()
            a2.save_keypair(a2.generate_keypair(algo), priv_path, pub_path)
        self.priv = a2.load_private(priv_path)
        self.pub = a2.load_public(pub_path)
        self.v_pub.set(pub_path)
        self.status.set("signature scheme: {} ({} byte signature)".format(
            algo, a2.signature_len(algo)))
        self._update_capacity()

    def _new_mock_cover(self):
        self.cover_kind.set("mock")
        self.codec = self.mock_codec
        try:
            n = max(64, int(self.mock_size.get()))
        except Exception:
            n = 200_000
        self.cover_view = self.mock_codec.make_cover(n, seed=42)
        self.cover_info.set("mock cover: {:,} units of pseudo-random bytes".format(n))
        self._update_capacity()

    def _load_real(self, kind: str):
        path = filedialog.askopenfilename(
            title="Select cover",
            filetypes=[("PNG", "*.png")] if kind == "image" else [("WAV", "*.wav")])
        if not path:
            return
        try:
            import a2_integration as integ
            self.codec = (integ.ImageCodecAdapter() if kind == "image"
                          else integ.AudioCodecAdapter())
            self.cover_view = self.codec.load(path)
            self.cover_kind.set(kind)
            units = len(self.codec.read_samples(self.cover_view))
            self.cover_info.set("{}: {}  ({:,} units)".format(
                self.codec.name, os.path.basename(path), units))
            self.media_id.set(("IMG-" if kind == "image" else "AUD-") + "0007")
            self.v_media_id.set(self.media_id.get())
        except Exception as exc:
            messagebox.showerror("Load failed", "{}: {}".format(type(exc).__name__, exc))
            return
        self._update_capacity()

    def _load_stego(self, kind: str):
        ft = {"image": [("PNG", "*.png")], "audio": [("WAV", "*.wav")],
              "mock": [("All files", "*.*")]}[kind]
        path = filedialog.askopenfilename(title="Select stego object", filetypes=ft)
        if not path:
            return
        try:
            if kind == "mock":
                self.codec = self.mock_codec
            else:
                import a2_integration as integ
                self.codec = (integ.ImageCodecAdapter() if kind == "image"
                              else integ.AudioCodecAdapter())
            self.stego_view = self.codec.load(path)
            self._clean_stego = self.stego_view
            self.stego_source = os.path.basename(path)
            self.verify_src.set("{}  via {}".format(path, getattr(self.codec, "name", "MemoryCodec")))
        except Exception as exc:
            messagebox.showerror("Load failed", "{}: {}".format(type(exc).__name__, exc))

    def _pick_pub(self):
        path = filedialog.askopenfilename(title="Public key",
                                          filetypes=[("PEM", "*.pem")])
        if path:
            self.v_pub.set(path)

    # =====================================================================
    # message + capacity
    # =====================================================================
    def _on_message_change(self):
        kind = self.msg_kind.get()
        if kind != "free":
            text = {"short": _read("payload_short.txt"),
                    "large": _read("payload_large.txt"),
                    "custom": _read("payload_custom.json")}[kind]
            self.msg_text.delete("1.0", "end")
            self.msg_text.insert("1.0", text)
        self._update_capacity()

    def _message(self) -> str:
        return self.msg_text.get("1.0", "end-1c")

    def _update_capacity(self):
        if self.cover_view is None:
            return
        try:
            n_lsb = int(self.n_lsb.get())
            if not (1 <= n_lsb <= 8):
                raise ValueError
        except Exception:
            self.cap_text.set("n_lsb must be 1-8")
            return
        try:
            rep = a2.capacity_report(self.codec, self.cover_view, n_lsb,
                                     self._message(), self.algo.get(),
                                     self.encrypt.get())
        except Exception as exc:
            self.cap_text.set(str(exc))
            return
        pct = rep["utilisation_percent"]
        self.cap_bar["value"] = min(pct, 100)
        mark = "OK" if rep["fits"] else "TOO BIG"
        self.cap_text.set(
            "need {:,} bits / {:,} usable ({}%)   [{}]".format(
                rep["needed_bits"], rep["usable_bits"], pct, mark))
        self.cap_label.configure(foreground="#1b7f3a" if rep["fits"] else "#b3261e")
        self.status.set(
            "raw capacity {:,} bits at {} LSB; usable {:,} after the keyed "
            "placement window reserves its tail".format(
                rep["capacity_bits"], n_lsb, rep["usable_bits"]))

    # =====================================================================
    # actions
    # =====================================================================
    def do_protect(self):
        if self.cover_view is None:
            messagebox.showwarning("No cover", "Load or generate a cover first.")
            return
        tr = Trace("protect")
        try:
            res = a2.protect(
                self.cover_view, self._message(), self.media_id.get(),
                int(self.n_lsb.get()), self.passphrase.get(), self.priv,
                codec=self.codec, bits=self.bits,
                media_type=getattr(self.codec, "media_type", "image"),
                algo=self.algo.get(), encrypt=self.encrypt.get(), trace=tr)
        except a2.CapacityError as exc:
            self._register_trace("protect", tr)
            self.protect_out.delete("1.0", "end")
            self.protect_out.insert("1.0",
                "BLOCKED - capacity check failed\n\n{}\n\n"
                "This is the required negative case: the payload is larger than "
                "the cover can carry at this LSB depth. Raise the LSB count, use "
                "a larger cover, or shorten the message.".format(exc))
            self.status.set("protect blocked: payload exceeds capacity")
            return
        except Exception as exc:
            messagebox.showerror("Protect failed", "{}: {}".format(type(exc).__name__, exc))
            return

        self.last_protect = res
        self.stego_view = res.stego_view
        self._clean_stego = res.stego_view
        self.stego_source = "in-memory stego from Protect tab"
        self.verify_src.set(self.stego_source)
        self._register_trace("protect", tr)

        # Note: the payload JSON contains braces, so each line is formatted on
        # its own - never run .format() over a string that already holds JSON.
        summary = [
            "PROTECTED",
            "  signature algorithm : {} ({} bytes)".format(res.algo, len(res.signature)),
            "  derived start unit  : {:,}   <- not stored anywhere in the file".format(
                res.start_unit),
            "  embedded stream     : {:,} bytes ({:,} bits)".format(
                res.stream_bytes, res.needed_bits),
            "  cover bytes changed : {:,}".format(res.details["changed_bytes"]),
            "  stable cover digest : {}".format(res.details["digest_hex"]),
            "",
            "PAYLOAD RECORD (this is what gets signed, in canonical form):",
            res.payload.pretty(),
            "",
            "SIGNATURE (hex): " + res.signature.hex(),
        ]
        self.protect_out.delete("1.0", "end")
        self.protect_out.insert("1.0", "\n".join(summary))

        # keep the verify tab in step
        self.v_media_id.set(self.media_id.get())
        self.v_n_lsb.set(int(self.n_lsb.get()))
        self.v_pass.set(self.passphrase.get())
        self.status.set("protected - offset {:,}, {} bytes embedded".format(
            res.start_unit, res.stream_bytes))

    def save_stego(self):
        if self.stego_view is None:
            messagebox.showwarning("Nothing to save", "Run Protect first.")
            return
        ext = {"image": ".png", "audio": ".wav"}.get(
            getattr(self.codec, "media_type", "memory"), ".bin")
        os.makedirs(OUT_DIR, exist_ok=True)
        path = filedialog.asksaveasfilename(
            initialdir=OUT_DIR, defaultextension=ext,
            initialfile="stego" + ext)
        if not path:
            return
        try:
            self.codec.save(self.stego_view, path)
            self.status.set("saved " + path)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def push_to_verify(self):
        if self.stego_view is None:
            messagebox.showwarning("Nothing to send", "Run Protect first.")
            return
        self.nb.select(self.tab_verify)

    def do_verify(self):
        if self.stego_view is None:
            messagebox.showwarning("No stego object", "Protect something or load a file.")
            return
        try:
            pub = a2.load_public(self.v_pub.get())
        except a2.KeyError_ as exc:
            self._show_verdict(a2.Verdict(VerdictCode.CANNOT_VERIFY, str(exc)))
            return

        tr = Trace("verify")
        v = a2.verify(self.stego_view, self.v_media_id.get(), int(self.v_n_lsb.get()),
                      self.v_pass.get(), pub, codec=self.codec, bits=self.bits,
                      trace=tr)
        self._register_trace("verify", tr)
        self._show_verdict(v)

    def _show_verdict(self, v):
        self.banner.configure(text=str(v.code), bg=v.colour, fg="white")
        self.reason.configure(text=v.reason)

        lines = ["source        : {}".format(self.stego_source),
                 "meaning       : {}".format(v.meaning), ""]
        for k, val in (v.details or {}).items():
            lines.append("{:<14}: {}".format(k, val))
        if v.payload is not None:
            lines += ["", "PAYLOAD RECORD:", v.payload.pretty()]
        self.checks.delete("1.0", "end")
        self.checks.insert("1.0", "\n".join(lines))

        self.recovered.delete("1.0", "end")
        self.recovered.insert("1.0", v.message_text() if v.message is not None
                              else "(no message recovered)")
        self.status.set(str(v.code))

    # =====================================================================
    # tamper toolbar
    # =====================================================================
    def _mutate(self, fn, note: str):
        """Apply fn(bytearray) to a copy of the clean stego and reload it."""
        if getattr(self, "_clean_stego", None) is None:
            messagebox.showwarning("Nothing loaded", "Protect or load a stego object first.")
            return
        sam = bytearray(self.codec.read_samples(self._clean_stego))
        fn(sam)
        self.stego_view = self.codec.write_samples(self._clean_stego, bytes(sam))
        self.stego_source = "tampered in memory: " + note
        self.verify_src.set(self.stego_source)
        self.status.set(note + " - press Verify")

    def t_content(self):
        start = self.last_protect.start_unit if self.last_protect else 0

        def fn(sam):
            # a high-order bit well away from the payload region
            i = (start + len(sam) // 3) % len(sam)
            sam[i] ^= 0x80
        self._mutate(fn, "flipped one high-order content bit")

    def t_payload(self):
        if not self.last_protect:
            messagebox.showwarning("Need a protect run",
                                   "Run Protect first so the payload offset is known.")
            return
        start = self.last_protect.start_unit

        def fn(sam):
            sam[start + 200] ^= 0x01          # inside the payload body
        self._mutate(fn, "flipped one bit inside the embedded payload")

    def t_passphrase(self):
        self.v_pass.set("definitely-the-wrong-passphrase")
        self.t_reset()
        self.status.set("passphrase changed - press Verify")

    def t_wrongkey(self):
        path = os.path.join(KEYS_DIR, "impostor_public.pem")
        if not os.path.exists(path):
            a2.save_keypair(a2.generate_keypair(self.algo.get()),
                            os.path.join(KEYS_DIR, "impostor_private.pem"), path)
        self.v_pub.set(path)
        self.t_reset()
        self.status.set("switched to an impostor public key - press Verify")

    def t_clean(self):
        if self.cover_view is None:
            return
        self.stego_view = self.cover_view
        self._clean_stego = self.cover_view
        self.stego_source = "the original clean cover (no payload embedded)"
        self.verify_src.set(self.stego_source)
        self.status.set("using the clean cover - press Verify")

    def t_wronglsb(self):
        cur = int(self.v_n_lsb.get())
        self.v_n_lsb.set(cur + 1 if cur < 8 else 1)
        self.t_reset()
        self.status.set("LSB count changed to {} - press Verify".format(self.v_n_lsb.get()))

    def t_header(self):
        if not self.last_protect:
            messagebox.showwarning("Need a protect run", "Run Protect first.")
            return
        start = self.last_protect.start_unit
        n = self.last_protect.n_lsb

        def fn(sam):
            # leave the magic intact, wreck the declared-length fields
            for i in range(9 * 8 // n, 13 * 8 // n):
                sam[start + i] |= (1 << n) - 1
        self._mutate(fn, "corrupted the header length fields")

    def t_reset(self):
        if self.last_protect is not None:
            self._clean_stego = self.last_protect.stego_view
            self.stego_view = self.last_protect.stego_view
            self.stego_source = "clean stego from the last Protect run"
            self.verify_src.set(self.stego_source)

    # =====================================================================
    # trace tab
    # =====================================================================
    def _register_trace(self, name: str, tr: Trace):
        self.traces[name] = tr
        self.trace_combo["values"] = list(self.traces)
        self.trace_pick.set(name)
        self._render_trace()

    def _render_trace(self):
        tr = self.traces.get(self.trace_pick.get())
        self.tree.delete(*self.tree.get_children())
        if tr is None:
            return
        for i, st in enumerate(tr.steps):
            self.tree.insert("", "end", iid=str(i), values=(
                st.stage, st.label, "{:.2f}".format(st.ms), "ok" if st.ok else "FAIL"))

    def _show_step(self):
        tr = self.traces.get(self.trace_pick.get())
        sel = self.tree.selection()
        if not tr or not sel:
            return
        st = tr.steps[int(sel[0])]
        out = ["stage : {}".format(st.stage),
               "label : {}".format(st.label),
               "ok    : {}".format(st.ok),
               "ms    : {:.3f}".format(st.ms), "", "detail:"]
        out.append(json.dumps(st.detail, indent=2, default=str))
        if st.blob is not None:
            out += ["", "blob ({} bytes):".format(len(st.blob)), hexdump(st.blob, 256)]
        self.step_out.delete("1.0", "end")
        self.step_out.insert("1.0", "\n".join(out))

    def copy_trace(self):
        tr = self.traces.get(self.trace_pick.get())
        if tr is None:
            return
        self.clipboard_clear()
        self.clipboard_append(tr.to_json())
        self.status.set("trace copied to clipboard")

    def export_trace(self):
        tr = self.traces.get(self.trace_pick.get())
        if tr is None:
            return
        os.makedirs(OUT_DIR, exist_ok=True)
        path = filedialog.asksaveasfilename(
            initialdir=OUT_DIR, defaultextension=".json",
            initialfile="trace_{}.json".format(self.trace_pick.get()))
        if path:
            tr.save(path)
            self.status.set("trace written to " + path)

    def run_selftest(self):
        import io
        import contextlib
        from a2_crypto import selftest
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = selftest.main()
        self.step_out.delete("1.0", "end")
        self.step_out.insert("1.0", buf.getvalue())
        self.nb.select(self.tab_trace)
        self.status.set("selftest exit code {}".format(code))


if __name__ == "__main__":
    A2DebugGUI().mainloop()
