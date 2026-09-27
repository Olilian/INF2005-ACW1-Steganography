"""
gui/exchange_tab.py - the mandatory "party A sends, party B downloads and
verifies" case, as two honest halves of one screen.

Party A's "Send" writes the stego file into gui_out/party_a_sent/ - standing
in for an email attachment. Party B never sees Party A's in-memory state:
the only way B gets the file is by picking it from that folder and
"downloading" a copy into gui_out/party_b_downloads/, then supplying the
media ID / passphrase / LSB count / public key A gave them out of band. That
separation is the point of the demo - it's what makes the extraction and
signature check meaningful rather than trivially trusted in-memory state.
"""
from __future__ import annotations

import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import a2_crypto as a2
from a2_crypto import Trace

from . import session as sess
from . import theme
from .session import CoverHandle, SessionState
from .widgets import CapacityBar, ScrollableFrame, VerdictBanner, read_n_lsb

MONO = theme.mono_font(10)


class ExchangeTab(ttk.Frame):
    def __init__(self, master, session: SessionState):
        super().__init__(master)
        self.session = session
        self.a_cover: CoverHandle | None = None
        self.b_stego: CoverHandle | None = None
        self._build()

    # ------------------------------------------------------------------ ui
    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        root = scroll.body

        ttk.Label(root, text="Party A protects and sends a file by email. Party B only "
                             "gets the file itself - the media ID, passphrase, LSB count "
                             "and public key must reach them some other way (a call, a "
                             "signed handout). That is what is being verified below.",
                 foreground=theme.COLORS["muted"], wraplength=1080).pack(fill="x", padx=8, pady=(8, 4))

        body = ttk.Frame(root)
        body.pack(fill="both", expand=True, padx=8, pady=4)
        self._build_party_a(body)
        self._build_party_b(body)

    # --------------------------------------------------------------- party A
    def _build_party_a(self, parent):
        a = ttk.LabelFrame(parent, text="Party A - protect and send")
        a.pack(side="left", fill="both", expand=True, padx=(0, 6))

        ttk.Button(a, text="Load PNG cover...", command=lambda: self._a_load("image")).pack(
            anchor="w", padx=6, pady=(6, 0))
        ttk.Button(a, text="Load WAV cover...", command=lambda: self._a_load("audio")).pack(
            anchor="w", padx=6, pady=(2, 0))
        self.a_cover_info = tk.StringVar(value="(nothing loaded)")
        ttk.Label(a, textvariable=self.a_cover_info, foreground=theme.COLORS["muted"]).pack(
            anchor="w", padx=6, pady=(2, 6))

        ttk.Label(a, text="Message:").pack(anchor="w", padx=6)
        self.a_msg_kind = tk.StringVar(value="short")
        for key in ("short", "large", "custom"):
            ttk.Radiobutton(a, text=sess.MESSAGE_LABELS[key], variable=self.a_msg_kind,
                            value=key, command=self._a_update_capacity).pack(anchor="w", padx=16)

        form = ttk.Frame(a)
        form.pack(fill="x", padx=6, pady=6)
        self.a_media_id = tk.StringVar(value="IMG-0007")
        self.a_passphrase = tk.StringVar(value=sess.DEFAULT_PASSPHRASE)
        self.a_n_lsb = tk.IntVar(value=2)
        self.a_algo = tk.StringVar(value=a2.DEFAULT_SIGN_ALGO)
        ttk.Label(form, text="Media ID:").grid(row=0, column=0, sticky="e")
        ttk.Entry(form, textvariable=self.a_media_id, width=14).grid(row=0, column=1, sticky="w")
        ttk.Label(form, text="LSBs:").grid(row=1, column=0, sticky="e")
        ttk.Spinbox(form, from_=1, to=8, textvariable=self.a_n_lsb, width=5,
                   command=self._a_update_capacity).grid(row=1, column=1, sticky="w")
        ttk.Label(form, text="Passphrase:").grid(row=2, column=0, sticky="e")
        ttk.Entry(form, textvariable=self.a_passphrase, width=22, show="*").grid(
            row=2, column=1, sticky="w")
        ttk.Label(form, text="Algo:").grid(row=3, column=0, sticky="e")
        ttk.Combobox(form, textvariable=self.a_algo, width=12, state="readonly",
                    values=list(a2.SIGNERS)).grid(row=3, column=1, sticky="w")

        self.a_cap = CapacityBar(a)
        self.a_cap.pack(fill="x", padx=6, pady=4)

        ttk.Button(a, text="Protect & send as email attachment ->",
                  command=self._a_send, style="Accent.TButton").pack(padx=6, pady=6, anchor="w")
        self.a_out = tk.Text(a, height=10, wrap="word", font=MONO)
        self.a_out.pack(fill="both", expand=True, padx=6, pady=(0, 6))

    def _a_load(self, media_type):
        ft = [("PNG", "*.png")] if media_type == "image" else [("WAV", "*.wav")]
        path = filedialog.askopenfilename(title="Select cover", filetypes=ft)
        if not path:
            return
        codec = self.session.codec_for(media_type)
        try:
            view = codec.load(path)
        except Exception as exc:
            messagebox.showerror("Load failed", str(exc))
            return
        self.a_cover = CoverHandle(media_type, codec, view, os.path.basename(path))
        self.a_cover_info.set(self.a_cover.source)
        self.a_media_id.set(sess.DEFAULT_MEDIA_ID[media_type])
        self._a_update_capacity()

    def _a_update_capacity(self):
        if self.a_cover is None:
            self.a_cap.set_message("load a cover to see capacity")
            return
        try:
            report = a2.capacity_report(
                self.a_cover.codec, self.a_cover.view, int(self.a_n_lsb.get()),
                sess.MESSAGE_PRESETS[self.a_msg_kind.get()](), self.a_algo.get(), True)
        except Exception as exc:
            self.a_cap.set_message(str(exc))
            return
        self.a_cap.update_report(report)

    def _a_send(self):
        if self.a_cover is None:
            messagebox.showwarning("No cover", "Party A needs to load a cover first.")
            return
        n_lsb = read_n_lsb(self.a_n_lsb)
        if n_lsb is None:
            return
        if not self.a_passphrase.get():
            messagebox.showwarning("Passphrase required",
                                   "Party A needs a passphrase - an empty one would let "
                                   "anyone find and read the payload.")
            return
        if not self.a_media_id.get().strip():
            messagebox.showwarning("Media ID required", "Party A needs a media ID.")
            return
        priv, _pub, _pub_path = self.session.keys_for(self.a_algo.get())
        message = sess.MESSAGE_PRESETS[self.a_msg_kind.get()]()
        tr = Trace("protect")
        try:
            res = a2.protect(
                self.a_cover.view, message, self.a_media_id.get(), n_lsb,
                self.a_passphrase.get(), priv, codec=self.a_cover.codec, bits=self.session.bits,
                media_type=self.a_cover.media_type, algo=self.a_algo.get(),
                encrypt=True, trace=tr)
        except a2.CapacityError as exc:
            self.a_out.delete("1.0", "end")
            self.a_out.insert("1.0", "BLOCKED - capacity check failed:\n{}".format(exc))
            return
        except Exception as exc:
            messagebox.showerror("Protect failed", str(exc))
            return

        ext = ".png" if self.a_cover.media_type == "image" else ".wav"
        base = "{}_{}".format(self.a_media_id.get(), os.path.splitext(self.a_cover.source)[0])
        filename = "{}{}".format(base, ext)
        out_path = os.path.join(sess.OUTBOX_DIR, filename)
        self.a_cover.codec.save(res.stego_view, out_path)

        self.a_out.delete("1.0", "end")
        self.a_out.insert("1.0",
            "Sent as an email attachment: {}\n\n"
            "Signature: {} ({} bytes)\nDerived start unit: {:,} (not in the file)\n\n"
            "Party A must now tell Party B, out of band, the media ID ({}), the "
            "passphrase, the LSB count ({}) and share the public key - none of that "
            "travels with the attachment.".format(
                filename, res.algo, len(res.signature), res.start_unit,
                self.a_media_id.get(), n_lsb))
        self.event_generate("<<OutboxUpdated>>")

    # --------------------------------------------------------------- party B
    def _build_party_b(self, parent):
        b = ttk.LabelFrame(parent, text="Party B - download and verify")
        b.pack(side="left", fill="both", expand=True, padx=(6, 0))

        ttk.Button(b, text="Check inbox (Party A's outbox)", command=self._b_refresh_inbox).pack(
            anchor="w", padx=6, pady=(6, 0))
        self.b_listbox = tk.Listbox(b, height=5)
        self.b_listbox.pack(fill="x", padx=6, pady=4)
        ttk.Button(b, text="Download selected to my folder", command=self._b_download).pack(
            anchor="w", padx=6)
        self.b_src_info = tk.StringVar(value="(nothing downloaded yet)")
        ttk.Label(b, textvariable=self.b_src_info, foreground=theme.COLORS["muted"]).pack(
            anchor="w", padx=6, pady=(2, 6))

        form = ttk.Frame(b)
        form.pack(fill="x", padx=6, pady=6)
        self.b_media_id = tk.StringVar(value="IMG-0007")
        self.b_passphrase = tk.StringVar(value=sess.DEFAULT_PASSPHRASE)
        self.b_n_lsb = tk.IntVar(value=2)
        self.b_algo = tk.StringVar(value=a2.DEFAULT_SIGN_ALGO)
        self.b_pub_path = tk.StringVar(value="")
        ttk.Label(form, text="Media ID (told by A):").grid(row=0, column=0, sticky="e")
        ttk.Entry(form, textvariable=self.b_media_id, width=14).grid(row=0, column=1, sticky="w")
        ttk.Label(form, text="LSBs (told by A):").grid(row=1, column=0, sticky="e")
        ttk.Spinbox(form, from_=1, to=8, textvariable=self.b_n_lsb, width=5).grid(
            row=1, column=1, sticky="w")
        ttk.Label(form, text="Passphrase (told by A):").grid(row=2, column=0, sticky="e")
        ttk.Entry(form, textvariable=self.b_passphrase, width=22, show="*").grid(
            row=2, column=1, sticky="w")
        ttk.Label(form, text="A's public key:").grid(row=3, column=0, sticky="e")
        ttk.Entry(form, textvariable=self.b_pub_path, width=30).grid(row=3, column=1, sticky="w")
        ttk.Button(form, text="Browse...", command=self._b_pick_pub).grid(row=3, column=2)
        ttk.Button(form, text="Use A's demo public key for this algo",
                  command=self._b_use_demo_key).grid(row=4, column=0, columnspan=3, sticky="w",
                                                      pady=(2, 0))
        ttk.Combobox(form, textvariable=self.b_algo, width=12, state="readonly",
                    values=list(a2.SIGNERS)).grid(row=0, column=2, padx=(6, 0))

        ttk.Button(b, text="Extract & verify ->", command=self._b_verify,
                  style="Accent.TButton").pack(padx=6, pady=6, anchor="w")
        self.b_verdict = VerdictBanner(b)
        self.b_verdict.pack(fill="x", padx=6, pady=4)
        self.b_out = tk.Text(b, height=8, wrap="word", font=MONO)
        self.b_out.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self._b_use_demo_key()

    def _b_refresh_inbox(self):
        self.b_listbox.delete(0, "end")
        for name in sorted(os.listdir(sess.OUTBOX_DIR)):
            self.b_listbox.insert("end", name)

    def _b_download(self):
        sel = self.b_listbox.curselection()
        if not sel:
            messagebox.showwarning("Nothing selected", "Pick a file from the inbox list first.")
            return
        name = self.b_listbox.get(sel[0])
        src = os.path.join(sess.OUTBOX_DIR, name)
        dst = os.path.join(sess.INBOX_DIR, name)
        media_type = "image" if name.lower().endswith(".png") else "audio"
        codec = self.session.codec_for(media_type)
        try:
            shutil.copyfile(src, dst)
            view = codec.load(dst)
        except FileNotFoundError:
            messagebox.showwarning("File no longer in the outbox",
                                   "'{}' is no longer in Party A's outbox. The inbox list "
                                   "has been refreshed.".format(name))
            self._b_refresh_inbox()
            return
        except Exception as exc:
            messagebox.showerror("Download failed", "{}: {}".format(type(exc).__name__, exc))
            return
        self.b_stego = CoverHandle(media_type, codec, view,
                                   "downloaded from inbox: {}".format(name))
        self.b_src_info.set("Downloaded to {}".format(dst))
        # don't leave the previous file's verdict showing next to a new file
        self.b_verdict.clear()
        self.b_out.delete("1.0", "end")

    def _b_pick_pub(self):
        path = filedialog.askopenfilename(title="Public key", filetypes=[("PEM", "*.pem")])
        if path:
            self.b_pub_path.set(path)

    def _b_use_demo_key(self):
        _priv, _pub, pub_path = self.session.keys_for(self.b_algo.get())
        self.b_pub_path.set(pub_path)

    def _b_verify(self):
        if self.b_stego is None:
            messagebox.showwarning("Nothing downloaded", "Download a file from the inbox first.")
            return
        n_lsb = read_n_lsb(self.b_n_lsb)
        if n_lsb is None:
            return
        try:
            pub = a2.load_public(self.b_pub_path.get())
        except a2.KeyError_ as exc:
            self.b_verdict.show(a2.Verdict(a2.VerdictCode.CANNOT_VERIFY, str(exc)))
            return
        v = a2.verify(self.b_stego.view, self.b_media_id.get(), n_lsb,
                     self.b_passphrase.get(), pub, codec=self.b_stego.codec,
                     bits=self.session.bits, algo=self.b_algo.get())
        replay_of = self.session.check_replay(v, self.b_stego.source)
        self.b_verdict.show(v, replay_of)
        lines = ["proof of integrity + signature verification:", ""]
        if replay_of:
            lines += ["REPLAY - this payload was already accepted from: {}".format(replay_of), ""]
        for k, val in (v.details or {}).items():
            lines.append("{:<20}: {}".format(k, val))
        if v.message is not None:
            lines += ["", "recovered message:", v.message_text()]
        self.b_out.delete("1.0", "end")
        self.b_out.insert("1.0", "\n".join(lines))
