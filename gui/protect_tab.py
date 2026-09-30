"""
gui/protect_tab.py - Protect screen: load a cover, choose a message, embed it.

Covers FR1/FR2 (image/audio input), FR3 (payload), FR4 (signing), FR5/FR6
(embedding), FR7 (start location - shown after embedding, never before), and
the mandatory capacity-check negative case.
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
from .widgets import (AudioPlayButton, CapacityBar, FileLoadRow, ImagePreview,
                      ScrollableFrame, WaveformView, read_n_lsb)

MONO = theme.mono_font(10)


class ProtectTab(ttk.Frame):
    def __init__(self, master, session: SessionState, go_to_verify):
        super().__init__(master)
        self.session = session
        self.go_to_verify = go_to_verify
        self.cover: CoverHandle | None = None
        self._build()

    # ------------------------------------------------------------------ ui
    def _build(self):
        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)
        body = scroll.body

        cov = ttk.LabelFrame(body, text="1. Cover object (FR1/FR2)")
        cov.pack(fill="x", padx=8, pady=6)
        self.loader = FileLoadRow(cov, self._load, dialog_title="Select cover", samples=True,
                                  empty_text="No cover loaded yet - load a PNG/WAV or use a sample.")
        self.loader.pack(fill="x")

        msg = ttk.LabelFrame(body, text="2. Hidden message (FR3 payload content)")
        msg.pack(fill="x", padx=8, pady=6)
        self.msg_kind = tk.StringVar(value="short")
        self._prev_msg_kind = "short"
        self._free_draft = ""
        for i, key in enumerate(("short", "large", "custom", "oversized", "free")):
            ttk.Radiobutton(msg, text=sess.MESSAGE_LABELS[key], variable=self.msg_kind,
                            value=key, command=self._on_message_change).grid(
                                row=0, column=i, sticky="w", padx=4, pady=4)
        self.msg_text = tk.Text(msg, height=5, wrap="word", font=MONO)
        self.msg_text.grid(row=1, column=0, columnspan=5, sticky="ew", padx=6, pady=(0, 6))
        self.msg_text.bind("<KeyRelease>", lambda _e: self._update_capacity())
        msg.columnconfigure(4, weight=1)

        ctl = ttk.LabelFrame(body, text="3. Embedding parameters (FR4 signing, FR6/FR7 depth + location)")
        ctl.pack(fill="x", padx=8, pady=6)
        self.n_lsb = tk.IntVar(value=2)
        self.media_id = tk.StringVar(value="IMG-0007")
        self.passphrase = tk.StringVar(value=sess.DEFAULT_PASSPHRASE)
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
        ttk.Entry(ctl, textvariable=self.passphrase, width=28, show="*").grid(
            row=0, column=5, sticky="w")
        ttk.Checkbutton(ctl, text="Encrypt message (AES-256-GCM)", variable=self.encrypt,
                        command=self._update_capacity).grid(
            row=1, column=0, columnspan=2, sticky="w", padx=4)
        ttk.Label(ctl, text="Signature:").grid(row=1, column=2, sticky="e", padx=4)
        cb = ttk.Combobox(ctl, textvariable=self.algo, width=14, state="readonly",
                          values=list(a2.SIGNERS))
        cb.grid(row=1, column=3, sticky="w")
        cb.bind("<<ComboboxSelected>>", lambda _e: self._update_capacity())
        ttk.Label(ctl, text="This passphrase also derives WHERE the payload is hidden "
                            "(FR7) - see docs/A2_CRYPTO_README.md. Changing it moves the "
                            "hidden location; it is never stored in the file.",
                 foreground=theme.COLORS["muted"], wraplength=760).grid(
            row=2, column=0, columnspan=6, sticky="w", padx=4, pady=(4, 0))

        self.cap_bar = CapacityBar(body)
        self.cap_bar.pack(fill="x", padx=8, pady=6)
        # packed under the capacity bar only while n_lsb = 8 (see _update_lsb_warning)
        self.lsb_warn = tk.Label(body, anchor="w", justify="left", wraplength=1000,
                                 background=theme.COLORS["warn_bg"],
                                 foreground=theme.COLORS["warn"],
                                 font=theme.font(10, "bold"), padx=10, pady=6)

        act = ttk.Frame(body)
        act.pack(fill="x", padx=8, pady=4)
        ttk.Button(act, text="Protect -> embed payload", command=self.do_protect,
                  style="Accent.TButton").pack(side="left")
        self.save_btn = ttk.Button(act, text="Save stego to file...", command=self.save_stego,
                                   state="disabled")
        self.save_btn.pack(side="left", padx=6)
        self.verify_btn = ttk.Button(act, text="Send stego to Verify tab ->",
                                     command=self._send_to_verify, state="disabled")
        self.verify_btn.pack(side="left", padx=6)

        self.out_text = tk.Text(body, height=9, wrap="word", font=MONO)
        self.out_text.pack(fill="x", padx=8, pady=6)

        self.compare_frame = ttk.LabelFrame(
            body, text="4. Before / after comparison (proof the payload is imperceptible)")
        self.compare_frame.pack(fill="both", expand=True, padx=8, pady=6)
        ttk.Label(self.compare_frame, text="Protect a cover to see the comparison.",
                 foreground=theme.COLORS["muted"]).pack(padx=10, pady=10)

        self._on_message_change()

    # -------------------------------------------------------------- cover
    def _load(self, media_type: str, path: str):
        codec = self.session.codec_for(media_type)
        try:
            view = codec.load(path)
        except Exception as exc:
            messagebox.showerror("Load failed", "{}: {}".format(type(exc).__name__, exc))
            return
        self.cover = CoverHandle(media_type, codec, view, os.path.basename(path))
        units = len(codec.read_samples(view))
        self.loader.set_loaded("Loaded: {}   ({}, {:,} units)".format(
            self.cover.source, codec.name, units))
        self.media_id.set(sess.DEFAULT_MEDIA_ID[media_type])
        self.save_btn.configure(state="disabled")
        self.verify_btn.configure(state="disabled")
        self._reset_compare()
        self._update_capacity()

    # ------------------------------------------------------------- message
    def _on_message_change(self):
        kind = self.msg_kind.get()
        if self._prev_msg_kind == "free" and kind != "free":
            self._free_draft = self._message()
        self._prev_msg_kind = kind
        self.msg_text.delete("1.0", "end")
        if kind == "free":
            self.msg_text.insert("1.0", self._free_draft)
            self.msg_text.focus_set()
        else:
            self.msg_text.insert("1.0", sess.MESSAGE_PRESETS[kind]())
        self._update_capacity()

    def _message(self) -> str:
        return self.msg_text.get("1.0", "end-1c")

    # ------------------------------------------------------------ capacity
    def _update_capacity(self):
        # parsed quietly here (this runs on every keypress); do_protect() is
        # where an invalid value gets a popup
        try:
            n_lsb = int(self.n_lsb.get())
            valid = 1 <= n_lsb <= 8
        except Exception:
            valid = False
        self._update_lsb_warning(n_lsb if valid else None)
        if self.cover is None:
            self.cap_bar.set_message("load a cover to see capacity")
            return
        if not valid:
            self.cap_bar.set_message("n_lsb must be 1-8")
            return
        try:
            # `bits` makes the live bar use the bitstream engine's own
            # capacity_check, the same one protect()'s gate uses, so the bar
            # and the block can never disagree.
            report = a2.capacity_report(self.cover.codec, self.cover.view, n_lsb,
                                        self._message(), self.algo.get(), self.encrypt.get(),
                                        bits=self.session.bits)
        except Exception as exc:
            self.cap_bar.set_message(str(exc))
            return
        self.cap_bar.update_report(report)

    def _update_lsb_warning(self, n_lsb):
        """A2 handoff requirement: warn at n_lsb = 8. Every bit of every byte
        then carries payload, so the cover hash has nothing left to cover."""
        if n_lsb is not None and not a2.tamper_detection_strength(n_lsb)["detects_content_tampering"]:
            self.lsb_warn.configure(
                text="Warning: at 8 LSBs every bit of every cover byte carries payload, so "
                     "content tampering and payload substitution can NOT be detected - only "
                     "the signature still protects the payload itself. Use 7 or fewer LSBs "
                     "if you need tamper detection.")
            if not self.lsb_warn.winfo_manager():
                self.lsb_warn.pack(fill="x", padx=8, pady=(0, 6), after=self.cap_bar)
        else:
            self.lsb_warn.pack_forget()

    # -------------------------------------------------------------- protect
    def do_protect(self):
        if self.cover is None:
            messagebox.showwarning("No cover", "Load a PNG or WAV cover first.")
            return
        n_lsb = read_n_lsb(self.n_lsb)
        if n_lsb is None:
            return
        if not self.passphrase.get():
            messagebox.showwarning(
                "Passphrase required",
                "Enter a passphrase. It derives both where the payload is hidden and the "
                "key that encrypts it - an empty one would let anyone find and read it.")
            return
        if not self.media_id.get().strip():
            messagebox.showwarning("Media ID required",
                                   "Enter a media ID - it's signed into the payload and "
                                   "also decides where the payload is hidden.")
            return
        if not self._message() and not messagebox.askyesno(
                "Empty message", "The hidden message is empty. Protect anyway?"):
            return
        priv, _pub, _pub_path = self.session.keys_for(self.algo.get())
        tr = Trace("protect")
        try:
            res = a2.protect(
                self.cover.view, self._message(), self.media_id.get(),
                n_lsb, self.passphrase.get(), priv,
                codec=self.cover.codec, bits=self.session.bits,
                media_type=self.cover.media_type, algo=self.algo.get(),
                encrypt=self.encrypt.get(), trace=tr)
        except a2.CapacityError as exc:
            self.out_text.delete("1.0", "end")
            self.out_text.insert("1.0",
                "BLOCKED - capacity check failed (this is the mandatory negative "
                "case: payload larger than the cover can carry)\n\n{}\n\n"
                "Fix: raise the LSB count, use a larger cover, or pick a shorter "
                "message preset.".format(exc))
            return
        except Exception as exc:
            messagebox.showerror("Protect failed", "{}: {}".format(type(exc).__name__, exc))
            return

        self.session.last_protect = res
        self.session.last_protect_cover = self.cover
        stego = CoverHandle(self.cover.media_type, self.cover.codec, res.stego_view,
                            "protected just now from {}".format(self.cover.source))
        self.session.last_protect_stego = stego
        self.session.last_protect_params = {
            "media_id": self.media_id.get(), "n_lsb": n_lsb,
            "passphrase": self.passphrase.get(), "algo": self.algo.get(),
        }

        summary = [
            "PROTECTED",
            "  signature algorithm : {} ({} bytes)".format(res.algo, len(res.signature)),
            "  derived start unit  : {:,}   <- not stored anywhere in the stego file".format(
                res.start_unit),
            "  embedded stream     : {:,} bytes ({:,} bits)".format(
                res.stream_bytes, res.needed_bits),
            "  cover bytes changed : {:,}".format(res.details["changed_bytes"]),
            "  stable cover digest : {}".format(res.details["digest_hex"][:32] + "..."),
            "",
            "PAYLOAD RECORD (this is what gets signed, in canonical form):",
            res.payload.pretty(),
        ]
        self.out_text.delete("1.0", "end")
        self.out_text.insert("1.0", "\n".join(summary))

        self.save_btn.configure(state="normal")
        self.verify_btn.configure(state="normal")
        self._render_comparison()

    # ------------------------------------------------------------- output
    def save_stego(self):
        if self.session.last_protect_stego is None:
            return
        stego = self.session.last_protect_stego
        ext = ".png" if stego.media_type == "image" else ".wav"
        os.makedirs(sess.OUT_DIR, exist_ok=True)
        path = filedialog.asksaveasfilename(
            initialdir=sess.OUT_DIR, defaultextension=ext, initialfile="stego" + ext)
        if not path:
            return
        try:
            stego.codec.save(stego.view, path)
            messagebox.showinfo("Saved", "Stego object written to:\n{}".format(path))
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def _send_to_verify(self):
        self.go_to_verify()

    # --------------------------------------------------------- comparison
    def _reset_compare(self):
        for child in self.compare_frame.winfo_children():
            child.destroy()
        ttk.Label(self.compare_frame, text="Protect this cover to see the comparison.",
                 foreground=theme.COLORS["muted"]).pack(padx=10, pady=10)

    def _render_comparison(self):
        for child in self.compare_frame.winfo_children():
            child.destroy()
        cover, stego = self.session.last_protect_cover, self.session.last_protect_stego
        stats = cover.codec.compare(cover.view, stego.view)

        if cover.media_type == "image":
            row = ttk.Frame(self.compare_frame)
            row.pack(fill="x", padx=6, pady=6)
            p_cover = ImagePreview(row, "Cover (before)")
            p_cover.pack(side="left", padx=4)
            p_cover.show_array(cover.view)
            p_stego = ImagePreview(row, "Stego (after)")
            p_stego.pack(side="left", padx=4)
            p_stego.show_array(stego.view)
            p_diff = ImagePreview(row, "Diff (amplified x32)")
            p_diff.pack(side="left", padx=4)
            p_diff.show_array(cover.codec.diff_image(cover.view, stego.view, amplify=32))
            ttk.Label(self.compare_frame,
                     text="{:,} / {:,} pixels changed ({}%), max channel delta {} - "
                          "imperceptible to the eye, visible only once amplified.".format(
                              stats["changed_pixels"], stats["total_pixels"],
                              stats["percent_changed"], stats["max_channel_delta"])
                     ).pack(padx=6, pady=(0, 6), anchor="w")
        else:
            cover_arr, cover_params = cover.view
            stego_arr, _stego_params = stego.view
            cover_wave = cover.codec.waveform(cover.view)
            stego_wave = stego.codec.waveform(stego.view)
            peak = max(1.0, float(max(abs(cover_wave).max(), abs(stego_wave).max())))

            row1 = ttk.Frame(self.compare_frame)
            row1.pack(fill="x", padx=6, pady=(6, 0))
            ttk.Label(row1, text="Cover (before):", width=16).pack(side="left")
            wv1 = WaveformView(row1)
            wv1.pack(side="left", padx=4)
            wv1.draw(cover_wave, peak=peak)
            AudioPlayButton(row1, lambda: (cover_arr.tobytes(), cover_params.n_channels,
                                           cover_params.sampwidth, cover_params.framerate)
                           ).pack(side="left", padx=6)

            row2 = ttk.Frame(self.compare_frame)
            row2.pack(fill="x", padx=6, pady=(4, 0))
            ttk.Label(row2, text="Stego (after):", width=16).pack(side="left")
            wv2 = WaveformView(row2)
            wv2.pack(side="left", padx=4)
            wv2.draw(stego_wave, peak=peak)
            AudioPlayButton(row2, lambda: (stego_arr.tobytes(), cover_params.n_channels,
                                           cover_params.sampwidth, cover_params.framerate)
                           ).pack(side="left", padx=6)

            row3 = ttk.Frame(self.compare_frame)
            row3.pack(fill="x", padx=6, pady=(4, 0))
            ttk.Label(row3, text="Diff (amplified x32):", width=16).pack(side="left")
            
            diff_wave = (stego_wave.astype(float) - cover_wave.astype(float)) * 32
            wv3 = WaveformView(row3, color=theme.COLORS.get("warn", "red"))
            wv3.pack(side="left", padx=4)
            wv3.draw(diff_wave, peak=peak)

            # amplified diff
            ttk.Label(self.compare_frame,
                     text="{:,} / {:,} bytes changed ({}%), max byte delta {} - low-byte-only "
                          "embedding keeps this inaudible. The amplified diff above proves the "
                          "payload exists.".format(
                              stats["changed_bytes"], stats["total_bytes"],
                              stats["percent_changed"], stats["max_byte_delta"])
                     ).pack(padx=6, pady=6, anchor="w")

            # Zoomed-in diff, cropped to the embed region and auto-scaled to
            # its OWN max (peak=None) instead of the full-file peak above.
            # At low LSB depths the real delta is only a few units, which is
            # invisible next to full-scale audio even amplified x32 - this
            # is the same diff data, just windowed + independently scaled
            # so it's actually visible on screen, not a different metric.
            res = self.session.last_protect
            if res is not None:
                start = getattr(res, "start_unit", 0)
                n_lsb_val = max(1, self.n_lsb.get())
                approx_units = -(-res.needed_bits // n_lsb_val)  # ceiling division
                pad = 100
                lo = max(0, start - pad)
                hi = min(len(diff_wave), start + approx_units + pad)
                zoom_wave = diff_wave[lo:hi]

                row4 = ttk.Frame(self.compare_frame)
                row4.pack(fill="x", padx=6, pady=(4, 0))
                ttk.Label(row4, text="Diff, zoomed to\nembed region:", width=16).pack(side="left")
                wv4 = WaveformView(row4, color=theme.COLORS.get("warn", "red"))
                wv4.pack(side="left", padx=4)
                wv4.draw(zoom_wave, peak=None)  # auto-scales to this window's own max

                ttk.Label(self.compare_frame,
                         text="Same diff as above, cropped to samples {:,}-{:,} (the embed "
                              "region) and scaled to its own range instead of the full "
                              "audio's peak - this is where the {:,} bytes actually "
                              "changed.".format(lo, hi, stats["changed_bytes"])
                         ).pack(padx=6, pady=(0, 6), anchor="w")