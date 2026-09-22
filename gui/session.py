"""
gui/session.py - state and helpers shared by every tab of the production GUI.

One SessionState is created by the App and handed to each tab. It owns the
codec/bitstream adapters (the same ones a2_integration.py and
a2_debug_gui.py use), the demo keypairs, and the "last result" pointers that
let one tab hand its output to another (e.g. Protect -> Verify, or
Party A's send -> Party B's inbox).

No Tkinter imports here - this module is UI-framework-agnostic so it stays
easy to unit test on its own.
"""
from __future__ import annotations

import os

import a2_crypto as a2
from a2_integration import A1BitstreamAdapter, AudioCodecAdapter, ImageCodecAdapter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(HERE, "keys")
TESTDATA_DIR = os.path.join(HERE, "a2_crypto", "testdata")
OUT_DIR = os.path.join(HERE, "gui_out")
OUTBOX_DIR = os.path.join(OUT_DIR, "party_a_sent")       # A's "sent mail"
INBOX_DIR = os.path.join(OUT_DIR, "party_b_downloads")    # B's "downloads"

DEFAULT_MEDIA_ID = {"image": "IMG-0007", "audio": "AUD-0007"}
DEFAULT_PASSPHRASE = "team-P1-4-shared-passphrase"


def _read_testdata(name: str) -> str:
    try:
        with open(os.path.join(TESTDATA_DIR, name), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


# Required by the spec: a short message (a Learning Outcome), a large one
# (the Project Overview paragraph) and a custom team payload - the exact
# three sizes a2_crypto/testdata already carries as test fixtures. "oversized"
# is a one-click way to reliably trigger the mandatory capacity-check
# negative case regardless of which cover is loaded.
MESSAGE_PRESETS = {
    "short": lambda: _read_testdata("payload_short.txt"),
    "large": lambda: _read_testdata("payload_large.txt"),
    "custom": lambda: _read_testdata("payload_custom.json"),
    "oversized": lambda: _read_testdata("payload_large.txt") * 40,
}
MESSAGE_LABELS = {
    "short": "Short (Learning Outcome)",
    "large": "Large (Project Overview)",
    "custom": "Custom (team JSON record)",
    "oversized": "Oversized (forces capacity check to fail)",
    "free": "Free text",
}


class CoverHandle:
    """One loaded cover or stego object: its in-memory view, codec and where it came from."""

    def __init__(self, media_type: str, codec, view, source: str):
        self.media_type = media_type
        self.codec = codec
        self.view = view
        self.source = source


class SessionState:
    """Shared state for the whole app. Created once by App.__init__."""

    def __init__(self):
        os.makedirs(KEYS_DIR, exist_ok=True)
        os.makedirs(OUTBOX_DIR, exist_ok=True)
        os.makedirs(INBOX_DIR, exist_ok=True)

        self.bits = A1BitstreamAdapter()
        self.image_codec = ImageCodecAdapter()
        self.audio_codec = AudioCodecAdapter()

        self._keys: dict[str, tuple] = {}          # algo -> (priv, pub, pub_path)

        # cross-tab handoffs
        self.last_protect = None                    # a2_crypto.ProtectResult
        self.last_protect_cover: CoverHandle | None = None
        self.last_protect_stego: CoverHandle | None = None
        self.last_protect_params: dict | None = None  # media_id/n_lsb/passphrase/algo used

    def codec_for(self, media_type: str):
        return self.image_codec if media_type == "image" else self.audio_codec

    # -- keys -----------------------------------------------------------
    def keys_for(self, algo: str):
        """
        Load (generating on first use) the demo keypair for one signing
        algorithm. The default algorithm reuses the unsuffixed demo_*.pem
        files already committed under keys/; other algorithms get their own
        suffixed pair, same convention a2_debug_gui.py uses.
        """
        if algo in self._keys:
            return self._keys[algo]
        if algo == a2.DEFAULT_SIGN_ALGO:
            priv_path = os.path.join(KEYS_DIR, "demo_private.pem")
            pub_path = os.path.join(KEYS_DIR, "demo_public.pem")
        else:
            priv_path = os.path.join(KEYS_DIR, "demo_private_{}.pem".format(algo))
            pub_path = os.path.join(KEYS_DIR, "demo_public_{}.pem".format(algo))
        if not os.path.exists(priv_path):
            a2.save_keypair(a2.generate_keypair(algo), priv_path, pub_path)
        priv = a2.load_private(priv_path)
        pub = a2.load_public(pub_path)
        self._keys[algo] = (priv, pub, pub_path)
        return self._keys[algo]

    def impostor_public_path(self, algo: str) -> str:
        """A public key that never verifies against the demo private key - the Wrong-Key case."""
        if algo == a2.DEFAULT_SIGN_ALGO:
            priv_path = os.path.join(KEYS_DIR, "impostor_private.pem")
            pub_path = os.path.join(KEYS_DIR, "impostor_public.pem")
        else:
            priv_path = os.path.join(KEYS_DIR, "impostor_private_{}.pem".format(algo))
            pub_path = os.path.join(KEYS_DIR, "impostor_public_{}.pem".format(algo))
        if not os.path.exists(pub_path):
            a2.save_keypair(a2.generate_keypair(algo), priv_path, pub_path)
        return pub_path
