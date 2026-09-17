"""
a2_integration.py - adapters binding a2_crypto to the team's real codecs.

WHY THIS FILE SITS OUTSIDE THE PACKAGE
    Plug-and-play rule 2 says a2_crypto imports nothing from a teammate's
    package, so the layer stays swappable as a folder and its selftest runs
    with no PNG or WAV support present. The glue therefore lives here, not in
    a2_crypto/. Nothing in a2_crypto imports this file, and selftest_purity()
    below enforces that in both directions.

WHAT IT PROVIDES
    ImageCodecAdapter  - wraps image/image_codec.py   (person 3)
    AudioCodecAdapter  - wraps audio/audio_codec.py   (person 4)

    Both satisfy the same Codec port, so protect()/verify() run unchanged over
    either medium. That is the "one interface, two media" claim in the demo,
    and it is demonstrated by running this file.

UNIT CONVENTION
    One unit = one addressable cover byte: an image channel value, or one byte
    of PCM audio. This matches what image_codec.py and audio_codec.py already
    do, so A2's derived offsets and their embed/extract agree.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# --- image ------------------------------------------------------------------
class ImageCodecAdapter:
    """Codec port over person 3's PNG codec. CoverView is a numpy uint8 array."""

    media_type = "image"
    name = "image_codec (PNG)"

    def __init__(self):
        from image import image_codec
        import numpy as np
        self._ic = image_codec
        self._np = np

    def load(self, path: str):
        return self._ic.load_image(path)

    def save(self, view, path: str) -> None:
        self._ic.save_image(view, path)

    def capacity_bits(self, view, n_lsb: int) -> int:
        return int(view.size) * n_lsb

    def read_samples(self, view) -> bytes:
        return view.tobytes()

    def write_samples(self, view, data: bytes):
        arr = self._np.frombuffer(data, dtype=self._np.uint8)
        return arr.reshape(view.shape).copy()      # new array, never mutates

    # -- extras the GUI uses, not part of the port --------------------------
    def compare(self, cover, stego) -> dict:
        return self._ic.compare_images(cover, stego)

    def diff_image(self, cover, stego, amplify: int = 32):
        return self._ic.make_diff_image(cover, stego, amplify)


# --- audio ------------------------------------------------------------------
class AudioCodecAdapter:
    """
    Codec port over person 4's WAV codec. CoverView is an (array, params)
    tuple, because a WAV cannot be written back without its frame parameters.
    A2 treats the view as opaque, so the tuple costs the pipeline nothing.
    """

    media_type = "audio"
    name = "audio_codec (WAV/PCM)"

    def __init__(self):
        from audio import audio_codec
        import numpy as np
        self._ac = audio_codec
        self._np = np

    def load(self, path: str):
        arr, params = self._ac.load_audio(path)
        return (arr, params)

    def save(self, view, path: str) -> None:
        arr, params = view
        self._ac.save_audio(arr, params, path)

    def capacity_bits(self, view, n_lsb: int) -> int:
        return int(view[0].size) * n_lsb

    def read_samples(self, view) -> bytes:
        return view[0].tobytes()

    def write_samples(self, view, data: bytes):
        arr = self._np.frombuffer(data, dtype=self._np.uint8).copy()
        return (arr, view[1])

    # -- extras the GUI uses, not part of the port --------------------------
    def compare(self, cover, stego) -> dict:
        return self._ac.compare_audio(cover[0], stego[0])

    def waveform(self, view):
        return self._ac.samples_for_waveform(view[0], view[1])


# --- purity check -----------------------------------------------------------
def selftest_purity() -> bool:
    """
    Proves the "a2_crypto has zero imports from teammates' packages" item on
    the definition-of-done list, by reading the source rather than trusting it.
    """
    import re
    pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a2_crypto")
    banned = ("image", "audio", "payload_temp", "image_codec", "audio_codec",
              "PIL", "numpy", "a2_integration")
    bad = []
    pattern = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", re.M)
    for fn in sorted(os.listdir(pkg)):
        if not fn.endswith(".py"):
            continue
        src = open(os.path.join(pkg, fn), encoding="utf-8").read()
        for mod in pattern.findall(src):
            if mod.split(".")[0] in banned:
                bad.append("{}: imports {}".format(fn, mod))
    if bad:
        print("PURITY FAIL:")
        for b in bad:
            print("   ", b)
        return False
    print("PURITY PASS: a2_crypto imports nothing from teammate packages,")
    print("             PIL or numpy - only stdlib plus `cryptography`.")
    return True


# --- demonstration ----------------------------------------------------------
def demo(image_path: str, audio_path: str, out_dir: str = "a2_out") -> int:
    """
    Run the identical A2 pipeline over a real PNG and a real WAV.

        python a2_integration.py

    This is demo point 5: one interface, two media, no branch in the crypto
    layer.
    """
    import a2_crypto as a2
    from a2_crypto import ReferenceBitstream, Trace

    os.makedirs(out_dir, exist_ok=True)
    bits = ReferenceBitstream()
    passphrase = "team-P1-4-shared-passphrase"

    priv_path = os.path.join("keys", "demo_private.pem")
    pub_path = os.path.join("keys", "demo_public.pem")
    if not os.path.exists(priv_path):
        kb = a2.generate_keypair()
        a2.save_keypair(kb, priv_path, pub_path)
        print("generated demo keypair in keys/")
    priv, pub = a2.load_private(priv_path), a2.load_public(pub_path)

    message = ("Explain how steganography can be used to embed hidden "
               "verification data in image and audio cover objects.")

    failures = 0
    for adapter_cls, path, media_id, n_lsb in (
        (ImageCodecAdapter, image_path, "IMG-0007", 2),
        (AudioCodecAdapter, audio_path, "AUD-0003", 2),
    ):
        codec = adapter_cls()
        print("\n" + "=" * 70)
        print("{}  <-  {}".format(codec.name, path))
        print("=" * 70)

        cover = codec.load(path)
        rep = a2.capacity_report(codec, cover, n_lsb, message)
        print("capacity: {:,} bits raw, {:,} usable, need {:,} ({}%) -> {}".format(
            rep["capacity_bits"], rep["usable_bits"], rep["needed_bits"],
            rep["utilisation_percent"], "FITS" if rep["fits"] else "TOO BIG"))

        tp = Trace("protect")
        res = a2.protect(cover, message, media_id, n_lsb, passphrase, priv,
                         codec=codec, bits=bits,
                         media_type=codec.media_type, trace=tp)
        stego_path = os.path.join(out_dir, "stego_" + os.path.basename(path))
        codec.save(res.stego_view, stego_path)
        print("derived start offset : {:,} (never stored in the file)".format(res.start_unit))
        print("embedded stream      : {:,} bytes".format(res.stream_bytes))
        print("cover bytes changed  : {:,} ({}%)".format(
            res.details["changed_bytes"],
            round(100 * res.details["changed_bytes"] / len(codec.read_samples(cover)), 3)))
        print("comparison           :", codec.compare(cover, res.stego_view))
        print("written              :", stego_path)

        tv = Trace("verify")
        v = a2.verify(codec.load(stego_path), media_id, n_lsb, passphrase, pub,
                      codec=codec, bits=bits, trace=tv)
        print("VERDICT (round trip) : {}".format(v.code))
        if not v.ok:
            print("   reason:", v.reason)
            failures += 1

        # negative case: tamper with real content, not the LSB planes
        tampered = codec.load(stego_path)
        sam = bytearray(codec.read_samples(tampered))
        for i in range(0, min(4000, len(sam)), 7):
            sam[i] ^= 0x40                     # visible/audible change
        v2 = a2.verify(codec.write_samples(tampered, bytes(sam)), media_id,
                       n_lsb, passphrase, pub, codec=codec, bits=bits)
        print("VERDICT (tampered)   : {}".format(v2.code))
        if v2.code is not a2.VerdictCode.TAMPERED:
            failures += 1

        # negative case: wrong passphrase
        v3 = a2.verify(codec.load(stego_path), media_id, n_lsb,
                       "wrong-passphrase", pub, codec=codec, bits=bits)
        print("VERDICT (wrong pass) : {}".format(v3.code))
        if v3.code is not a2.VerdictCode.WRONG_START_LOCATION:
            failures += 1

        tv.save(os.path.join(out_dir, "trace_{}.json".format(codec.media_type)))

    print("\n" + "=" * 70)
    ok = selftest_purity()
    print("=" * 70)
    if failures or not ok:
        print("INTEGRATION FAILURES:", failures)
        return 1
    print("Integration OK - the same protect()/verify() served PNG and WAV")
    print("with no media-specific code in a2_crypto.")
    return 0


if __name__ == "__main__":
    img = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        "tests", "samples", "image", "chelsea_cat.png")
    wav = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        "tests", "samples", "audio", "sample_cover.wav")
    sys.exit(demo(img, wav))
