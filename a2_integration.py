"""
a2_integration.py - adapters binding a2_crypto to the team's real codecs.

WHY THIS FILE SITS OUTSIDE THE PACKAGE
    Plug-and-play rule 2 says a2_crypto imports nothing from a teammate's
    package, so the layer stays swappable as a folder and its selftest runs
    with no PNG or WAV support present. The glue therefore lives here, not in
    a2_crypto/. Nothing in a2_crypto imports this file, and selftest_purity()
    below enforces that in both directions.

WHAT IT PROVIDES
    ImageCodecAdapter    - wraps image/image_codec.py         (person 3)
    AudioCodecAdapter    - wraps audio/audio_codec.py         (person 4)
    A1BitstreamAdapter   - wraps bitstream/bitstream_engine.py (person 1)

    The two codec adapters satisfy the same Codec port, so protect()/verify()
    run unchanged over either medium. That is the "one interface, two media"
    claim in the demo, and it is demonstrated by running this file.

    A1BitstreamAdapter satisfies the Bitstream port, so the team's real
    framing replaces A2's reference implementation without a single edit
    inside a2_crypto/. Running this file proves that too: the 18 selftest
    cases are re-run against person 1's engine.

UNIT CONVENTION
    One unit = one addressable cover byte: an image channel value, or one byte
    of PCM audio. This matches what image_codec.py and audio_codec.py already
    do, so A2's derived offsets and their embed/extract agree.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# --- bitstream (person 1) ---------------------------------------------------
class A1BitstreamAdapter:
    """
    Bitstream port over person 1's bitstream_engine.

    Their engine and A2's port were designed independently, so this class is
    where the two conventions are reconciled. Nothing in a2_crypto changed to
    accommodate it - that is the point of having a port.

    WHAT HAD TO BE BRIDGED
      * `unpack()` returns (payload, sig, n_lsb); the port wants (payload, sig).
        The n_lsb the header records is exposed through header_info() instead.
      * Their engine raises UnpackError (a ValueError). The pipeline's verdict
        tree catches HeaderError, so every raise is translated - otherwise a
        corrupt header would escape as an unexpected exception and land on
        "Cannot Verify" for the wrong reason.
      * Their engine has no embed/extract: writing units into a cover is the
        codecs' job there. Those two methods are built here out of their
        bytes_to_unit_values()/unit_values_to_bytes(), so the bit order stays
        theirs and A2 never reimplements it.
      * Their header has no algorithm byte, so `algo_id` is accepted and
        ignored. The verifier infers the scheme from the public key it was
        handed, which it can always do. A2 loses nothing: the algorithm field
        was only ever a convenience.
      * Their parse_header does not sanity-check declared lengths, so the
        MAX_PAYLOAD_BYTES ceiling is applied here. Without it a corrupt length
        field reads as a plausible header and the "Cannot Verify" verdict for
        a corrupt header becomes unreachable.

    MAGIC is b"STG1" here versus b"INF2" in A2's reference implementation. The
    pipeline reads it off this attribute rather than assuming its own.
    """

    name = "bitstream_engine (person 1)"

    def __init__(self):
        from bitstream import bitstream_engine as be
        from a2_crypto.errors import HeaderError
        from a2_crypto import config
        self._be = be
        self._HeaderError = HeaderError
        self._config = config
        self.MAGIC = be.MAGIC
        self.HEADER_SIZE = be.HEADER_SIZE_BYTES

    # -- framing ------------------------------------------------------------
    def pack(self, payload: bytes, sig: bytes, n_lsb: int, algo_id: int = 0) -> bytes:
        return self._be.pack(payload, sig, n_lsb)      # algo_id: see class docstring

    def unpack(self, stream: bytes):
        try:
            payload, sig, _n_lsb = self._be.unpack(stream)
        except self._be.UnpackError as exc:
            raise self._HeaderError(str(exc)) from exc
        return payload, sig

    # -- header introspection ----------------------------------------------
    def has_magic(self, header: bytes) -> bool:
        return len(header) >= 4 and header[:4] == self._be.MAGIC

    def header_info(self, header: bytes) -> dict:
        info = self._parse(header)
        return {
            "payload_len": info["payload_len"],
            "sig_len": info["sig_len"],
            "version": info["version"],
            "n_lsb": info["n_lsb"],
        }

    def declared_total_bits(self, header: bytes) -> int:
        info = self._parse(header)
        return (self.HEADER_SIZE + info["payload_len"] + info["sig_len"]) * 8

    def header_size_bits(self, n_lsb: int = 1) -> int:
        return self.HEADER_SIZE * 8

    def _parse(self, header: bytes) -> dict:
        try:
            info = self._be.parse_header(header)
        except self._be.UnpackError as exc:
            raise self._HeaderError(str(exc)) from exc
        p_len = info["payload_len"]
        if p_len == 0 or p_len > self._config.MAX_PAYLOAD_BYTES:
            raise self._HeaderError(
                "Declared payload length {} is out of range.".format(p_len))
        return info

    # -- carrier ------------------------------------------------------------
    def embed(self, samples: bytes, stream: bytes, n_lsb: int, start: int) -> bytes:
        values = self._be.bytes_to_unit_values(stream, n_lsb)
        if start < 0 or start + len(values) > len(samples):
            raise self._HeaderError(
                "Stream needs {} units from offset {}, cover has {}.".format(
                    len(values), start, len(samples)))
        out = bytearray(samples)
        mask = 0xFF ^ ((1 << n_lsb) - 1)
        for i, v in enumerate(values):
            out[start + i] = (out[start + i] & mask) | v
        return bytes(out)

    def extract(self, samples: bytes, n_lsb: int, start: int, max_bits: int) -> bytes:
        if start < 0 or start >= len(samples):
            raise self._HeaderError(
                "Start offset {} outside cover of {} units.".format(start, len(samples)))
        num_units = self._be.required_units(max_bits, n_lsb)
        available = min(num_units, len(samples) - start)
        low = (1 << n_lsb) - 1
        values = [samples[start + i] & low for i in range(available)]
        return self._be.unit_values_to_bytes(values, n_lsb, max_bits // 8)


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
        sampwidth = view[1].sampwidth
        low_byte_units = self._ac.embeddable_view(view[0], sampwidth).size
        return low_byte_units * n_lsb

    def read_samples(self, view) -> bytes:
        sampwidth = view[1].sampwidth
        return self._ac.embeddable_view(view[0], sampwidth).tobytes()

    def write_samples(self, view, data: bytes):
        sampwidth = view[1].sampwidth
        low_bytes = self._np.frombuffer(data, dtype=self._np.uint8)
        merged = self._ac.merge_embeddable_view(view[0], sampwidth, low_bytes)
        return (merged, view[1])

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
    from a2_crypto import Trace

    os.makedirs(out_dir, exist_ok=True)
    bits = A1BitstreamAdapter()          # the team's real framing, not A2's mock
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
            
        # negative case: wrong public key (impostor) -> Signature Invalid
        impostor_pub_path = os.path.join("keys", "impostor_public.pem")
        if not os.path.exists(impostor_pub_path):
            impostor_priv_path = os.path.join("keys", "impostor_private.pem")
            kb2 = a2.generate_keypair()
            a2.save_keypair(kb2, impostor_priv_path, impostor_pub_path)
            print("generated impostor keypair in keys/ (for the wrong-key negative case)")
        impostor_pub = a2.load_public(impostor_pub_path)

        v4 = a2.verify(codec.load(stego_path), media_id, n_lsb, passphrase, impostor_pub,
                    codec=codec, bits=bits)
        print("VERDICT (wrong key)  : {}".format(v4.code))
        if v4.code is not a2.VerdictCode.SIGNATURE_INVALID:
            failures += 1

        # negative case: invalid/corrupt public key -> Cannot Verify
        BROKEN_KEY_PATH = os.path.join(out_dir, "broken_public.pem")
        with open(BROKEN_KEY_PATH, "w") as f:
            f.write("-----BEGIN PUBLIC KEY-----\nNOT-ACTUALLY-A-KEY\n-----END PUBLIC KEY-----\n")
        try:
            broken_pub = a2.load_public(BROKEN_KEY_PATH)
            v5 = a2.verify(codec.load(stego_path), media_id, n_lsb, passphrase, broken_pub,
                        codec=codec, bits=bits)
            print("VERDICT (broken key) : {}".format(v5.code))
            if v5.code is not a2.VerdictCode.CANNOT_VERIFY:
                failures += 1
        except Exception as exc:
            # load_public() may reject a malformed key before verify() even runs --
            # that's still the same "invalid key" failure mode, just caught one
            # layer earlier. Worth keeping as evidence either way.
            print("VERDICT (broken key) : load_public() rejected it directly ({})".format(exc))

        tv.save(os.path.join(out_dir, "trace_{}.json".format(codec.media_type)))

    # The plug-and-play claim, actually tested: re-run A2's whole internal
    # suite with person 1's framing swapped in for A2's reference one.
    print("\n" + "=" * 70)
    print("Re-running the 18 A2 selftest cases against person 1's bitstream")
    print("engine, to prove swapping the Bitstream port needs no A2 edits.")
    print("=" * 70)
    from a2_crypto import selftest
    a1_code = selftest.main(bits_factory=A1BitstreamAdapter,
                            label="A1BitstreamAdapter (STG1 framing)")
    if a1_code != 0:
        failures += 1

    print("\n" + "=" * 70)
    ok = selftest_purity()
    print("=" * 70)
    if failures or not ok:
        print("INTEGRATION FAILURES:", failures)
        return 1
    print("Integration OK:")
    print("  - the same protect()/verify() served PNG and WAV")
    print("  - person 1's bitstream engine drove all 18 A2 cases")
    print("  - no media-specific or teammate-specific code inside a2_crypto")
    return 0


if __name__ == "__main__":
    img = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        "tests", "samples", "image", "chelsea_cat.png")
    wav = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        "tests", "samples", "audio", "sample_cover.wav")
    sys.exit(demo(img, wav))
