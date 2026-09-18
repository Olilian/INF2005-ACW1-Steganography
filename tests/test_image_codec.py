"""
Required test cases for the image codec, run
through the REAL crypto/bitstream pipeline (a2_crypto + a2_integration),
plus an LSB-depth sweep (1-8) demonstrating selectable bit depth.
"""
import os
import sys
import numpy as np
from PIL import Image

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import a2_crypto as a2
from a2_crypto import Trace, VerdictCode
from a2_integration import ImageCodecAdapter, A1BitstreamAdapter

SAMPLES_DIR = os.path.join(REPO_ROOT, "tests", "samples", "image")
EVIDENCE_DIR = os.path.join(REPO_ROOT, "tests", "test_evidence", "image")
SWEEP_DIR = os.path.join(EVIDENCE_DIR, "lsb_sweep")
KEYS_DIR = os.path.join(REPO_ROOT, "keys")

COVER_PATH = os.path.join(SAMPLES_DIR, "chelsea_cat.png")
PRIV_PATH = os.path.join(KEYS_DIR, "demo_private.pem")
PUB_PATH = os.path.join(KEYS_DIR, "demo_public.pem")
IMPOSTOR_PUB_PATH = os.path.join(KEYS_DIR, "impostor_public.pem")

MEDIA_ID = "IMG-TEST-001"
N_LSB = 2
PASSPHRASE = "team-P1-4-shared-passphrase"
LSB_DEPTHS = [1, 2, 3, 4, 5, 6, 7, 8]

SHORT_MESSAGE = (
    "Explain how steganography can be used to embed hidden verification "
    "data in image and audio cover objects."
)
LARGE_MESSAGE = (
    "This undergraduate project requires student teams to design, "
    "implement and demonstrate a GUI-based LSB Replacement steganography "
    "program (window-based or web-based) that protects and verifies both "
    "image and audio cover objects using steganography, hashing and "
    "digital signatures. The project focuses on practical cybersecurity "
    "concepts: hiding a verification payload inside an image and an audio "
    "file, signing relevant verification data, extracting the hidden "
    "payload, checking the digital signature, and demonstrating positive "
    "and negative verification cases."
)
CUSTOM_MESSAGE = (
    "CONFIDENTIAL RELEASE NOTE - Build v1.0.3, cleared for release "
    "2026-09-15. Do not distribute prior to embargo lift."
)


def _ensure_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not (os.path.exists(PRIV_PATH) and os.path.exists(PUB_PATH)):
        kb = a2.generate_keypair()
        a2.save_keypair(kb, PRIV_PATH, PUB_PATH)
        print("Generated demo keypair ->", KEYS_DIR)
    if not os.path.exists(IMPOSTOR_PUB_PATH):
        kb2 = a2.generate_keypair()
        a2.save_keypair(kb2, os.path.join(KEYS_DIR, "impostor_private.pem"), IMPOSTOR_PUB_PATH)
        print("Generated impostor keypair (for the Signature Invalid case) ->", KEYS_DIR)


def run_required_cases(codec, bits, priv, pub, impostor_pub, cover):
    print("== Setup ==")
    print(f"Using {COVER_PATH}, shape {cover.shape}")
    rep = a2.capacity_report(codec, cover, N_LSB, SHORT_MESSAGE)
    print("Capacity:", rep)
    assert rep["fits"], "Short message unexpectedly does not fit: check cover size / n_lsb"

    print("\n== Positive case: protect + verify ==")
    stego_path = os.path.join(EVIDENCE_DIR, "image_stego.png")
    tp = Trace("image_protect")
    result = a2.protect(cover, SHORT_MESSAGE, MEDIA_ID, N_LSB, PASSPHRASE, priv,
                         codec=codec, bits=bits, media_type="image", trace=tp)
    codec.save(result.stego_view, stego_path)
    tp.save(os.path.join(EVIDENCE_DIR, "trace_protect_positive.json"))
    print("Protected OK ->", stego_path)
    print("start_unit:", result.start_unit, " stream_bytes:", result.stream_bytes)

    tv = Trace("image_verify")
    v = a2.verify(codec.load(stego_path), MEDIA_ID, N_LSB, PASSPHRASE, pub,
                  codec=codec, bits=bits, trace=tv)
    tv.save(os.path.join(EVIDENCE_DIR, "trace_verify_positive.json"))
    print("Verdict:", v.code, "-", v.reason)
    print("Recovered message:", v.message_text())
    assert v.code == VerdictCode.AUTHENTIC, "Expected Authentic on clean round-trip"
    assert v.message_text() == SHORT_MESSAGE, "Decrypted message doesn't match what was sent"

    print("\n== Before/after comparison + diff image ==")
    stego_view = codec.load(stego_path)
    stats = codec.compare(cover, stego_view)
    print("Compare stats:", stats)
    diff_arr = codec.diff_image(cover, stego_view)
    Image.fromarray(diff_arr).save(os.path.join(EVIDENCE_DIR, "image_diff.png"))

    print("\n== Negative case: tampering (content changed after signing) ==")
    tampered = codec.load(stego_path)
    samples = bytearray(codec.read_samples(tampered))
    for i in range(max(0, len(samples) - 3000), len(samples)):
        samples[i] ^= 0xFF
    tampered_view = codec.write_samples(tampered, bytes(samples))
    tampered_path = os.path.join(EVIDENCE_DIR, "image_tampered.png")
    codec.save(tampered_view, tampered_path)

    v_tamper = a2.verify(codec.load(tampered_path), MEDIA_ID, N_LSB, PASSPHRASE, pub,
                          codec=codec, bits=bits)
    print("Verdict:", v_tamper.code, "-", v_tamper.reason)
    assert v_tamper.code == VerdictCode.TAMPERED, "Expected Tampered after flipping cover bytes"

    print("\n== Negative case: wrong passphrase -> Wrong Start Location ==")
    v_wrong_loc = a2.verify(codec.load(stego_path), MEDIA_ID, N_LSB, "wrong-passphrase", pub,
                             codec=codec, bits=bits)
    print("Verdict:", v_wrong_loc.code, "-", v_wrong_loc.reason)
    assert v_wrong_loc.code == VerdictCode.WRONG_START_LOCATION

    print("\n== Negative case: wrong public key -> Signature Invalid ==")
    v_sig = a2.verify(codec.load(stego_path), MEDIA_ID, N_LSB, PASSPHRASE, impostor_pub,
                       codec=codec, bits=bits)
    print("Verdict:", v_sig.code, "-", v_sig.reason)
    assert v_sig.code == VerdictCode.SIGNATURE_INVALID

    print("\n== Negative case: capacity check failure ==")
    tiny = np.zeros((2, 2, 3), dtype=np.uint8)
    tiny_path = os.path.join(EVIDENCE_DIR, "image_tiny.png")
    Image.fromarray(tiny).save(tiny_path)
    tiny_cover = codec.load(tiny_path)
    try:
        a2.protect(tiny_cover, SHORT_MESSAGE, MEDIA_ID, N_LSB, PASSPHRASE, priv,
                   codec=codec, bits=bits, media_type="image")
        print("UNEXPECTED: capacity check did not fail")
    except a2.CapacityError as exc:
        print("Correctly rejected:", exc)

    print("\n== Required case: varying payload sizes ==")
    for label, message in (("short", SHORT_MESSAGE), ("large", LARGE_MESSAGE), ("custom", CUSTOM_MESSAGE)):
        out_path = os.path.join(EVIDENCE_DIR, f"image_stego_{label}.png")
        res = a2.protect(cover, message, f"IMG-SIZE-{label.upper()}", N_LSB, PASSPHRASE, priv,
                          codec=codec, bits=bits, media_type="image")
        codec.save(res.stego_view, out_path)
        v = a2.verify(codec.load(out_path), f"IMG-SIZE-{label.upper()}", N_LSB, PASSPHRASE, pub,
                      codec=codec, bits=bits)
        print(f"[{label}] chars={len(message)} stream_bytes={res.stream_bytes} verdict={v.code}")
        assert v.code == VerdictCode.AUTHENTIC, f"Expected Authentic for {label} payload"
        assert v.message_text() == message

    print("\nAll required image test cases passed.")


def run_lsb_sweep(codec, bits, priv, pub, cover):
    print("\n\n== LSB depth sweep (1-8): demonstrates selectable bit depth ==")
    os.makedirs(SWEEP_DIR, exist_ok=True)
    print(f"{'n_lsb':>5} | {'usable_bits':>11} | {'changed_px':>10} | {'% changed':>9} | {'max_delta':>9} | verdict")
    print("-" * 70)

    for n_lsb in LSB_DEPTHS:
        stego_path = os.path.join(SWEEP_DIR, f"image_stego_lsb{n_lsb}.png")
        diff_path = os.path.join(SWEEP_DIR, f"image_diff_lsb{n_lsb}.png")

        rep = a2.capacity_report(codec, cover, n_lsb, SHORT_MESSAGE)
        result = a2.protect(cover, SHORT_MESSAGE, "IMG-LSB-SWEEP", n_lsb, PASSPHRASE, priv,
                             codec=codec, bits=bits, media_type="image")
        codec.save(result.stego_view, stego_path)

        stego_view = codec.load(stego_path)
        stats = codec.compare(cover, stego_view)
        diff_arr = codec.diff_image(cover, stego_view)
        Image.fromarray(diff_arr).save(diff_path)

        v = a2.verify(stego_view, "IMG-LSB-SWEEP", n_lsb, PASSPHRASE, pub, codec=codec, bits=bits)

        print(f"{n_lsb:>5} | {rep['usable_bits']:>11,} | {stats['changed_pixels']:>10,} | "
              f"{stats['percent_changed']:>8}% | {stats['max_channel_delta']:>9} | {v.code}")
        assert v.code == VerdictCode.AUTHENTIC, f"n_lsb={n_lsb} failed round-trip"

    print(f"\nAll {len(LSB_DEPTHS)} depths verified Authentic.")
    print(f"Stego + diff images for each depth saved in: {SWEEP_DIR}")


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    _ensure_keys()

    codec = ImageCodecAdapter()
    bits = A1BitstreamAdapter()
    priv = a2.load_private(PRIV_PATH)
    pub = a2.load_public(PUB_PATH)
    impostor_pub = a2.load_public(IMPOSTOR_PUB_PATH)
    cover = codec.load(COVER_PATH)

    run_required_cases(codec, bits, priv, pub, impostor_pub, cover)
    run_lsb_sweep(codec, bits, priv, pub, cover)


if __name__ == "__main__":
    main()