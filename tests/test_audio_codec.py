"""
tests/test_audio_codec.py - required test cases for the audio codec, run
through the REAL crypto/bitstream pipeline (a2_crypto + a2_integration).
Mirrors tests/test_image_codec.py's structure so both media types are
exercised the same way.

Run from anywhere (repo root, this folder, an IDE's Run button, etc.):
    python tests/test_audio_codec.py
    (or, from inside tests/):  python test_audio_codec.py
"""
import os
import sys
import wave

import numpy as np
from PIL import Image, ImageDraw

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import a2_crypto as a2
from a2_crypto import Trace, VerdictCode
from a2_integration import AudioCodecAdapter, A1BitstreamAdapter

SAMPLES_DIR = os.path.join(REPO_ROOT, "tests", "samples", "audio")
EVIDENCE_DIR = os.path.join(REPO_ROOT, "tests", "test_evidence", "audio")
KEYS_DIR = os.path.join(REPO_ROOT, "keys")

COVER_PATH = os.path.join(SAMPLES_DIR, "sample_cover.wav")
PRIV_PATH = os.path.join(KEYS_DIR, "demo_private.pem")
PUB_PATH = os.path.join(KEYS_DIR, "demo_public.pem")
IMPOSTOR_PUB_PATH = os.path.join(KEYS_DIR, "impostor_public.pem")

MEDIA_ID = "AUD-TEST-001"
N_LSB = 2
PASSPHRASE = "team-P1-4-shared-passphrase"
LSB_DEPTHS = [1, 2, 3, 4, 5, 6, 7, 8]
SWEEP_REPORT_PATH = os.path.join(EVIDENCE_DIR, "audio_lsb_sweep.txt")

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


def _make_tiny_wav(path, n_frames=4, sampwidth=2, framerate=8000):
    """Tiny WAV for the capacity-failure case, same role as the 2x2 PNG in the image test."""
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        wf.writeframes(np.zeros(n_frames, dtype=np.int16).tobytes())


def _save_waveform_compare(cover_wave, stego_wave, path, n_samples=2000):
    """Cover vs stego waveform, drawn with Pillow so the evidence image is
    always produced (the previous matplotlib version silently skipped it
    when matplotlib wasn't installed)."""
    width, panel_h, pad = 1000, 200, 24
    img = Image.new("RGB", (width, 2 * panel_h), "white")
    d = ImageDraw.Draw(img)
    cover, stego = cover_wave[:n_samples], stego_wave[:n_samples]
    peak = float(max(1, np.abs(cover).max(), np.abs(stego).max()))
    for i, (title, wave) in enumerate((("Cover (first {} samples)", cover),
                                       ("Stego (first {} samples)", stego))):
        top = i * panel_h
        mid = top + pad + (panel_h - pad) / 2
        half = (panel_h - pad) / 2 - 4
        d.text((8, top + 4), title.format(len(wave)), fill="black")
        d.line([(0, mid), (width, mid)], fill="#dddddd")
        pts = [(x * width / max(1, len(wave) - 1), mid - float(s) / peak * half)
               for x, s in enumerate(wave)]
        d.line(pts, fill="#1f77b4", width=1)
    img.save(path)


def run_required_cases(codec, bits, priv, pub, impostor_pub, cover):
    print("== Setup ==")
    print(f"Using {COVER_PATH}")
    rep = a2.capacity_report(codec, cover, N_LSB, SHORT_MESSAGE)
    print("Capacity:", rep)
    assert rep["fits"], "Short message unexpectedly does not fit: check cover size / n_lsb"

    print("\n== Positive case: protect + verify ==")
    stego_path = os.path.join(EVIDENCE_DIR, "audio_stego.wav")
    tp = Trace("audio_protect")
    result = a2.protect(cover, SHORT_MESSAGE, MEDIA_ID, N_LSB, PASSPHRASE, priv,
                        codec=codec, bits=bits, media_type="audio", trace=tp)
    codec.save(result.stego_view, stego_path)
    tp.save(os.path.join(EVIDENCE_DIR, "trace_protect_positive.json"))
    print("Protected OK ->", stego_path)
    print("start_unit:", result.start_unit, " stream_bytes:", result.stream_bytes)

    tv = Trace("audio_verify")
    v = a2.verify(codec.load(stego_path), MEDIA_ID, N_LSB, PASSPHRASE, pub,
                 codec=codec, bits=bits, trace=tv)
    tv.save(os.path.join(EVIDENCE_DIR, "trace_verify_positive.json"))
    print("Verdict:", v.code, "-", v.reason)
    print("Recovered message:", v.message_text())
    assert v.code == VerdictCode.AUTHENTIC, "Expected Authentic on clean round-trip"
    assert v.message_text() == SHORT_MESSAGE, "Decrypted message doesn't match what was sent"

    print("\n== Before/after comparison + waveform ==")
    cover_arr, cover_params = cover
    stego_view = codec.load(stego_path)
    stego_arr, stego_params = stego_view
    stats = codec.compare(cover, stego_view)
    print("Compare stats:", stats)

    waveform_path = os.path.join(EVIDENCE_DIR, "audio_waveform_compare.png")
    _save_waveform_compare(codec.waveform(cover), codec.waveform(stego_view), waveform_path)
    print("Saved waveform comparison ->", waveform_path)

    print("\n== Negative case: tampering (content changed after signing) ==")
    tampered_view = codec.load(stego_path)
    samples = bytearray(codec.read_samples(tampered_view))
    for i in range(max(0, len(samples) - 3000), len(samples)):
        samples[i] ^= 0xFF
    tampered_view = codec.write_samples(tampered_view, bytes(samples))
    tampered_path = os.path.join(EVIDENCE_DIR, "audio_tampered.wav")
    codec.save(tampered_view, tampered_path)

    v_tamper = a2.verify(codec.load(tampered_path), MEDIA_ID, N_LSB, PASSPHRASE, pub,
                         codec=codec, bits=bits)
    print("Verdict:", v_tamper.code, "-", v_tamper.reason)
    assert v_tamper.code == VerdictCode.TAMPERED, "Expected Tampered after flipping cover bytes"

    print("\n== Negative case: HIGH-byte-only tampering (integrity coverage) ==")
    # Every other tamper case in this file mutates through read_samples(),
    # which for WAV/PCM narrows to the LOW byte of each sample - the only
    # bytes the carrier is allowed to touch. That means those cases can only
    # ever exercise bytes the digest already covered, and a hole in the OTHER
    # half of the file was invisible to the whole suite.
    #
    # This case goes around read_samples() on purpose and rewrites only the
    # HIGH bytes, which carry no payload but hold most of each sample's
    # amplitude. It turns the audio into noise without disturbing a single
    # embedded bit, so the payload still extracts and its signature still
    # verifies - only the cover hash can catch it. Before digest_samples()
    # existed this returned Authentic.
    high_view = codec.load(stego_path)
    high_arr, high_params = high_view
    smashed = high_arr.copy()
    if high_params.sampwidth > 1:
        for off in range(1, high_params.sampwidth):
            smashed[off::high_params.sampwidth] ^= 0x55
        assert not np.array_equal(smashed, high_arr), "high-byte tamper changed nothing"
        v_high = a2.verify((smashed, high_params), MEDIA_ID, N_LSB, PASSPHRASE, pub,
                           codec=codec, bits=bits)
        print("Rewrote every high byte ({:,} of {:,} raw bytes, 0 payload bits touched)".format(
            int((smashed != high_arr).sum()), smashed.size))
        print("Verdict:", v_high.code, "-", v_high.reason)
        assert v_high.code == VerdictCode.TAMPERED, (
            "High-byte tampering must be detected: the integrity hash has to cover "
            "the whole medium, not just the bytes the carrier writes into.")
    else:
        print("8-bit PCM: every byte is embeddable, so there are no high bytes. Skipped.")

    print("\n== Negative case: wrong passphrase -> Wrong Start Location ==")
    v_wrong_loc = a2.verify(codec.load(stego_path), MEDIA_ID, N_LSB, "wrong-passphrase", pub,
                            codec=codec, bits=bits)
    print("Verdict:", v_wrong_loc.code, "-", v_wrong_loc.reason)
    assert v_wrong_loc.code == VerdictCode.WRONG_START_LOCATION

    print("\n== Negative case: wrong public key -> Signature Invalid ==")
    sig_path = os.path.join(EVIDENCE_DIR, "audio_sig_invalid.wav")
    codec.save(codec.load(stego_path), sig_path)
    v_sig = a2.verify(codec.load(sig_path), MEDIA_ID, N_LSB, PASSPHRASE, impostor_pub,
                      codec=codec, bits=bits)
    print("Verdict:", v_sig.code, "-", v_sig.reason)
    assert v_sig.code == VerdictCode.SIGNATURE_INVALID

    print("\n== Negative case: capacity check failure ==")
    tiny_path = os.path.join(EVIDENCE_DIR, "audio_tiny.wav")
    _make_tiny_wav(tiny_path)
    tiny_cover = codec.load(tiny_path)
    try:
        a2.protect(tiny_cover, SHORT_MESSAGE, MEDIA_ID, N_LSB, PASSPHRASE, priv,
                  codec=codec, bits=bits, media_type="audio")
    except a2.CapacityError as exc:
        print("Correctly rejected:", exc)
    else:
        raise AssertionError("Capacity check did not reject a payload larger than the cover")

    print("\n== Required case: varying payload sizes ==")
    for label, message in (("short", SHORT_MESSAGE), ("large", LARGE_MESSAGE), ("custom", CUSTOM_MESSAGE)):
        out_path = os.path.join(EVIDENCE_DIR, f"audio_stego_{label}.wav")
        res = a2.protect(cover, message, f"AUD-SIZE-{label.upper()}", N_LSB, PASSPHRASE, priv,
                         codec=codec, bits=bits, media_type="audio")
        codec.save(res.stego_view, out_path)
        v = a2.verify(codec.load(out_path), f"AUD-SIZE-{label.upper()}", N_LSB, PASSPHRASE, pub,
                     codec=codec, bits=bits)
        print(f"[{label}] chars={len(message)} stream_bytes={res.stream_bytes} verdict={v.code}")
        assert v.code == VerdictCode.AUTHENTIC, f"Expected Authentic for {label} payload"
        assert v.message_text() == message

    print("\nAll required audio test cases passed.")


def run_lsb_sweep(codec, bits, priv, pub, cover):
    """Selectable LSB depth 1-8 on audio, mirroring the image sweep. Only the
    results table is saved (not 8 stego WAVs at 2 MB each)."""
    lines = ["== LSB depth sweep (1-8): demonstrates selectable bit depth ==",
             f"{'n_lsb':>5} | {'usable_bits':>11} | {'changed_bytes':>13} | {'% changed':>9} | "
             f"{'max_delta':>9} | verdict",
             "-" * 72]
    print("\n\n" + "\n".join(lines))

    for n_lsb in LSB_DEPTHS:
        rep = a2.capacity_report(codec, cover, n_lsb, SHORT_MESSAGE)
        result = a2.protect(cover, SHORT_MESSAGE, "AUD-LSB-SWEEP", n_lsb, PASSPHRASE, priv,
                            codec=codec, bits=bits, media_type="audio")
        stats = codec.compare(cover, result.stego_view)
        v = a2.verify(result.stego_view, "AUD-LSB-SWEEP", n_lsb, PASSPHRASE, pub,
                      codec=codec, bits=bits)
        line = (f"{n_lsb:>5} | {rep['usable_bits']:>11,} | {stats['changed_bytes']:>13,} | "
                f"{stats['percent_changed']:>8}% | {stats['max_byte_delta']:>9} | {v.code}")
        print(line)
        lines.append(line)
        assert v.code == VerdictCode.AUTHENTIC, f"n_lsb={n_lsb} failed round-trip"

    lines.append(f"\nAll {len(LSB_DEPTHS)} depths verified Authentic.")
    with open(SWEEP_REPORT_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])
    print("Sweep table saved to:", SWEEP_REPORT_PATH)


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    _ensure_keys()

    codec = AudioCodecAdapter()
    bits = A1BitstreamAdapter()
    priv = a2.load_private(PRIV_PATH)
    pub = a2.load_public(PUB_PATH)
    impostor_pub = a2.load_public(IMPOSTOR_PUB_PATH)
    cover = codec.load(COVER_PATH)

    run_required_cases(codec, bits, priv, pub, impostor_pub, cover)
    run_lsb_sweep(codec, bits, priv, pub, cover)


if __name__ == "__main__":
    main()
