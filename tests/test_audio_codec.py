"""
tests/test_audio_codec.py — sanity check + required test cases for the
audio codec (audio_codec.py + payload_temp.py).

Run from anywhere (repo root, this folder, an IDE's Run button, etc.):
    python tests/test_audio_codec.py
    (or, from inside tests/):  python test_audio_codec.py
"""
import os
import sys
import numpy as np
import wave

# Make the repo root importable regardless of the current working directory
# or how this script is launched (double-click, IDE, different cwd, etc.).
# Without this, `import payload_temp` / `from audio import audio_codec`
# only work if you happen to run the script from exactly the repo root.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from audio import audio_codec as ac
import payload_temp as pt

COVER_PATH = os.path.join(REPO_ROOT, "tests", "samples", "audio", "sample_cover.wav")
EVIDENCE_DIR = os.path.join(REPO_ROOT, "tests", "test_evidence", "audio")

STEGO_PATH = os.path.join(EVIDENCE_DIR, "audio_stego.wav")
TAMPERED_PATH = os.path.join(EVIDENCE_DIR, "audio_tampered.wav")
TINY_PATH = os.path.join(EVIDENCE_DIR, "audio_tiny.wav")
TINY_STEGO_PATH = os.path.join(EVIDENCE_DIR, "audio_tiny_stego.wav")

BIT_DEPTH = 2
START_UNIT = 1234
METADATA = {"team": "P#-#", "cover_type": "audio"}


def _make_tiny_wav(path, n_frames=4, sampwidth=2, framerate=8000):
    """Tiny WAV for the capacity-failure case, same role as the 2x2 PNG in the image test."""
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        wf.writeframes(np.zeros(n_frames, dtype=np.int16).tobytes())


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    print("== Setup ==")
    print(f"Using {COVER_PATH}")
    check_arr, check_params = ac.load_audio(COVER_PATH)
    print(f"Loaded audio bytes: {check_arr.size}, sampwidth={check_params.sampwidth}, "
          f"channels={check_params.n_channels}, framerate={check_params.framerate}")

    print("\n== Positive case: protect + verify ==")
    result = ac.protect_audio(COVER_PATH, STEGO_PATH, media_id="AUD-TEST-001",
                               metadata=METADATA, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Protected OK ->", result["output_path"])
    print("Capacity check:", result["capacity_check"])

    verify_result = ac.verify_audio(STEGO_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Verdict:", verify_result["verdict"], "-", verify_result["detail"])
    assert verify_result["verdict"] == pt.Verdict.AUTHENTIC, "Expected Authentic on clean round-trip"

    print("\n== Before/after comparison ==")
    cover_arr, cover_params = ac.load_audio(COVER_PATH)
    stego_arr, stego_params = ac.load_audio(STEGO_PATH)
    stats = ac.compare_audio(cover_arr, stego_arr)
    print("Compare stats:", stats)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        cover_wave = ac.samples_for_waveform(cover_arr, cover_params)
        stego_wave = ac.samples_for_waveform(stego_arr, stego_params)
        fig, axes = plt.subplots(2, 1, figsize=(10, 4), sharex=True)
        axes[0].plot(cover_wave[:2000])
        axes[0].set_title("Cover (first 2000 samples)")
        axes[1].plot(stego_wave[:2000])
        axes[1].set_title("Stego (first 2000 samples)")
        fig.tight_layout()
        WAVEFORM_PATH = os.path.join(EVIDENCE_DIR, "audio_waveform_compare.png")
        fig.savefig(WAVEFORM_PATH)
        print("Saved waveform comparison ->", WAVEFORM_PATH)
    except ImportError:
        print("matplotlib not installed, skipping waveform plot (stats above still cover this case)")

    print("\n== Negative case: tampering ==")
    tampered = stego_arr.copy()
    # Flip bytes at the END of the byte stream, well past
    # [START_UNIT, START_UNIT + required_units) so we don't accidentally
    # corrupt the header/payload itself (which would give Payload Missing /
    # Cannot Verify instead of the Tampered case we want here).
    tampered[-200:] = 255 - tampered[-200:]
    ac.save_audio(tampered, stego_params, TAMPERED_PATH)

    tamper_result = ac.verify_audio(TAMPERED_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Verdict:", tamper_result["verdict"], "-", tamper_result["detail"])
    assert tamper_result["verdict"] == pt.Verdict.TAMPERED, "Expected Tampered after flipping bytes"

    print("\n== Negative case: wrong start location ==")
    wrong_loc_result = ac.verify_audio(STEGO_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT + 999)
    print("Verdict:", wrong_loc_result["verdict"], "-", wrong_loc_result["detail"])
    assert wrong_loc_result["verdict"] in (pt.Verdict.PAYLOAD_MISSING, pt.Verdict.WRONG_START_LOCATION,
                                            pt.Verdict.CANNOT_VERIFY), "Expected a failure verdict"

    print("\n== Negative case: capacity check failure ==")
    _make_tiny_wav(TINY_PATH)
    try:
        ac.protect_audio(TINY_PATH, TINY_STEGO_PATH, media_id="AUD-TEST-002",
                          metadata=METADATA, bit_depth=1, start_unit=0)
        print("UNEXPECTED: capacity check did not fail")
    except ValueError as exc:
        print("Correctly rejected: ", exc)

    print("\n== Negative case: signature invalid ==")
    # Different from the tampering case above: there we corrupted cover
    # bytes AFTER embedding (hash mismatch). Here we corrupt the SIGNATURE
    # itself before embedding, to specifically exercise Verdict.SIGNATURE_INVALID
    # rather than Verdict.TAMPERED — these are different failure paths in
    # payload_temp.open_protected_blob() and the rubric calls out
    # "failed-signature... handling" as its own thing to demonstrate.
    #
    # NOTE: embedding now only touches the LOW byte of each sample (see the
    # audio_codec.py fix), so reading/writing the blob here must go through
    # embeddable_view()/merge_embeddable_view() instead of the raw full
    # array — extract_at_offset() expects the low-byte-only view, not the
    # full interleaved byte stream.
    SIG_INVALID_PATH = os.path.join(EVIDENCE_DIR, "audio_sig_invalid.wav")

    low_bytes = ac.embeddable_view(stego_arr, stego_params.sampwidth)
    good_blob = ac.extract_at_offset(low_bytes, START_UNIT, BIT_DEPTH)
    payload_bytes, signature, n_lsb = pt.unpack(good_blob)
    corrupted_signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
    corrupted_blob = pt.pack(payload_bytes, corrupted_signature, n_lsb)

    fresh_cover_arr, fresh_cover_params = ac.load_audio(COVER_PATH)
    fresh_low = ac.embeddable_view(fresh_cover_arr, fresh_cover_params.sampwidth)
    embedded_low = ac.embed_at_offset(fresh_low, corrupted_blob, START_UNIT, BIT_DEPTH)
    sig_invalid_arr = ac.merge_embeddable_view(fresh_cover_arr, fresh_cover_params.sampwidth, embedded_low)
    ac.save_audio(sig_invalid_arr, fresh_cover_params, SIG_INVALID_PATH)

    sig_result = ac.verify_audio(SIG_INVALID_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Verdict:", sig_result["verdict"], "-", sig_result["detail"])
    assert sig_result["verdict"] == pt.Verdict.SIGNATURE_INVALID, "Expected Signature Invalid on corrupted signature"

    print("\n== Required case: varying payload sizes ==")
    # Spec (Section 5) requires three message sizes: a short message (one
    # Learning Outcome), a large message (the Project Overview paragraph),
    # and a custom payload the team defines for confidentiality/integrity.
    SHORT_MESSAGE = (
        "Explain how steganography can be used to embed hidden "
        "verification data in image and audio cover objects."
    )
    LARGE_MESSAGE = (
        "This undergraduate project requires student teams to design, "
        "implement and demonstrate a GUI-based LSB Replacement "
        "steganography program (window-based or web-based) that protects "
        "and verifies both image and audio cover objects using "
        "steganography, hashing and digital signatures. The project "
        "focuses on practical cybersecurity concepts: hiding a "
        "verification payload inside an image and an audio file, signing "
        "relevant verification data, extracting the hidden payload, "
        "checking the digital signature, and demonstrating positive and "
        "negative verification cases. Video as a cover object is not "
        "required for the main assignment, but may be attempted as an "
        "optional challenge."
    )
    CUSTOM_MESSAGE = (
        "CONFIDENTIAL RELEASE NOTE — Build v1.0.3, cleared for release "
        "2026-09-15. Do not distribute prior to embargo lift. Contact: "
        "verification-team@example.test"
    )

    size_cases = [
        ("short", SHORT_MESSAGE, os.path.join(EVIDENCE_DIR, "audio_stego_short.wav")),
        ("large", LARGE_MESSAGE, os.path.join(EVIDENCE_DIR, "audio_stego_large.wav")),
        ("custom", CUSTOM_MESSAGE, os.path.join(EVIDENCE_DIR, "audio_stego_custom.wav")),
    ]

    for label, message, out_path in size_cases:
        meta = dict(METADATA)
        meta["message"] = message
        result = ac.protect_audio(COVER_PATH, out_path, media_id=f"AUD-SIZE-{label.upper()}",
                                   metadata=meta, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
        blob_size = result["capacity_check"]["blob_size_bytes"]
        v = ac.verify_audio(out_path, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
        print(f"[{label}] message chars={len(message)}, blob bytes={blob_size}, "
              f"verdict={v['verdict']}")
        assert v["verdict"] == pt.Verdict.AUTHENTIC, f"Expected Authentic for {label} payload"

    print("\nAll round-trip checks passed.")


if __name__ == "__main__":
    main()