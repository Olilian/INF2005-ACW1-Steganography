"""
tests/test_image_codec.py — sanity check + required test cases for the
image codec (image_codec.py + payload_temp.py).

Run from anywhere (repo root, this folder, an IDE's Run button, etc.):
    python tests/test_image_codec.py
    (or, from inside tests/):  python test_image_codec.py
"""
import os
import sys
import numpy as np
from PIL import Image

# Make the repo root importable regardless of the current working directory
# or how this script is launched (double-click, IDE, different cwd, etc.).
# Without this, `import payload_temp` / `from image import image_codec`
# only work if you happen to run the script from exactly the repo root.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from image import image_codec as ic
import payload_temp as pt

COVER_PATH = os.path.join(REPO_ROOT, "tests", "samples", "image", "chelsea_cat.png")
EVIDENCE_DIR = os.path.join(REPO_ROOT, "tests", "test_evidence", "image")

STEGO_PATH = os.path.join(EVIDENCE_DIR, "cat_stego.png")
TAMPERED_PATH = os.path.join(EVIDENCE_DIR, "cat_tampered.png")
DIFF_PATH = os.path.join(EVIDENCE_DIR, "cat_diff.png")
TINY_PATH = os.path.join(EVIDENCE_DIR, "cat_tiny.png")
TINY_STEGO_PATH = os.path.join(EVIDENCE_DIR, "sample_tiny_stego.png")

BIT_DEPTH = 2
START_UNIT = 1234
METADATA = {"team": "P#-#", "cover_type": "image"}


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    print("== Setup ==")
    print(f"Using {COVER_PATH}")
    check_arr = ic.load_image(COVER_PATH)
    print(f"Loaded image shape: {check_arr.shape}")

    print("\n== Positive case: protect + verify ==")
    result = ic.protect_image(COVER_PATH, STEGO_PATH, media_id="IMG-TEST-001",
                               metadata=METADATA, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Protected OK ->", result["output_path"])
    print("Capacity check:", result["capacity_check"])

    verify_result = ic.verify_image(STEGO_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Verdict:", verify_result["verdict"], "-", verify_result["detail"])
    assert verify_result["verdict"] == pt.Verdict.AUTHENTIC, "Expected Authentic on clean round-trip"

    print("\n== Before/after comparison ==")
    cover_arr = ic.load_image(COVER_PATH)
    stego_arr = ic.load_image(STEGO_PATH)
    stats = ic.compare_images(cover_arr, stego_arr)
    print("Compare stats:", stats)

    diff_arr = ic.make_diff_image(cover_arr, stego_arr)
    Image.fromarray(diff_arr).save(DIFF_PATH)
    print("Saved amplified diff image ->", DIFF_PATH)

    print("\n== Negative case: tampering ==")
    tampered = stego_arr.copy()
    # Flip pixels in the LAST few rows. Row-major flatten means row r starts
    # at unit r * width * channels, so picking a late row guarantees we're
    # well past [START_UNIT, START_UNIT + required_units) and don't
    # accidentally corrupt the header/payload itself (which would produce
    # Cannot Verify / Payload Missing instead of the Tampered case we want).
    tampered[-5:, :, :] = 255 - tampered[-5:, :, :]
    Image.fromarray(tampered).save(TAMPERED_PATH)

    tamper_result = ic.verify_image(TAMPERED_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT)
    print("Verdict:", tamper_result["verdict"], "-", tamper_result["detail"])
    assert tamper_result["verdict"] == pt.Verdict.TAMPERED, "Expected Tampered after flipping pixels"

    print("\n== Negative case: wrong start location ==")
    wrong_loc_result = ic.verify_image(STEGO_PATH, bit_depth=BIT_DEPTH, start_unit=START_UNIT + 999)
    print("Verdict:", wrong_loc_result["verdict"], "-", wrong_loc_result["detail"])
    assert wrong_loc_result["verdict"] in (pt.Verdict.PAYLOAD_MISSING, pt.Verdict.WRONG_START_LOCATION,
                                            pt.Verdict.CANNOT_VERIFY), "Expected a failure verdict"

    print("\n== Negative case: capacity check failure ==")
    tiny = np.zeros((2, 2, 3), dtype=np.uint8)
    Image.fromarray(tiny).save(TINY_PATH)
    try:
        ic.protect_image(TINY_PATH, TINY_STEGO_PATH, media_id="IMG-TEST-002",
                          metadata=METADATA, bit_depth=1, start_unit=0)
        print("UNEXPECTED: capacity check did not fail")
    except ValueError as exc:
        print("Correctly rejected: ", exc)

    print("\nAll round-trip checks passed.")


if __name__ == "__main__":
    main()