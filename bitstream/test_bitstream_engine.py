"""
bitstream/test_bitstream_engine.py — tests for bitstream_engine.py only.

Does not import or touch any teammate-owned file (payload_temp.py,
image_codec.py, audio_codec.py, or their tests) — this module is
self-contained pure-Python, so it can be tested in total isolation.

Run:
    python bitstream/test_bitstream_engine.py
    (or, from inside bitstream/):  python test_bitstream_engine.py
"""
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from bitstream import bitstream_engine as be


def test_pack_unpack_roundtrip():
    print("== pack()/unpack() round-trip across sizes and bit depths ==")
    cases = [
        (b"", b"", 1),
        (b"a", b"sig", 4),
        (b"hello world", b"0123456789abcdef", 8),
        (os.urandom(500), os.urandom(32), 3),
    ]
    for payload, sig, n_lsb in cases:
        blob = be.pack(payload, sig, n_lsb)
        out_payload, out_sig, out_n_lsb = be.unpack(blob)
        assert out_payload == payload, f"payload mismatch for n_lsb={n_lsb}"
        assert out_sig == sig, f"signature mismatch for n_lsb={n_lsb}"
        assert out_n_lsb == n_lsb, f"n_lsb mismatch: expected {n_lsb}, got {out_n_lsb}"
    print("OK")


def test_parse_header_bad_magic():
    print("== parse_header() rejects bad magic ==")
    bad = b"XXXX" + bytes(be.HEADER_SIZE_BYTES - 4)
    try:
        be.parse_header(bad)
        raise AssertionError("Expected UnpackError for bad magic")
    except be.UnpackError:
        print("OK — raised UnpackError as expected")


def test_parse_header_truncated():
    print("== parse_header() rejects truncated header ==")
    truncated = be.MAGIC + b"\x00"
    try:
        be.parse_header(truncated)
        raise AssertionError("Expected UnpackError for truncated header")
    except be.UnpackError:
        print("OK — raised UnpackError as expected")

    print("== unpack() rejects blob shorter than header claims ==")
    header = be.build_header(n_lsb=4, payload_len=100, sig_len=32)
    short_blob = header + b"only ten b"
    try:
        be.unpack(short_blob)
        raise AssertionError("Expected UnpackError for blob shorter than claimed")
    except be.UnpackError:
        print("OK — raised UnpackError as expected")


def test_required_units_and_capacity_check():
    print("== required_units()/capacity_check() across bit depths 1-8 ==")
    for bit_depth in range(1, 9):
        # Exact fit: num_bits is a clean multiple of bit_depth.
        num_bits = bit_depth * 10
        units = be.required_units(num_bits, bit_depth)
        assert units == 10, f"exact-fit failed for bit_depth={bit_depth}: got {units}"

        # Overflow by one bit: needs one extra unit.
        units_over = be.required_units(num_bits + 1, bit_depth)
        assert units_over == 11, f"overflow-by-one-bit failed for bit_depth={bit_depth}: got {units_over}"

        check_fits = be.capacity_check(cover_units=10, blob_size_bytes=(num_bits // 8) or 1, bit_depth=bit_depth)
        assert check_fits["required_units"] == be.required_units((num_bits // 8 or 1) * 8, bit_depth)

        check_no_fit = be.capacity_check(cover_units=1, blob_size_bytes=1000, bit_depth=bit_depth)
        assert check_no_fit["fits"] is False, f"expected no-fit for bit_depth={bit_depth}"
    print("OK")


def test_unit_values_roundtrip():
    print("== bytes_to_unit_values()/unit_values_to_bytes() round-trip, bit depths 1-8 ==")
    payloads = [
        b"",
        b"A",
        b"hello, bitstream!",
        os.urandom(37),  # length not a clean multiple of most bit depths
    ]
    for n_lsb in range(1, 9):
        for payload in payloads:
            values = be.bytes_to_unit_values(payload, n_lsb)
            recovered = be.unit_values_to_bytes(values, n_lsb, total_bytes=len(payload))
            assert recovered == payload, (
                f"round-trip failed for n_lsb={n_lsb}, len={len(payload)}: "
                f"expected {payload!r}, got {recovered!r}"
            )
    print("OK")


def test_mismatched_n_lsb_does_not_silently_succeed():
    print("== encoding with n_lsb=X, decoding with n_lsb=Y produces garbage, not a silent correct result ==")
    payload = b"this is a reasonably long test payload for mismatch testing"
    n_lsb_encode = 2
    n_lsb_decode = 5

    # Simulates the real failure mode: a codec reads the SAME sequence of
    # per-unit integers from the cover object, but reinterprets each one as
    # n_lsb_decode bits wide instead of the n_lsb_encode bits it was
    # actually written with (e.g. verifier told the wrong bit depth).
    values = be.bytes_to_unit_values(payload, n_lsb_encode)
    garbage = be.unit_values_to_bytes(values, n_lsb_decode, total_bytes=len(payload))

    assert garbage != payload, (
        "Decoding with the wrong n_lsb must NOT silently reproduce the "
        "original payload — that would mask the Wrong Start Location / "
        "Cannot Verify failure mode this test exists to simulate."
    )
    print("OK — mismatched n_lsb correctly produces garbage, not a silent false-positive")


def main():
    test_pack_unpack_roundtrip()
    test_parse_header_bad_magic()
    test_parse_header_truncated()
    test_required_units_and_capacity_check()
    test_unit_values_roundtrip()
    test_mismatched_n_lsb_does_not_silently_succeed()
    print("\nAll bitstream_engine tests passed.")


if __name__ == "__main__":
    main()
