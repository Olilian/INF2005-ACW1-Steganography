"""
bitstream_engine.py — Bitstream Engine (Role 1)
=================================================================
The translator between "a stream of bytes" (header + signed payload) and
"a list of small integers, one per cover unit" (what an image or audio
codec actually writes into LSBs). This module never touches a pixel, a
WAV file, or a PNG — it is pure stdlib so it can be unit-tested in total
isolation and reused unchanged by both the image and audio codecs (the
"same Codec interface for image and audio" rule the team agreed on).

NOT this module's job (see BITSTREAM_ENGINE_BUILD_SPEC.md): real
signing/keygen, hash semantics, payload dict contents, the Verdict enum,
or start-location *derivation*. Those are Role 2 / codec concerns.

Header layout (proposed STG1 — see build spec Step 1 note; this is a
byte-layout change from payload_temp.py's STG0, so it needs the team's
go-ahead before payload_temp.py or the codecs are touched — see
bitstream/README.md "What changed" section for status):

    MAGIC (4 bytes) | VERSION (1 byte) | N_LSB (1 byte) |
    PAYLOAD_LEN (4 bytes, big-endian) | SIG_LEN (4 bytes, big-endian)

Adding N_LSB makes the header self-describing: a verifier can recover
the bit depth a stego file was built with directly from the file itself,
instead of needing it passed in out-of-band (the gap flagged in the
build spec).
"""
import struct

MAGIC = b"STG1"
VERSION = 1

# 4 (magic) + 1 (version) + 1 (n_lsb) + 4 (payload_len) + 4 (sig_len)
HEADER_SIZE_BYTES = 14

_HEADER_STRUCT = ">4sBBII"  # magic, version, n_lsb, payload_len, sig_len


class UnpackError(ValueError):
    """
    Raised on bad magic bytes or a truncated blob/header.

    Deliberately a ValueError subclass, not a bare exception: callers
    (codec verify_* wrappers) treat this as a signal to report
    Verdict.PAYLOAD_MISSING or Verdict.WRONG_START_LOCATION rather than
    letting the app crash — reading garbage bits from the wrong offset
    is an expected failure mode, not a bug.
    """
    pass


def build_header(n_lsb: int, payload_len: int, sig_len: int) -> bytes:
    """
    Packs the fixed-size header.

    n_lsb is validated here (not just in the codecs' embed loop) because
    a header with an out-of-range bit depth would silently produce a
    blob no verifier could ever correctly re-derive units from — better
    to fail loudly at build time than produce a corrupt-by-construction
    stego file.
    """
    if not (1 <= n_lsb <= 8):
        raise ValueError("n_lsb must be between 1 and 8")
    return struct.pack(_HEADER_STRUCT, MAGIC, VERSION, n_lsb, payload_len, sig_len)


def parse_header(header_bytes: bytes) -> dict:
    """
    Unpacks and validates the header.

    Checks magic and length explicitly (rather than letting struct.error
    propagate) so every "this isn't a valid header" case funnels through
    one exception type (UnpackError) that the rest of the pipeline
    already knows how to turn into a Verdict.
    """
    if len(header_bytes) < HEADER_SIZE_BYTES:
        raise UnpackError("Header shorter than HEADER_SIZE_BYTES")

    magic, version, n_lsb, payload_len, sig_len = struct.unpack(
        _HEADER_STRUCT, header_bytes[:HEADER_SIZE_BYTES]
    )
    if magic != MAGIC:
        raise UnpackError("Magic bytes mismatch — payload missing or wrong start location")

    return {
        "version": version,
        "n_lsb": n_lsb,
        "payload_len": payload_len,
        "sig_len": sig_len,
    }


def pack(payload_bytes: bytes, signature: bytes, n_lsb: int) -> bytes:
    """
    header (now including n_lsb) + payload_bytes + signature, ready to
    hand to a codec's embed_at_offset().
    """
    header = build_header(n_lsb, len(payload_bytes), len(signature))
    return header + payload_bytes + signature


def unpack(blob: bytes) -> tuple:
    """
    Inverse of pack(). Returns (payload_bytes, signature, n_lsb).

    Re-derives n_lsb from the header rather than trusting a caller-
    supplied value, so a blob unpacked with the wrong bit depth at the
    codec-extraction stage still carries the *correct* n_lsb once the
    header itself is readable — this is what lets a verifier cross-check
    "did I read this with the bit depth the file says it was written
    with" instead of trusting an external parameter.
    """
    if len(blob) < HEADER_SIZE_BYTES:
        raise UnpackError("Blob shorter than header size")

    header = parse_header(blob)
    payload_len = header["payload_len"]
    sig_len = header["sig_len"]
    n_lsb = header["n_lsb"]

    expected_total = HEADER_SIZE_BYTES + payload_len + sig_len
    if len(blob) < expected_total:
        raise UnpackError("Blob shorter than header claims")

    payload_bytes = blob[HEADER_SIZE_BYTES: HEADER_SIZE_BYTES + payload_len]
    signature = blob[HEADER_SIZE_BYTES + payload_len: expected_total]
    return payload_bytes, signature, n_lsb


def required_units(num_bits: int, bit_depth: int) -> int:
    """
    Ceiling-division capacity math: how many cover units (one unit =
    one pixel channel byte, or one PCM byte) are needed to carry
    num_bits at bit_depth bits per unit. Ceiling (not floor) because a
    partial last unit still needs a whole unit to hold it.
    """
    return -(-num_bits // bit_depth)  # ceiling division


def capacity_check(cover_units: int, blob_size_bytes: int, bit_depth: int) -> dict:
    """
    Pure math "does this payload fit" check — no numpy/PIL/wave
    dependency, so it can run before any file is even opened. Return
    shape mirrors image_codec.capacity_check()'s dict (minus the
    array-specific pieces) so a codec can adopt this as a drop-in
    replacement without changing its own return contract.
    """
    req_units = required_units(blob_size_bytes * 8, bit_depth)
    return {
        "fits": req_units <= cover_units,
        "capacity_units": cover_units,
        "required_units": req_units,
        "bit_depth": bit_depth,
        "blob_size_bytes": blob_size_bytes,
    }


def bytes_to_unit_values(data: bytes, n_lsb: int) -> list:
    """
    Splits payload bytes into a list of small integers (0 to 2^n_lsb-1),
    one per cover unit, MSB-first, zero-padded at the end if needed.

    This replaces the duplicated _bytes_to_bits/_bits_to_bytes-plus-
    packing-loop that currently lives inline, near-identically, in both
    image_codec.py and audio_codec.py.
    """
    if not (1 <= n_lsb <= 8):
        raise ValueError("n_lsb must be between 1 and 8")

    bit_string = "".join(f"{b:08b}" for b in data)
    pad = (-len(bit_string)) % n_lsb
    padded = bit_string + ("0" * pad)
    num_units = len(padded) // n_lsb
    return [int(padded[i * n_lsb:(i + 1) * n_lsb], 2) for i in range(num_units)]


def unit_values_to_bytes(values: list, n_lsb: int, total_bytes: int) -> bytes:
    """
    Inverse of bytes_to_unit_values(). total_bytes truncates any padding
    bits introduced by bytes_to_unit_values() so the caller gets back
    exactly the number of bytes originally encoded, not a
    partial-byte-rounded-up version of it.

    Deliberately does NOT try to detect "you used the wrong n_lsb here"
    — it will happily decode garbage, because that garbage is exactly
    the Wrong Start Location / Cannot Verify failure mode: the caller's
    job (via parse_header's magic check, downstream) is to notice the
    result doesn't look like a valid blob, not this function's.
    """
    if not (1 <= n_lsb <= 8):
        raise ValueError("n_lsb must be between 1 and 8")

    bit_string = "".join(format(v, f"0{n_lsb}b") for v in values)
    total_bits = total_bytes * 8
    bit_string = bit_string[:total_bits]
    return bytes(
        int(bit_string[i:i + 8], 2) for i in range(0, len(bit_string), 8)
    )
