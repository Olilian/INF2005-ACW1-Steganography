"""
hashing.py - the stable-representation hash.

THE PROBLEM
    You cannot hash a cover file and hide that hash inside the same file.
    Embedding changes the bytes, so the digest would never match at verify
    time - every verification would report Tampered.

THE SOLUTION
    Hash the cover with the target LSB planes masked to zero:

        stable_digest(samples, n_lsb) = SHA-256(samples & ~((1 << n_lsb) - 1))

    Embedding only ever writes the bottom n_lsb bits, so the masked
    representation is bit-identical before and after embedding. The verifier
    recomputes it straight from the stego file and gets the same value.

    This is not a loophole that weakens tamper detection: any edit to actual
    picture or audio content moves the upper bits, which changes the masked
    digest, which fails the comparison -> Tampered. What it does give up is
    detection of tampering confined purely to the LSB planes, which is the
    same region the payload itself occupies and is protected instead by the
    signature over the payload.

HONEST LIMITATION (state this in the demo)
    The masked digest gets weaker as n_lsb rises, because more of each byte
    is being discarded before hashing. At n_lsb=8 the mask is 0x00: every
    byte masks to zero, the digest collapses to a constant, and this check
    provides NO tamper detection at all - which is correct, because at 8 LSBs
    the payload has overwritten the entire cover and there is no original
    content left to protect. `tamper_detection_strength()` reports the
    surviving bits per byte so the GUI can warn the user, and the pipeline
    records a trace warning at n_lsb >= 7.
"""
from __future__ import annotations

import hashlib

from . import config


def lsb_mask(n_lsb: int) -> int:
    """Byte mask that clears the bottom n_lsb bits. n_lsb=2 -> 0xFC."""
    _check_lsb(n_lsb)
    return 0xFF ^ ((1 << n_lsb) - 1)


def mask_low_bits(samples: bytes | bytearray | memoryview, n_lsb: int) -> bytes:
    """Zero the bottom n_lsb bits of every byte. Returns a new bytes object."""
    mask = lsb_mask(n_lsb)
    return bytes(samples).translate(_translation_table(mask))


def stable_digest(samples: bytes | bytearray | memoryview, n_lsb: int) -> bytes:
    """
    SHA-256 over the LSB-masked cover. Invariant across embedding at the same
    n_lsb - that invariance is selftest case 4 and the sharpest talking point
    in the demo.
    """
    h = hashlib.new(config.HASH_NAME)
    h.update(mask_low_bits(samples, n_lsb))
    return h.digest()


def stable_digest_hex(samples: bytes | bytearray | memoryview, n_lsb: int) -> str:
    return stable_digest(samples, n_lsb).hex()


def tamper_detection_strength(n_lsb: int) -> dict:
    """
    How much of each cover byte still feeds the digest at this LSB depth.
    Drives the GUI warning and the honest-limitations slide.
    """
    _check_lsb(n_lsb)
    surviving = 8 - n_lsb
    return {
        "n_lsb": n_lsb,
        "bits_hashed_per_byte": surviving,
        "fraction_hashed": surviving / 8.0,
        "detects_content_tampering": surviving > 0,
        "note": (
            "n_lsb=8 masks every byte to zero: the stable digest is a constant "
            "and cannot detect content tampering. The payload signature is the "
            "only integrity guarantee left at this depth."
            if surviving == 0 else
            f"{surviving} of 8 bits per byte feed the digest."
        ),
    }


def sha256(data: bytes) -> bytes:
    """Plain digest, used for payload fingerprints in the trace."""
    return hashlib.new(config.HASH_NAME, data).digest()


# --- internals --------------------------------------------------------------
_TABLES: dict[int, bytes] = {}


def _translation_table(mask: int) -> bytes:
    """bytes.translate() runs the mask in C - far faster than a Python loop."""
    tbl = _TABLES.get(mask)
    if tbl is None:
        tbl = bytes(b & mask for b in range(256))
        _TABLES[mask] = tbl
    return tbl


def _check_lsb(n_lsb: int) -> None:
    if not isinstance(n_lsb, int) or not (config.MIN_LSB <= n_lsb <= config.MAX_LSB):
        raise ValueError(
            f"n_lsb must be an int in {config.MIN_LSB}..{config.MAX_LSB}, got {n_lsb!r}"
        )
