"""
a2_crypto - crypto and verdict layer for INF2005 ACW1 (Pair A, person 2).

WHAT THIS PACKAGE IS
    Hashing, payload construction, digital signatures, keyed start-location
    derivation and the verdict decision tree. It covers FR3, FR4, FR7, FR9 and
    FR10 of the assignment spec.

WHAT IT DELIBERATELY IS NOT
    It reads no PNG and no WAV. It converts no bits into pixels. Media access
    arrives through the Codec port and bit framing through the Bitstream port
    (see ports.py), both of which teammates implement. That is why the same
    code path serves image and audio without a branch.

PLUG AND PLAY
    Everything lives in this folder. It imports nothing from any teammate
    package. The whole layer is swapped by replacing the folder, and
    `python -m a2_crypto.selftest` proves a replacement works before it is
    trusted.

TYPICAL USE
    from a2_crypto import protect, verify, load_private, load_public
    from a2_crypto.mocks import MemoryCodec, ReferenceBitstream

    codec, bits = MemoryCodec(), ReferenceBitstream()
    res = protect(cover, "secret message", "IMG-0007", 2, "passphrase",
                  priv, codec=codec, bits=bits)
    codec.save(res.stego_view, "stego.png")

    v = verify(codec.load("stego.png"), "IMG-0007", 2, "passphrase", pub,
               codec=codec, bits=bits)
    print(v.code, v.reason)
"""
from __future__ import annotations

from .config import API_VERSION, DEFAULT_SIGN_ALGO, MAGIC
from .errors import (
    A2Error,
    CapacityError,
    DecryptionError,
    HeaderError,
    KeyError_,
)
from .hashing import (
    lsb_mask,
    mask_low_bits,
    stable_digest,
    stable_digest_hex,
    tamper_detection_strength,
)
from .keys import (
    KeyBundle,
    Secrets,
    algo_of_key,
    derive_secrets,
    generate_keypair,
    load_private,
    load_public,
    public_fingerprint,
    save_keypair,
)
from .location import (
    ScanResult,
    derive_start,
    derive_start_preview,
    max_payload_bits,
    placement_window,
    scan_for_magic,
)
from .mocks import MemoryCodec, ReferenceBitstream
from .payload import (
    Payload,
    build_payload,
    canonical_bytes,
    decrypt_message,
    encrypt_message,
    payload_from_bytes,
)
from .pipeline import (
    ProtectResult,
    capacity_report,
    estimate_stream_bits,
    protect,
    verify,
)
from .ports import Bitstream, Codec, CoverView
from .signing import SIGNERS, sign_payload, signature_len, verify_signature
from .trace import Trace, TraceStep, hexdump
from .verdict import VERDICT_COLOUR, VERDICT_MEANING, Verdict, VerdictCode

__all__ = [
    # version
    "API_VERSION", "DEFAULT_SIGN_ALGO", "MAGIC",
    # orchestration
    "protect", "verify", "ProtectResult", "capacity_report", "estimate_stream_bits",
    # verdicts
    "Verdict", "VerdictCode", "VERDICT_MEANING", "VERDICT_COLOUR",
    # keys and secrets
    "generate_keypair", "save_keypair", "load_private", "load_public",
    "derive_secrets", "KeyBundle", "Secrets", "algo_of_key", "public_fingerprint",
    # primitives
    "stable_digest", "stable_digest_hex", "mask_low_bits", "lsb_mask",
    "tamper_detection_strength",
    "Payload", "build_payload", "canonical_bytes", "payload_from_bytes",
    "encrypt_message", "decrypt_message",
    "sign_payload", "verify_signature", "signature_len", "SIGNERS",
    "derive_start", "derive_start_preview", "max_payload_bits",
    "placement_window", "scan_for_magic", "ScanResult",
    # ports and reference implementations
    "Codec", "Bitstream", "CoverView", "MemoryCodec", "ReferenceBitstream",
    # tracing
    "Trace", "TraceStep", "hexdump",
    # errors
    "A2Error", "CapacityError", "HeaderError", "DecryptionError", "KeyError_",
]


def check_api_version(expected: str) -> bool:
    """
    Host apps call this at startup. Returns True on a match and warns on a
    mismatch rather than failing hard, so a minor bump does not stop a demo.
    """
    if expected != API_VERSION:
        import warnings
        warnings.warn(
            "a2_crypto API_VERSION is {} but the caller expects {}. "
            "Check the public surface before relying on it.".format(
                API_VERSION, expected),
            RuntimeWarning, stacklevel=2,
        )
        return False
    return True
