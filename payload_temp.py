import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from enum import Enum

from bitstream.bitstream_engine import (
    MAGIC,
    VERSION,
    HEADER_SIZE_BYTES,
    UnpackError,
    pack,
    unpack,
    required_units,
)

# ---------------------------------------------------------------------------
# Verdict enum — six required outcomes (FR10). Wording is from the spec,
# don't change it.
# ---------------------------------------------------------------------------
class Verdict(str, Enum):
    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"

    def __str__(self):
        return self.value


# ---------------------------------------------------------------------------
# FAKE crypto — placeholder only, until A's real keygen/sign/verify lands.
# ---------------------------------------------------------------------------
_TEMP_SHARED_KEY = b"TEMP-DO-NOT-USE-IN-FINAL-SUBMISSION"


def hash_bytes(data: bytes) -> str:
    """Real SHA-256 hashing — this part doesn't need to change later."""
    return hashlib.sha256(data).hexdigest()


def fake_sign(payload_bytes: bytes) -> bytes:
    """
    PLACEHOLDER for A's real digital signature (RSA/Ed25519).
    HMAC is symmetric (same key signs and verifies) — fine for testing
    the codec, NOT a real digital signature for the final submission.
    """
    return hmac.new(_TEMP_SHARED_KEY, payload_bytes, hashlib.sha256).digest()


def fake_verify(payload_bytes: bytes, signature: bytes) -> bool:
    expected = fake_sign(payload_bytes)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Payload shape (FR3)
# ---------------------------------------------------------------------------
def build_payload(media_id: str, cover_hash_hex: str, metadata: dict, nonce: str = None) -> dict:
    return {
        "media_id": media_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hash": f"sha256:{cover_hash_hex}",
        "nonce": nonce or os.urandom(16).hex(),
        "metadata": metadata,
    }


def serialize_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_payload(payload_bytes: bytes) -> dict:
    return json.loads(payload_bytes.decode("utf-8"))


# ---------------------------------------------------------------------------
# Packed blob layout — self-describing header so the codec doesn't need to
# know payload/signature lengths in advance. MAGIC, VERSION, HEADER_SIZE_BYTES,
# UnpackError, pack(), unpack(), required_units() now live in
# bitstream/bitstream_engine.py (Role 1's real module) and are re-exported
# here so this file stays the single call site the codecs already use.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Convenience: build a full ready-to-embed blob in one call, using the fake
# crypto above. This is the function your image_codec.py should call for now.
# ---------------------------------------------------------------------------
def build_protectable_blob(cover_bytes: bytes, media_id: str, metadata: dict, n_lsb: int) -> tuple:
    """
    Returns (blob_bytes, payload_dict) — blob_bytes is what gets embedded,
    payload_dict is what you'll want to log/display/keep for test evidence.

    n_lsb is required now because the header is self-describing (see
    bitstream_engine.py) — the bit depth used to embed gets recorded in
    the blob itself.
    """
    cover_hash_hex = hash_bytes(cover_bytes)
    payload = build_payload(media_id, cover_hash_hex, metadata)
    payload_bytes = serialize_payload(payload)
    signature = fake_sign(payload_bytes)
    blob = pack(payload_bytes, signature, n_lsb)
    return blob, payload


def open_protected_blob(blob: bytes) -> tuple:
    """
    Returns (Verdict, payload_dict_or_None, detail_string).
    Only checks signature validity here — the codec/caller is responsible
    for comparing the recovered hash against a freshly recomputed one to
    catch Verdict.TAMPERED.
    """
    try:
        payload_bytes, signature, _n_lsb = unpack(blob)
    except UnpackError as exc:
        return Verdict.PAYLOAD_MISSING, None, str(exc)

    try:
        payload = deserialize_payload(payload_bytes)
    except Exception as exc:
        return Verdict.CANNOT_VERIFY, None, f"Payload JSON malformed: {exc}"

    if not fake_verify(payload_bytes, signature):
        return Verdict.SIGNATURE_INVALID, payload, "Signature check failed"

    return Verdict.AUTHENTIC, payload, "Signature OK — caller should still compare hash for tamper check"
