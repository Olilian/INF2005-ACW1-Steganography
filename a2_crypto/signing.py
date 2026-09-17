"""
signing.py - signature scheme registry.

Plug-and-play rule 6: schemes live in a dict, so changing the default is a
config string edit rather than a refactor. Both registered schemes are put
through the same selftest cases.

WHY Ed25519 IS THE DEFAULT (expect this question in the demo)
    * 64-byte signature, fixed. RSA-2048 emits 256 bytes. At 1 LSB in a small
      WAV the signature is a real chunk of the capacity budget - a 256-byte
      signature costs 2,048 cover bytes on its own.
    * 32-byte public key, so a marker can eyeball it.
    * No padding mode, no exponent, no parameter to choose wrongly. RSA
      signatures are only as good as the padding scheme; PKCS#1 v1.5 is still
      the common default in tutorials, so RSA here is registered as PSS.
    * Deterministic, so a signature is reproducible from the same inputs.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding

from . import config
from .errors import KeyError_


# --- ed25519 ----------------------------------------------------------------
def _ed25519_sign(data: bytes, priv) -> bytes:
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        raise KeyError_("ed25519 signer needs an Ed25519 private key")
    return priv.sign(data)


def _ed25519_verify(data: bytes, sig: bytes, pub) -> bool:
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        return False
    try:
        pub.verify(sig, data)
        return True
    except InvalidSignature:
        return False


# --- rsa-2048 pss -----------------------------------------------------------
def _rsa_pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def _rsa_sign(data: bytes, priv) -> bytes:
    if not hasattr(priv, "sign"):
        raise KeyError_("rsa2048-pss signer needs an RSA private key")
    return priv.sign(data, _rsa_pss_padding(), hashes.SHA256())


def _rsa_verify(data: bytes, sig: bytes, pub) -> bool:
    try:
        pub.verify(sig, data, _rsa_pss_padding(), hashes.SHA256())
        return True
    except (InvalidSignature, Exception):
        return False


# --- registry ---------------------------------------------------------------
SIGNERS = {
    "ed25519": {
        "sign": _ed25519_sign,
        "verify": _ed25519_verify,
        "sig_len": 64,
        "id": config.ALGO_IDS["ed25519"],
        "label": "Ed25519",
    },
    "rsa2048-pss": {
        "sign": _rsa_sign,
        "verify": _rsa_verify,
        "sig_len": 256,
        "id": config.ALGO_IDS["rsa2048-pss"],
        "label": "RSA-2048 PSS / SHA-256",
    },
}


def get_signer(algo: str) -> dict:
    try:
        return SIGNERS[algo]
    except KeyError as exc:
        raise KeyError_(
            f"Unknown signature algorithm {algo!r}. Registered: {list(SIGNERS)}"
        ) from exc


def signature_len(algo: str) -> int:
    """Used by the capacity estimate before anything is actually signed."""
    return get_signer(algo)["sig_len"]


def sign_payload(payload_bytes: bytes, priv, algo: str = config.DEFAULT_SIGN_ALGO) -> bytes:
    """Sign the CANONICAL bytes. Callers must never hand raw json.dumps output."""
    return get_signer(algo)["sign"](payload_bytes, priv)


def verify_signature(payload_bytes: bytes, sig: bytes, pub,
                     algo: str = config.DEFAULT_SIGN_ALGO) -> bool:
    """
    Returns False rather than raising on a bad signature - a failed check is a
    verdict, not an exception. Only an unknown algorithm raises.
    """
    if not sig:
        return False
    return get_signer(algo)["verify"](payload_bytes, sig, pub)
