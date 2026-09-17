"""
payload.py - the verification record, its canonical bytes, and message crypto.

CANONICAL SERIALIZATION (read this before touching anything here)
    A signature over JSON breaks the moment key order or whitespace differs
    between the signing side and the verifying side. Every sign and every
    verify in this package routes through canonical_bytes(), which pins
    sort_keys, separators and ASCII escaping. This is the single most common
    source of "signature invalid but nothing is actually wrong" bugs, so it
    is centralised in exactly one function and never inlined.

TWO SEPARATE GUARANTEES
    * the AES-GCM tag proves the hidden MESSAGE was not modified and keeps it
      confidential from anyone without the passphrase;
    * the signature over these canonical bytes proves the whole RECORD was
      issued by the holder of the private key.
    They are different claims. Say so explicitly in the demo.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .errors import DecryptionError
from .keys import Secrets


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime(config.TIMESTAMP_FMT)


# --- the record -------------------------------------------------------------
@dataclass
class Payload:
    """
    FR3: media ID, timestamp, hash, nonce and team-defined metadata, plus the
    protected message. The signature travels ALONGSIDE this record, never
    inside it - a record cannot contain a signature over itself.
    """
    media_id: str
    media_type: str          # "image" | "audio"
    ts: str                  # UTC ISO-8601
    nonce: str               # hex, anti-replay
    n_lsb: int
    cover_hash: str          # hex stable_digest
    enc: str                 # "aes-256-gcm" | "none"
    msg_ct: str              # base64 ciphertext (or plaintext bytes if enc none)
    msg_iv: str = ""         # base64, 12-byte GCM IV
    msg_tag: str = ""        # base64, 16-byte GCM tag
    v: int = config.PAYLOAD_SCHEMA_VERSION
    meta: dict = field(default_factory=lambda: dict(config.DEFAULT_META))

    # -- serialisation ------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "v": self.v,
            "media_id": self.media_id,
            "media_type": self.media_type,
            "ts": self.ts,
            "nonce": self.nonce,
            "n_lsb": self.n_lsb,
            "cover_hash": self.cover_hash,
            "enc": self.enc,
            "msg_ct": self.msg_ct,
            "msg_iv": self.msg_iv,
            "msg_tag": self.msg_tag,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, obj: dict) -> "Payload":
        return cls(
            v=obj["v"],
            media_id=obj["media_id"],
            media_type=obj["media_type"],
            ts=obj["ts"],
            nonce=obj["nonce"],
            n_lsb=obj["n_lsb"],
            cover_hash=obj["cover_hash"],
            enc=obj["enc"],
            msg_ct=obj["msg_ct"],
            msg_iv=obj.get("msg_iv", ""),
            msg_tag=obj.get("msg_tag", ""),
            meta=obj.get("meta", {}),
        )

    def pretty(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def canonical_bytes(payload: "Payload | dict") -> bytes:
    """
    THE one serialisation used for signing and verifying. Deterministic across
    dict ordering, whitespace and non-ASCII content.
    """
    obj = payload.to_dict() if isinstance(payload, Payload) else payload
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def payload_from_bytes(data: bytes) -> Payload:
    return Payload.from_dict(json.loads(data.decode("utf-8")))


# --- message confidentiality ------------------------------------------------
def encrypt_message(message: str | bytes, secrets: Secrets) -> tuple[str, str, str]:
    """AES-256-GCM. Returns (ct_b64, iv_b64, tag_b64)."""
    raw = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    iv = os.urandom(config.GCM_IV_LEN)
    sealed = AESGCM(secrets.k_enc).encrypt(iv, raw, None)
    ct, tag = sealed[:-config.GCM_TAG_LEN], sealed[-config.GCM_TAG_LEN:]
    return _b64(ct), _b64(iv), _b64(tag)


def decrypt_message(payload: Payload, secrets: Secrets) -> bytes:
    """
    Raises DecryptionError when the GCM tag fails - which the verdict tree
    reports as CANNOT_VERIFY ("correct signature, correct hash, wrong
    decryption passphrase"), not as tampering.
    """
    if payload.enc == config.AEAD_NONE:
        return _unb64(payload.msg_ct)
    if payload.enc != config.AEAD_NAME:
        raise DecryptionError(f"Unknown message encryption scheme {payload.enc!r}")
    try:
        sealed = _unb64(payload.msg_ct) + _unb64(payload.msg_tag)
        return AESGCM(secrets.k_enc).decrypt(_unb64(payload.msg_iv), sealed, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "AES-GCM authentication tag failed - wrong decryption passphrase "
            "or the ciphertext was modified."
        ) from exc
    except Exception as exc:
        raise DecryptionError(f"Message decryption failed: {exc}") from exc


# --- construction -----------------------------------------------------------
def build_payload(cover_hash: bytes | str, media_id: str, media_type: str,
                  n_lsb: int, message: str | bytes, secrets: Secrets,
                  meta: dict | None = None, encrypt: bool = True,
                  ts: str | None = None, nonce: bytes | None = None) -> Payload:
    """
    Assemble the record. `encrypt=False` stores the message as plain base64 -
    useful for showing a marker the payload contents in the clear, but then
    only the signature protects it, not the GCM tag.
    """
    digest_hex = cover_hash.hex() if isinstance(cover_hash, (bytes, bytearray)) else str(cover_hash)

    if encrypt:
        ct, iv, tag = encrypt_message(message, secrets)
        enc = config.AEAD_NAME
    else:
        raw = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        ct, iv, tag = _b64(raw), "", ""
        enc = config.AEAD_NONE

    return Payload(
        media_id=media_id,
        media_type=media_type,
        ts=ts or utc_now_iso(),
        nonce=(nonce or os.urandom(config.NONCE_LEN)).hex(),
        n_lsb=n_lsb,
        cover_hash=digest_hex,
        enc=enc,
        msg_ct=ct,
        msg_iv=iv,
        msg_tag=tag,
        meta=dict(meta) if meta is not None else dict(config.DEFAULT_META),
    )
