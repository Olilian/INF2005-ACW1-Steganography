"""
pipeline.py - protect() and verify(), the two functions the GUI calls.

These orchestrate the layer and own the verdict decision tree. Everything
media-specific arrives through the Codec and Bitstream ports; nothing here
knows what a PNG or a WAV is.

VERDICT ORDER (evaluated strictly top down, first match wins)
     1  CANNOT_VERIFY         missing key, unreadable input, capacity error
     2  WRONG_START_LOCATION  no magic at the derived offset, but a payload
                              is found at another offset or another LSB depth
     3  PAYLOAD_MISSING       no magic at the derived offset and none anywhere
     4  CANNOT_VERIFY         header parses but declares impossible lengths
     5  SIGNATURE_INVALID     payload recovered, public-key check fails
     6  TAMPERED              signature valid, recomputed cover hash differs
     7  CANNOT_VERIFY         signature and hash fine, AES-GCM tag fails
     8  AUTHENTIC             everything passes
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import config
from .errors import A2Error, CapacityError, DecryptionError, HeaderError, KeyError_
from .hashing import stable_digest, tamper_detection_strength
from .keys import algo_of_key, derive_secrets, public_fingerprint
from .location import (
    derive_start,
    derive_start_preview,
    max_payload_bits,
    probe_other_lsb_depths,
    scan_for_magic,
)
from .payload import (
    Payload,
    build_payload,
    canonical_bytes,
    decrypt_message,
    payload_from_bytes,
)
from .signing import sign_payload, signature_len, verify_signature
from .ports import Bitstream, Codec, CoverView
from .trace import NullTrace, Trace
from .verdict import Verdict, VerdictCode


@dataclass
class ProtectResult:
    """What protect() hands back. `stego_view` goes straight to codec.save()."""
    stego_view: CoverView
    payload: Payload
    signature: bytes
    start_unit: int
    n_lsb: int
    stream_bytes: int
    capacity_bits: int
    needed_bits: int
    algo: str
    trace: Trace | None = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "payload": self.payload.to_dict(),
            "signature_hex": self.signature.hex(),
            "signature_len": len(self.signature),
            "start_unit": self.start_unit,
            "n_lsb": self.n_lsb,
            "stream_bytes": self.stream_bytes,
            "capacity_bits": self.capacity_bits,
            "needed_bits": self.needed_bits,
            "algo": self.algo,
            "details": self.details,
        }


# --- capacity ---------------------------------------------------------------
def estimate_stream_bits(message: str | bytes, algo: str = config.DEFAULT_SIGN_ALGO,
                         encrypt: bool = True) -> int:
    """
    Upper-bound size of the embedded stream, WITHOUT building or signing
    anything. Drives the live capacity bar in the GUI so the user sees a
    payload overflow before pressing Protect.
    """
    raw = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    ct_b64 = 4 * ((len(raw) + 2) // 3)
    iv_tag_b64 = 4 * ((config.GCM_IV_LEN + 2) // 3) + 4 * ((config.GCM_TAG_LEN + 2) // 3)
    json_overhead = 420          # field names, hex hash, nonce, meta, punctuation
    payload_bytes = ct_b64 + (iv_tag_b64 if encrypt else 0) + json_overhead
    return (config.HEADER_SIZE_BYTES + payload_bytes + signature_len(algo)) * 8


def capacity_report(codec: Codec, view: CoverView, n_lsb: int,
                    message: str | bytes = b"",
                    algo: str = config.DEFAULT_SIGN_ALGO,
                    encrypt: bool = True) -> dict:
    """
    The required cover-vs-payload capacity check, as a dict the GUI renders
    directly. `usable_bits` - not raw capacity - is the honest limit, because
    the keyed placement window reserves a tail (see location.py).
    """
    cap = codec.capacity_bits(view, n_lsb)
    needed = estimate_stream_bits(message, algo, encrypt)
    usable = max_payload_bits(cap, n_lsb)
    return {
        "capacity_bits": cap,
        "capacity_units": cap // n_lsb,
        "usable_bits": usable,
        "needed_bits": needed,
        "fits": needed <= usable,
        "utilisation_percent": round(100.0 * needed / max(usable, 1), 3),
        "n_lsb": n_lsb,
        "algo": algo,
        "encrypted": encrypt,
    }


# --- protect ----------------------------------------------------------------
def protect(cover: CoverView, message: str | bytes, media_id: str, n_lsb: int,
            passphrase: str, priv, *, codec: Codec, bits: Bitstream,
            media_type: str = "image", algo: str | None = None,
            meta: dict | None = None, encrypt: bool = True,
            trace: Trace | None = None) -> ProtectResult:
    """
    Steps 2-6 of the spec's security workflow: hash the cover, build the
    payload, sign it, derive the start location, embed.

    Returns a ProtectResult whose `stego_view` the caller passes to
    codec.save(). A2 performs no media file I/O of its own.
    """
    t = trace if trace is not None else NullTrace()  # empty Trace is falsy
    algo = algo or (algo_of_key(priv) if priv is not None else config.DEFAULT_SIGN_ALGO)
    _check_lsb(n_lsb)

    samples = codec.read_samples(cover)
    capacity_bits = codec.capacity_bits(cover, n_lsb)
    t.add("capacity", "Cover capacity measured",
          {"units": len(samples), "capacity_bits": capacity_bits, "n_lsb": n_lsb,
           "usable_bits": max_payload_bits(capacity_bits, n_lsb)})

    # -- 2. stable-representation hash --------------------------------------
    strength = tamper_detection_strength(n_lsb)
    digest = stable_digest(samples, n_lsb)
    t.add("hash", "Stable digest over LSB-masked cover",
          {"algo": config.HASH_NAME, "n_lsb": n_lsb,
           "bits_hashed_per_byte": strength["bits_hashed_per_byte"]},
          blob=digest)
    if not strength["detects_content_tampering"]:
        t.add("hash", "WARNING: no tamper detection at this depth",
              {"note": strength["note"]}, ok=False)

    # -- 3-4. payload + signature -------------------------------------------
    secrets = derive_secrets(passphrase)
    t.add("derive_secrets", "HKDF split passphrase into location and message keys",
          {"salt": config.KDF_SALT.decode(), "labels": [
              config.INFO_START_LOCATION.decode(),
              config.INFO_PAYLOAD_ENCRYPTION.decode()]})

    payload = build_payload(digest, media_id, media_type, n_lsb, message,
                            secrets, meta=meta, encrypt=encrypt)
    t.add("payload", "Verification payload built",
          {"media_id": media_id, "media_type": media_type, "ts": payload.ts,
           "nonce": payload.nonce, "enc": payload.enc,
           "message_bytes": len(message if isinstance(message, bytes)
                                else message.encode("utf-8"))})

    canon = canonical_bytes(payload)
    t.add("canonical", "Canonical JSON serialised for signing",
          {"bytes": len(canon), "rule": "sort_keys, no whitespace, ASCII-escaped"},
          blob=canon)

    if priv is None:
        raise KeyError_("protect() needs a private key to sign the payload.")
    signature = sign_payload(canon, priv, algo)
    t.add("sign", "Payload signed", {"algo": algo, "sig_bytes": len(signature)},
          blob=signature)

    # -- capacity gate -------------------------------------------------------
    stream = bits.pack(canon, signature, n_lsb, config.ALGO_IDS.get(algo, 0))
    needed_bits = len(stream) * 8
    usable_bits = max_payload_bits(capacity_bits, n_lsb)
    if needed_bits > usable_bits:
        t.fail("capacity", "Payload exceeds usable capacity",
               {"needed_bits": needed_bits, "usable_bits": usable_bits,
                "capacity_bits": capacity_bits})
        raise CapacityError(needed_bits, usable_bits, n_lsb)

    # -- 5. keyed start location --------------------------------------------
    preview = derive_start_preview(secrets, media_id, capacity_bits, n_lsb, needed_bits)
    start = preview["start_unit"]
    t.add("derive_start", "Start offset derived from passphrase (not stored)", preview)

    # -- 6. embed ------------------------------------------------------------
    t.add("pack", "Header + payload + signature framed",
          {"stream_bytes": len(stream), "header_bytes": config.HEADER_SIZE_BYTES},
          blob=stream[:64])
    stego_samples = bits.embed(samples, stream, n_lsb, start)
    stego_view = codec.write_samples(cover, stego_samples)
    changed = sum(1 for a, b in zip(samples, stego_samples) if a != b)
    t.add("embed", "Stream written into the LSB planes",
          {"start_unit": start, "units_written": -(-needed_bits // n_lsb),
           "bytes_changed": changed,
           "percent_of_cover": round(100.0 * changed / max(len(samples), 1), 4)})

    # The identity that makes the whole scheme work - assert it, do not hope.
    post = stable_digest(stego_samples, n_lsb)
    t.add("verify_invariant", "Stable digest unchanged by embedding",
          {"match": post == digest}, ok=(post == digest))

    return ProtectResult(
        stego_view=stego_view, payload=payload, signature=signature,
        start_unit=start, n_lsb=n_lsb, stream_bytes=len(stream),
        capacity_bits=capacity_bits, needed_bits=needed_bits, algo=algo,
        trace=trace,
        details={"digest_hex": digest.hex(), "changed_bytes": changed,
                 "placement": preview,
                 "public_fingerprint": public_fingerprint(priv.public_key())},
    )


# --- verify -----------------------------------------------------------------
def verify(stego: CoverView, media_id: str, n_lsb: int, passphrase: str, pub, *,
           codec: Codec, bits: Bitstream, algo: str | None = None,
           trace: Trace | None = None) -> Verdict:
    """
    Steps 7-10 of the spec's security workflow. Never raises for a failed
    check - a failure is a verdict, and the caller always gets one back.
    """
    t = trace if trace is not None else NullTrace()  # empty Trace is falsy
    try:
        return _verify_inner(stego, media_id, n_lsb, passphrase, pub,
                             codec=codec, bits=bits, algo=algo, t=t, trace=trace)
    except CapacityError as exc:
        return _cannot(t, trace, "Capacity error: {}".format(exc))
    except KeyError_ as exc:
        return _cannot(t, trace, "Key problem: {}".format(exc))
    except A2Error as exc:
        return _cannot(t, trace, str(exc))
    except Exception as exc:                      # verdict 1: never crash the GUI
        return _cannot(t, trace, "Unexpected error during verification: {}: {}".format(
            type(exc).__name__, exc))


def _verify_inner(stego, media_id, n_lsb, passphrase, pub, *, codec, bits, algo, t, trace):
    _check_lsb(n_lsb)
    if pub is None:
        raise KeyError_("A public key is required to verify a signature.")
    algo = algo or algo_of_key(pub)

    samples = codec.read_samples(stego)
    capacity_bits = codec.capacity_bits(stego, n_lsb)
    capacity_units = capacity_bits // n_lsb
    t.add("capacity", "Stego capacity measured",
          {"units": len(samples), "capacity_bits": capacity_bits, "n_lsb": n_lsb})

    secrets = derive_secrets(passphrase)
    t.add("derive_secrets", "HKDF re-derived location and message keys from passphrase", {})

    start = derive_start(secrets, media_id, capacity_bits, n_lsb)
    t.add("derive_start", "Start offset re-derived - no stored hint was read",
          {"start_unit": start, "media_id": media_id, "n_lsb": n_lsb})

    # -- header + magic ------------------------------------------------------
    header_bits = bits.header_size_bits(n_lsb)
    header = bits.extract(samples, n_lsb, start, header_bits)
    has_magic = bits.has_magic(header)
    t.add("magic_check", "Magic bytes at derived offset: {}".format(
        "present" if has_magic else "ABSENT"),
        {"expected": port_magic(bits).decode("latin-1"),
         "got": header[:4].decode("latin-1", "replace")},
        blob=header, ok=has_magic)

    if not has_magic:
        return _locate_failure(samples, secrets, media_id, capacity_units,
                               header_bits, n_lsb, start, bits, t, trace)

    # -- verdict 4: header parses but is self-inconsistent -------------------
    try:
        info = bits.header_info(header) if hasattr(bits, "header_info") else {}
        total_bits = bits.declared_total_bits(header)
    except HeaderError as exc:
        return _cannot(t, trace, "Corrupt header at the derived offset: {}".format(exc))

    remaining_bits = (len(samples) - start) * n_lsb
    if total_bits > remaining_bits:
        t.fail("header", "Declared length exceeds remaining capacity",
               {"declared_bits": total_bits, "remaining_bits": remaining_bits})
        return _cannot(t, trace,
                       "Header declares {:,} bits but only {:,} remain from the "
                       "start offset - the header is corrupt.".format(
                           total_bits, remaining_bits))
    t.add("header", "Header parsed", info or {"declared_bits": total_bits})

    if info and info.get("n_lsb") and info["n_lsb"] != n_lsb:
        t.fail("header", "Embedded LSB depth differs from the selected one",
               {"embedded": info["n_lsb"], "selected": n_lsb})

    # -- extract + unframe ---------------------------------------------------
    stream = bits.extract(samples, n_lsb, start, total_bits)
    try:
        payload_bytes, signature = bits.unpack(stream)
    except HeaderError as exc:
        return _cannot(t, trace, "Could not unframe the stream: {}".format(exc))
    t.add("extract_body", "Payload and signature extracted",
          {"payload_bytes": len(payload_bytes), "sig_bytes": len(signature)},
          blob=payload_bytes[:96])

    # -- verdict 5: signature ------------------------------------------------
    header_algo = (info or {}).get("algo")
    if header_algo in config.ALGO_IDS:
        algo = header_algo
    sig_ok = verify_signature(payload_bytes, signature, pub, algo)
    t.add("verify_sig", "Signature {}".format("VALID" if sig_ok else "INVALID"),
          {"algo": algo, "public_fingerprint": public_fingerprint(pub)},
          blob=signature[:32], ok=sig_ok)
    if not sig_ok:
        payload_maybe = _try_parse(payload_bytes)
        return Verdict(
            VerdictCode.SIGNATURE_INVALID,
            "The payload was recovered but its signature does not verify under "
            "this public key. The record was altered, or it was signed with a "
            "different private key.",
            payload=payload_maybe, trace=trace,
            details={"algo": algo, "start_unit": start,
                     "public_fingerprint": public_fingerprint(pub)},
        )

    try:
        payload = payload_from_bytes(payload_bytes)
    except Exception as exc:
        return _cannot(t, trace, "Signature verified but the payload JSON is "
                                 "malformed: {}".format(exc))
    t.add("unpack", "Payload record parsed",
          {"media_id": payload.media_id, "ts": payload.ts, "enc": payload.enc,
           "n_lsb": payload.n_lsb})

    # -- verdict 6: cover hash -----------------------------------------------
    recomputed = stable_digest(samples, payload.n_lsb)
    hash_ok = recomputed.hex() == payload.cover_hash
    t.add("compare_hash", "Cover hash {}".format("matches" if hash_ok else "MISMATCH"),
          {"expected": payload.cover_hash[:32] + "...",
           "recomputed": recomputed.hex()[:32] + "...",
           "hashed_bits_per_byte": tamper_detection_strength(payload.n_lsb)[
               "bits_hashed_per_byte"]},
          ok=hash_ok)
    if not hash_ok:
        return Verdict(
            VerdictCode.TAMPERED,
            "The signature is valid, so this payload really was issued by the "
            "key holder - but the cover content has changed since it was "
            "signed. The media was tampered with after protection.",
            payload=payload, trace=trace,
            details={"expected_hash": payload.cover_hash,
                     "recomputed_hash": recomputed.hex(), "start_unit": start},
        )

    # -- verdict 7: message decryption ---------------------------------------
    try:
        message = decrypt_message(payload, secrets)
    except DecryptionError as exc:
        t.fail("decrypt", "AES-GCM authentication failed", {"error": str(exc)})
        return Verdict(
            VerdictCode.CANNOT_VERIFY,
            "Signature and cover hash both check out, but the hidden message "
            "could not be decrypted: {}".format(exc),
            payload=payload, trace=trace,
            details={"stage": "decrypt", "start_unit": start},
        )
    t.add("decrypt", "Hidden message decrypted",
          {"enc": payload.enc, "message_bytes": len(message)})

    # -- verdict 8 -----------------------------------------------------------
    t.add("verdict", "AUTHENTIC", {"start_unit": start, "algo": algo})
    return Verdict(
        VerdictCode.AUTHENTIC,
        "Payload found at the derived offset, signature valid under the "
        "supplied public key, cover hash matches, and the message decrypted "
        "with an intact GCM tag.",
        payload=payload, message=message, trace=trace,
        details={"start_unit": start, "algo": algo,
                 "cover_hash": payload.cover_hash,
                 "public_fingerprint": public_fingerprint(pub),
                 "issued_at": payload.ts, "nonce": payload.nonce},
    )


# --- verdicts 2 and 3 -------------------------------------------------------
def _locate_failure(samples, secrets, media_id, capacity_units, header_bits,
                    n_lsb, start, bits, t, trace):
    """
    No magic at the derived offset. Decide between WRONG_START_LOCATION and
    PAYLOAD_MISSING. Cheap keyed probe first, then the bounded scan.
    """
    alt = probe_other_lsb_depths(samples, secrets, media_id, capacity_units,
                                 header_bits, n_lsb, bits)
    if alt is not None:
        t.add("scan", "Payload found at the offset for a different LSB depth", alt, ok=False)
        return Verdict(
            VerdictCode.WRONG_START_LOCATION,
            "No payload at the offset derived for {} LSB(s), but one is present "
            "at the offset these same parameters derive for {} LSB(s). The LSB "
            "selection does not match the one used to embed.".format(
                n_lsb, alt["n_lsb"]),
            trace=trace,
            details={"derived_start": start, "found_at": alt["start_unit"],
                     "correct_n_lsb": alt["n_lsb"], "selected_n_lsb": n_lsb},
        )

    t0 = time.perf_counter()
    scan = scan_for_magic(samples, n_lsb, magic=port_magic(bits),
                          skip_offset=start)
    t.add("scan", scan.note,
          {"found": scan.found, "offset": scan.offset,
           "ms": round((time.perf_counter() - t0) * 1000, 1)}, ok=False)

    if scan.found:
        return Verdict(
            VerdictCode.WRONG_START_LOCATION,
            "A payload IS embedded in this file, at unit {}, but these "
            "parameters derive offset {}. The passphrase or media ID does not "
            "match the one used to embed.".format(scan.offset, start),
            trace=trace,
            details={"derived_start": start, "found_at": scan.offset,
                     "n_lsb": n_lsb},
        )

    return Verdict(
        VerdictCode.PAYLOAD_MISSING,
        "No payload signature found at the derived offset or anywhere else in "
        "the cover at {} LSB(s). This file does not appear to carry a "
        "payload.".format(n_lsb),
        trace=trace,
        details={"derived_start": start, "n_lsb": n_lsb,
                 "scan_note": scan.note},
    )


# --- helpers ----------------------------------------------------------------
def port_magic(bits: Bitstream) -> bytes:
    """
    The magic bytes belong to whichever Bitstream implementation is plugged
    in, not to A2. ReferenceBitstream uses b"INF2"; person 1's engine uses
    b"STG1". Hardcoding config.MAGIC here would make the bounded scan hunt
    for the wrong marker and mis-report a relocated payload as missing.
    """
    return getattr(bits, "MAGIC", config.MAGIC)


def _cannot(t, trace, reason: str) -> Verdict:
    t.fail("verdict", "CANNOT_VERIFY", {"reason": reason})
    return Verdict(VerdictCode.CANNOT_VERIFY, reason, trace=trace)


def _try_parse(payload_bytes: bytes):
    try:
        return payload_from_bytes(payload_bytes)
    except Exception:
        return None


def _check_lsb(n_lsb: int) -> None:
    if not isinstance(n_lsb, int) or not (config.MIN_LSB <= n_lsb <= config.MAX_LSB):
        raise ValueError("n_lsb must be an int in {}..{}, got {!r}".format(
            config.MIN_LSB, config.MAX_LSB, n_lsb))
