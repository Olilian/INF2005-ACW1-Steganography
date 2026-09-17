"""
image_codec.py — Image codec (role 3, owned by you)
======================================================
PNG pixel read/write, embed/extract at a given start offset with selectable
bit depth (1-8), capacity check, and before/after comparison + diff image.

Built against payload_temp.py for now (build_protectable_blob /
open_protected_blob). When A's real bitstream/crypto module lands, swap
those two imports for the real equivalents — this file's embed/extract
logic doesn't need to change, since it operates on raw bytes/bits and
doesn't care how the blob was constructed.
"""
from PIL import Image
import numpy as np

import payload_temp as pt
from bitstream import bitstream_engine as be

# ---------------------------------------------------------------------------
# PNG read/write
# ---------------------------------------------------------------------------
def load_image(path: str) -> np.ndarray:
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA") if "A" in img.mode else img.convert("RGB")
    return np.array(img, dtype=np.uint8)


def save_image(arr: np.ndarray, path: str) -> None:
    mode = "RGBA" if arr.shape[-1] == 4 else "RGB"
    Image.fromarray(arr, mode=mode).save(path, format="PNG")


# ---------------------------------------------------------------------------
# Capacity (mandatory "is payload larger than cover?" test case)
# ---------------------------------------------------------------------------
def capacity_units(arr: np.ndarray) -> int:
    """One unit = one channel value (one R/G/B/A byte)."""
    return int(arr.size)


def capacity_check(arr: np.ndarray, blob: bytes, bit_depth: int) -> dict:
    cap_units = capacity_units(arr)
    req_units = pt.required_units(len(blob) * 8, bit_depth)
    return {
        "fits": req_units <= cap_units,
        "capacity_units": cap_units,
        "required_units": req_units,
        "bit_depth": bit_depth,
        "blob_size_bytes": len(blob),
    }


# ---------------------------------------------------------------------------
# n-LSB embed / extract at a caller-supplied offset (start_unit).
# Start-location DERIVATION is A's job (Criterion 1) — this codec just
# embeds/extracts wherever it's told to. Feed it a random int for now to
# keep testing independent of A's work.
# ---------------------------------------------------------------------------
def embed_at_offset(arr: np.ndarray, blob: bytes, start_unit: int, bit_depth: int) -> np.ndarray:
    """Returns a NEW array — does not mutate the original (need it for before/after)."""
    if not (1 <= bit_depth <= 8):
        raise ValueError("bit_depth must be 1-8")

    flat = arr.flatten().copy()
    values = be.bytes_to_unit_values(blob, bit_depth)
    num_units = len(values)

    if start_unit < 0 or start_unit + num_units > flat.size:
        raise ValueError(
            f"Payload needs {num_units} units starting at {start_unit}, "
            f"image only has {flat.size} units."
        )

    mask = np.uint8(0xFF ^ ((1 << bit_depth) - 1))
    for i, value in enumerate(values):
        idx = start_unit + i
        flat[idx] = (flat[idx] & mask) | np.uint8(value)

    return flat.reshape(arr.shape)


def _extract_header_bytes(arr: np.ndarray, start_unit: int, bit_depth: int) -> bytes:
    header_bits_needed = pt.HEADER_SIZE_BYTES * 8
    num_units = pt.required_units(header_bits_needed, bit_depth)
    flat = arr.flatten()
    if start_unit < 0 or start_unit + num_units > flat.size:
        raise ValueError("Start location out of range while reading header")

    low_mask = (1 << bit_depth) - 1
    values = [int(flat[start_unit + i]) & low_mask for i in range(num_units)]
    return be.unit_values_to_bytes(values, bit_depth, total_bytes=pt.HEADER_SIZE_BYTES)


def extract_at_offset(arr: np.ndarray, start_unit: int, bit_depth: int) -> bytes:
    """
    Reads the fixed-size header first to learn payload/signature lengths,
    then reads the rest. Returns the full blob (header + payload + signature)
    ready to hand to payload_temp.unpack() / open_protected_blob().

    Raises ValueError if the start location is clearly out of range.
    Does NOT raise on a bad magic byte / corrupt header — that's the
    caller's job to interpret as Verdict.PAYLOAD_MISSING via
    payload_temp.open_protected_blob().
    """
    header = _extract_header_bytes(arr, start_unit, bit_depth)
    try:
        header_info = be.parse_header(header)
    except be.UnpackError:
        # Return what we have — let open_protected_blob() classify it.
        return header

    total_bytes = pt.HEADER_SIZE_BYTES + header_info["payload_len"] + header_info["sig_len"]
    total_bits = total_bytes * 8
    num_units = pt.required_units(total_bits, bit_depth)

    flat = arr.flatten()
    if start_unit + num_units > flat.size:
        raise ValueError("Declared payload length exceeds image capacity from this start location")

    low_mask = (1 << bit_depth) - 1
    values = [int(flat[start_unit + i]) & low_mask for i in range(num_units)]
    return be.unit_values_to_bytes(values, bit_depth, total_bytes=total_bytes)


# ---------------------------------------------------------------------------
# Hashing that survives the embedding itself
# ---------------------------------------------------------------------------
def mask_low_bits(arr: np.ndarray, bit_depth: int) -> np.ndarray:
    """
    Zero out the low bit_depth bits of every channel value. The cover hash
    must be computed on THIS, not on the raw bytes — otherwise verification
    always reports Tampered, because embedding the payload necessarily
    changes those exact bits. Any tampering OUTSIDE the LSB planes (which
    is what real tamper tests do — flipping visible pixel values) still
    changes the masked bytes and is still caught.
    """
    mask = np.uint8(0xFF ^ ((1 << bit_depth) - 1))
    return (arr & mask).astype(np.uint8)


# ---------------------------------------------------------------------------
# Before/after comparison + diff image (your role's specific deliverable)
# ---------------------------------------------------------------------------
def compare_images(cover_arr: np.ndarray, stego_arr: np.ndarray) -> dict:
    """Summary stats for the GUI / test evidence."""
    if cover_arr.shape != stego_arr.shape:
        raise ValueError("Cover and stego images have different shapes — can't compare directly")

    diff = np.abs(cover_arr.astype(int) - stego_arr.astype(int))
    changed_mask = diff.any(axis=-1) if cover_arr.ndim == 3 else diff.astype(bool)

    return {
        "changed_pixels": int(changed_mask.sum()),
        "total_pixels": int(changed_mask.size),
        "percent_changed": round(100 * changed_mask.sum() / changed_mask.size, 4),
        "max_channel_delta": int(diff.max()),
    }


def make_diff_image(cover_arr: np.ndarray, stego_arr: np.ndarray, amplify: int = 32) -> np.ndarray:
    """
    Visual diff: amplifies per-channel differences so 1-2 LSB changes
    (normally invisible) show up clearly as a heatmap-style image.
    """
    if cover_arr.shape != stego_arr.shape:
        raise ValueError("Cover and stego images have different shapes — can't diff directly")

    diff = np.abs(cover_arr.astype(int) - stego_arr.astype(int))
    amplified = np.clip(diff * amplify, 0, 255).astype(np.uint8)
    return amplified


# ---------------------------------------------------------------------------
# High-level convenience wrappers tying this codec to payload_temp for now
# ---------------------------------------------------------------------------
def protect_image(cover_path: str, output_path: str, media_id: str, metadata: dict,
                   bit_depth: int, start_unit: int) -> dict:
    arr = load_image(cover_path)
    # Hash the cover with the LSB planes we're about to write to already
    # zeroed, so embedding itself doesn't change the hash (see mask_low_bits).
    hashable_bytes = mask_low_bits(arr, bit_depth).tobytes()
    blob, payload = pt.build_protectable_blob(hashable_bytes, media_id, metadata, n_lsb=bit_depth)

    check = capacity_check(arr, blob, bit_depth)
    if not check["fits"]:
        raise ValueError(f"Payload too large for cover at this bit depth: {check}")

    stego_arr = embed_at_offset(arr, blob, start_unit, bit_depth)
    save_image(stego_arr, output_path)

    return {"payload": payload, "capacity_check": check, "start_unit": start_unit, "output_path": output_path}


def verify_image(stego_path: str, bit_depth: int, start_unit: int) -> dict:
    arr = load_image(stego_path)
    try:
        blob = extract_at_offset(arr, start_unit, bit_depth)
    except ValueError as exc:
        return {"verdict": pt.Verdict.WRONG_START_LOCATION, "payload": None, "detail": str(exc)}

    verdict, payload, detail = pt.open_protected_blob(blob)
    if verdict != pt.Verdict.AUTHENTIC or payload is None:
        return {"verdict": verdict, "payload": payload, "detail": detail}

    # signature was fine — now check hash to catch tampering.
    # Mask the same LSB planes the encoder ignored, so the embedding itself
    # doesn't register as a mismatch — only genuine tampering elsewhere does.
    current_hash = pt.hash_bytes(mask_low_bits(arr, bit_depth).tobytes())
    embedded_hash = payload["hash"].split("sha256:")[-1]
    if current_hash != embedded_hash:
        return {"verdict": pt.Verdict.TAMPERED, "payload": payload,
                "detail": "Signature valid but recomputed hash does not match embedded hash"}

    return {"verdict": pt.Verdict.AUTHENTIC, "payload": payload, "detail": "Signature and hash both check out"}
