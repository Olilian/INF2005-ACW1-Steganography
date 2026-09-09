"""
audio_codec.py - audio codec (role 4)

WAV/PCM read/write, embed/extract at a given offset with selectable
bit depth (1-8), capacity check, waveform/playback comparison.

Uses payload_temp for now, swap to real crypto module once A is done.
Treats audio as raw PCM bytes (via wave module) instead of per-sample,
so one unit = one byte, same as image_codec's per-channel-byte approach.
"""
import wave
import struct
import numpy as np

import payload_temp as pt


# WAV/PCM read/write
class AudioParams:
    def __init__(self, n_channels, sampwidth, framerate, n_frames, comptype, compname):
        self.n_channels = n_channels
        self.sampwidth = sampwidth
        self.framerate = framerate
        self.n_frames = n_frames
        self.comptype = comptype
        self.compname = compname

    def as_wave_params(self):
        return (self.n_channels, self.sampwidth, self.framerate,
                self.n_frames, self.comptype, self.compname)


def load_audio(path: str):
    with wave.open(path, "rb") as wf:
        params = AudioParams(*wf.getparams())
        frames = wf.readframes(params.n_frames)
    arr = np.frombuffer(frames, dtype=np.uint8).copy()
    return arr, params


def save_audio(arr: np.ndarray, params: AudioParams, path: str) -> None:
    with wave.open(path, "wb") as wf:
        wf.setparams(params.as_wave_params())
        wf.writeframes(arr.tobytes())


# capacity check (mandatory "payload bigger than cover?" test case)
def capacity_units(arr: np.ndarray) -> int:
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


# n-LSB embed/extract at a given offset
# start-location derivation is A's job, this just embeds/extracts wherever told
def _bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def embed_at_offset(arr: np.ndarray, blob: bytes, start_unit: int, bit_depth: int) -> np.ndarray:
    # returns a new array, doesn't mutate original (need it for before/after)
    if not (1 <= bit_depth <= 8):
        raise ValueError("bit_depth must be 1-8")

    flat = arr.copy()
    bit_string = _bytes_to_bits(blob)
    pad = (-len(bit_string)) % bit_depth
    padded = bit_string + ("0" * pad)
    num_units = len(padded) // bit_depth

    if start_unit < 0 or start_unit + num_units > flat.size:
        raise ValueError(
            f"Payload needs {num_units} units starting at {start_unit}, "
            f"audio only has {flat.size} units."
        )

    mask = np.uint8(0xFF ^ ((1 << bit_depth) - 1))
    for i in range(num_units):
        value = np.uint8(int(padded[i * bit_depth:(i + 1) * bit_depth], 2))
        idx = start_unit + i
        flat[idx] = (flat[idx] & mask) | value

    return flat


def _extract_header_bytes(arr: np.ndarray, start_unit: int, bit_depth: int) -> bytes:
    header_bits_needed = pt.HEADER_SIZE_BYTES * 8
    num_units = pt.required_units(header_bits_needed, bit_depth)
    if start_unit < 0 or start_unit + num_units > arr.size:
        raise ValueError("Start location out of range while reading header")

    low_mask = (1 << bit_depth) - 1
    bits = "".join(
        format(int(arr[start_unit + i]) & low_mask, f"0{bit_depth}b")
        for i in range(num_units)
    )
    return _bits_to_bytes(bits[:header_bits_needed])


def extract_at_offset(arr: np.ndarray, start_unit: int, bit_depth: int) -> bytes:
    # reads header first to get payload/sig lengths, then reads the rest
    # bad magic bytes aren't raised here, caller handles via open_protected_blob
    header = _extract_header_bytes(arr, start_unit, bit_depth)
    if len(header) < pt.HEADER_SIZE_BYTES or header[:4] != pt.MAGIC:
        return header

    payload_len, sig_len = struct.unpack(">II", header[5:13])
    total_bytes = pt.HEADER_SIZE_BYTES + payload_len + sig_len
    total_bits = total_bytes * 8
    num_units = pt.required_units(total_bits, bit_depth)

    if start_unit + num_units > arr.size:
        raise ValueError("Declared payload length exceeds audio capacity from this start location")

    low_mask = (1 << bit_depth) - 1
    bits = "".join(
        format(int(arr[start_unit + i]) & low_mask, f"0{bit_depth}b")
        for i in range(num_units)
    )
    return _bits_to_bytes(bits[:total_bits])


# hashing that survives the embedding itself
def mask_low_bits(arr: np.ndarray, bit_depth: int) -> np.ndarray:
    # zero out low bits before hashing so embedding itself doesn't
    # trigger a false Tampered verdict. tampering outside LSB planes
    # still changes the masked bytes and still gets caught
    mask = np.uint8(0xFF ^ ((1 << bit_depth) - 1))
    return (arr & mask).astype(np.uint8)


# before/after comparison + waveform diff
def compare_audio(cover_arr: np.ndarray, stego_arr: np.ndarray) -> dict:
    if cover_arr.shape != stego_arr.shape:
        raise ValueError("Cover and stego audio have different lengths — can't compare directly")

    diff = np.abs(cover_arr.astype(int) - stego_arr.astype(int))
    changed_mask = diff.astype(bool)

    return {
        "changed_bytes": int(changed_mask.sum()),
        "total_bytes": int(changed_mask.size),
        "percent_changed": round(100 * changed_mask.sum() / changed_mask.size, 4),
        "max_byte_delta": int(diff.max()),
    }


def samples_for_waveform(arr: np.ndarray, params: AudioParams) -> np.ndarray:
    # reinterprets raw bytes as signed samples for GUI waveform plotting
    # display only, doesn't affect embed/extract
    sw = params.sampwidth
    if sw == 1:
        # 8-bit PCM is unsigned, midpoint 128
        return arr.astype(np.int16) - 128
    elif sw == 2:
        return arr.view(np.int16)
    elif sw == 4:
        return arr.view(np.int32)
    elif sw == 3:
        # no native numpy dtype for 24-bit, build manually
        b = arr.reshape(-1, 3)
        as_int32 = (
            b[:, 0].astype(np.int32)
            | (b[:, 1].astype(np.int32) << 8)
            | (b[:, 2].astype(np.int32) << 16)
        )
        as_int32 = np.where(as_int32 & 0x800000, as_int32 - 0x1000000, as_int32)
        return as_int32
    else:
        raise ValueError(f"Unsupported sample width: {sw} bytes")


# high-level wrappers tying this codec to payload_temp
def protect_audio(cover_path: str, output_path: str, media_id: str, metadata: dict,
                   bit_depth: int, start_unit: int) -> dict:
    arr, params = load_audio(cover_path)
    # hash cover with the LSB planes we're about to write already zeroed
    hashable_bytes = mask_low_bits(arr, bit_depth).tobytes()
    blob, payload = pt.build_protectable_blob(hashable_bytes, media_id, metadata)

    check = capacity_check(arr, blob, bit_depth)
    if not check["fits"]:
        raise ValueError(f"Payload too large for cover at this bit depth: {check}")

    stego_arr = embed_at_offset(arr, blob, start_unit, bit_depth)
    save_audio(stego_arr, params, output_path)

    return {"payload": payload, "capacity_check": check, "start_unit": start_unit, "output_path": output_path}


def verify_audio(stego_path: str, bit_depth: int, start_unit: int) -> dict:
    arr, params = load_audio(stego_path)
    try:
        blob = extract_at_offset(arr, start_unit, bit_depth)
    except ValueError as exc:
        return {"verdict": pt.Verdict.WRONG_START_LOCATION, "payload": None, "detail": str(exc)}

    verdict, payload, detail = pt.open_protected_blob(blob)
    if verdict != pt.Verdict.AUTHENTIC or payload is None:
        return {"verdict": verdict, "payload": payload, "detail": detail}

    # signature ok, now check hash to catch tampering
    # mask same LSB planes encoder ignored so embedding itself isn't flagged
    current_hash = pt.hash_bytes(mask_low_bits(arr, bit_depth).tobytes())
    embedded_hash = payload["hash"].split("sha256:")[-1]
    if current_hash != embedded_hash:
        return {"verdict": pt.Verdict.TAMPERED, "payload": payload,
                "detail": "Signature valid but recomputed hash does not match embedded hash"}

    return {"verdict": pt.Verdict.AUTHENTIC, "payload": payload, "detail": "Signature and hash both check out"}
