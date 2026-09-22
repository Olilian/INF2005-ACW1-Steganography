"""
audio_codec.py - WAV/PCM I/O and before/after comparison (role 4).

Payload construction, signing, start-location derivation, and n-LSB
embed/extract are all owned by the shared pipeline (a2_crypto +
a2_integration.AudioCodecAdapter + A1BitstreamAdapter) - same split as
image_codec.py. This file only reads, writes and compares raw PCM bytes.
"""
import wave
import numpy as np


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


# which raw bytes are safe to carry LSB changes
def embeddable_view(arr: np.ndarray, sampwidth: int) -> np.ndarray:
    """
    The subset of raw PCM bytes safe to embed into: the low byte of each
    sample. For 8-bit PCM every byte already IS a full sample (no separate
    high byte), so this returns everything. For 16/24/32-bit PCM, only the
    least-significant byte of each sample is included — flipping LSBs in
    a HIGH byte moves the sample value by up to (2**bit_depth - 1) * 256,
    an audible jump, instead of an inaudible rounding change.

    WAV PCM is little-endian, so the low byte of each sample is the FIRST
    byte of every sampwidth-byte group: indices 0, sampwidth, 2*sampwidth, ...
    """
    if sampwidth <= 0:
        raise ValueError("sample width must be positive")
    return arr[::sampwidth].copy()


def merge_embeddable_view(arr: np.ndarray, sampwidth: int, low_bytes: np.ndarray) -> np.ndarray:
    """
    Inverse of embeddable_view(): writes low_bytes back into their original
    stride positions in a full-length copy of arr, leaving every other byte
    (the high bytes of multi-byte samples) exactly as they were.
    """
    out = arr.copy()
    out[::sampwidth] = low_bytes
    return out


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
