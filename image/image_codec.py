"""
PNG-specific I/O and before/after comparison. Payload construction, signing,
start-location derivation, and n-LSB embed/extract are all owned by the
shared pipeline (a2_crypto + a2_integration.ImageCodecAdapter +
A1BitstreamAdapter).
"""

from PIL import Image
import numpy as np

# PNG read/write
def load_image(path: str) -> np.ndarray:
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA") if "A" in img.mode else img.convert("RGB")
    return np.array(img, dtype=np.uint8)


def save_image(arr: np.ndarray, path: str) -> None:
    mode = "RGBA" if arr.shape[-1] == 4 else "RGB"
    Image.fromarray(arr, mode=mode).save(path, format="PNG")


# Before/after comparison + diff image
def compare_images(cover_arr: np.ndarray, stego_arr: np.ndarray) -> dict:
    """Summary stats for the GUI / test evidence."""
    if cover_arr.shape != stego_arr.shape:
        raise ValueError("Cover and stego images have different shapes: cannot compare directly")

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
        raise ValueError("Cover and stego images have different shapes: cannot diff directly")

    diff = np.abs(cover_arr.astype(int) - stego_arr.astype(int))
    amplified = np.clip(diff * amplify, 0, 255).astype(np.uint8)
    return amplified