# INF2005-ACW1-Steganography
Image and Audio Steganography, Digital Signatures and Security Verification

## To Run it

pip install pillow numpy cryptography

python tests\test_image_codec.py

### For Image
Produces image_stego.png, image_diff.png, image_tampered.png, and a
full LSB-depth sweep (image_stego_lsb1.png ... lsb8.png, image_diff_lsb1.png
... lsb8.png) under tests/test_evidence/image/, demonstrating the payload
is recoverable and imperceptible across all 8 selectable bit depths.

> To be deleted for final submission
# Bitstream Engine
## What my module is responsible for (in plain English)

My code is the translator that sits between "a stream of bytes" (the
payload — header + signed data) and "a list of small numbers, one per
pixel or audio sample" (what the image/audio codec actually writes into
LSBs). It never touches a pixel, a WAV file, or a PNG directly. It also
defines the **self-describing header** so a stego file can tell a
verifier how it was built (bit depth, payload length, signature length)
without needing that information passed in separately.

Concretely, three jobs:
1. **Header framing** — magic bytes + version + n_lsb + payload length +
   signature length, packed and parsed
2. **Bit packing math** — turning payload bytes into N-bit chunks (N =
   1 to 8, selectable), and back again
3. **Capacity calculation** — pure math answering "does this payload fit
   in this cover file at this bit depth?" before anyone tries to embed

## Why this exists as a separate module (not just left inside the codecs)

Before my module: `image_codec.py` and `audio_codec.py` each had their
own copy-pasted version of the bit-packing loop, AND each one hardcoded
the header byte layout directly (`struct.unpack(">II", header[5:13])`)
instead of asking a shared function to parse it. That means:
- Two places to keep in sync if the header format ever changes
- No single source of truth for "what does a valid header look like"
- The header didn't even record which bit depth was used — a verifier
  had to be told the bit depth out-of-band, which is fragile

My module fixes this by being the *one* place that understands header
layout and bit-packing math. Both codecs can call into it identically —
which is also the "same Codec interface for image and audio" rule our
team agreed on, since audio and image cover objects don't need separate
bit-packing logic.

## File structure

```
bitstream/
├── __init__.py
├── bitstream_engine.py       ← the real module
└── test_bitstream_engine.py  ← my own tests, don't touch teammates' tests
```

## API reference

_(Fill this in / let the agent fill this in once implemented — keeping
placeholders here so I know what to expect and can sanity-check it.)_

| Function | What it does | Used by |
|---|---|---|
| `build_header(n_lsb, payload_len, sig_len)` | Packs the fixed-size header | `pack()` |
| `parse_header(header_bytes)` | Unpacks + validates the header, raises `UnpackError` on bad magic/truncation | `unpack()`, codecs during extraction |
| `pack(payload_bytes, signature, n_lsb)` | header + payload + signature → one blob ready to embed | codec `protect_*()` functions |
| `unpack(blob)` | blob → (payload_bytes, signature, n_lsb) | codec `verify_*()` functions |
| `required_units(num_bits, bit_depth)` | Ceiling-division capacity math | capacity checks |
| `capacity_check(cover_units, blob_size_bytes, bit_depth)` | Pure "does it fit" check, no array dependency | codec `capacity_check()` |
| `bytes_to_unit_values(data, n_lsb)` | Payload bytes → list of small ints to write into LSBs | codec `embed_at_offset()` |
| `unit_values_to_bytes(values, n_lsb, total_bytes)` | Inverse — LSB values read back → bytes | codec `extract_at_offset()` |

## Header format

Approved and applied — bumped `STG0` → `STG1` since the byte layout changed.

| Field | Size | Notes |
|---|---|---|
| Magic | 4 bytes | `STG1` (was `STG0` in the placeholder) |
| Version | 1 byte | `1` |
| n_lsb | 1 byte | **New** — not in the original placeholder header |
| Payload length | 4 bytes | big-endian |
| Signature length | 4 bytes | big-endian |

Total: 14 bytes (was 13).

`bit_depth` is still passed explicitly to `extract_at_offset()`/`verify_*()`
(Q3 from the build spec, deferred) — `n_lsb` in the header is recorded for
future cross-checking, not yet used to remove the explicit parameter,
since the verifier needs *some* bit depth to read the header itself
before it can learn n_lsb from it (chicken-and-egg otherwise).

## What changed in teammates' files (Step 2 plan, approved and applied)

- `payload_temp.py`: removed inline `MAGIC`/`VERSION`/`HEADER_SIZE_BYTES`/
  `UnpackError`/`pack()`/`unpack()`/`required_units()` — now re-exported
  from `bitstream.bitstream_engine`. `build_protectable_blob()` gained a
  required `n_lsb` param (forwarded into `pack()`). `open_protected_blob()`
  updated to unpack the new 3-tuple `(payload_bytes, signature, n_lsb)`
  from `unpack()` (n_lsb currently unused there — reserved for a future
  cross-check).
- `image/image_codec.py`: removed `_bytes_to_bits`/`_bits_to_bytes`;
  `embed_at_offset()` now calls `bitstream_engine.bytes_to_unit_values()`;
  `_extract_header_bytes()`/`extract_at_offset()` now call
  `bitstream_engine.unit_values_to_bytes()` and
  `bitstream_engine.parse_header()` instead of the hardcoded
  `struct.unpack(">II", header[5:13])`; `protect_image()` now passes
  `n_lsb=bit_depth` to `build_protectable_blob()`.
- `audio/audio_codec.py`: identical shape of changes to `image_codec.py`
  above (same functions, same reasoning); also dropped the now-unused
  `import struct`.
- `tests/test_audio_codec.py`: one required fallout fix — the
  signature-invalid test case called `pt.unpack()`/`pt.pack()` directly;
  updated to unpack/pack the new 3-tuple (adds `n_lsb`). No other test
  file needed changes; `tests/test_image_codec.py` doesn't call
  `pt.pack`/`pt.unpack` directly.

All three test suites (`bitstream/test_bitstream_engine.py`,
`tests/test_image_codec.py`, `tests/test_audio_codec.py`) pass after
these changes.
---

## A2 — Crypto & Verdict layer (hashing, signatures, start location, verdicts)

Covers FR3, FR4, FR7, FR9, FR10. Self-contained in `a2_crypto/`; imports
nothing from the other packages. Runs on person 1's bitstream engine through
`A1BitstreamAdapter`, and on the image and audio codecs through
`ImageCodecAdapter` / `AudioCodecAdapter` — all in `a2_integration.py`.

```bash
pip install cryptography                # a2_crypto's only dependency

python -m a2_crypto.selftest            # 18 internal cases -> "ALL CHECKS PASSED"
python a2_integration.py                # real PNG + WAV + person 1's bitstream,
                                        # then re-runs all 18 cases on that engine
python a2_debug_gui.py                  # Protect / Verify / Trace debug bench
```

`a2_integration.py` writes stego files and trace JSON to `a2_out/`, and creates
the demo keypair in `keys/` on first run.

**Verdicts:** `Authentic`, `Tampered`, `Signature Invalid`, `Payload Missing`,
`Wrong Start Location`, `Cannot Verify`. The passphrase, media ID and LSB count
must match between protect and verify, or the derived start offset moves and
you get `Wrong Start Location`.

Full details: [docs/A2_CRYPTO_README.md](docs/A2_CRYPTO_README.md).
Team integration notes: [docs/A2_HANDOFF.md](docs/A2_HANDOFF.md).
