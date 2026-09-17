# INF2005-ACW1-Steganography
Image and Audio Steganography, Digital Signatures and Security Verification

## To Run it

```bash
pip install pillow numpy
python tests\test_image_codec.py
```
### For Image
Produces `cat_cover.png`, `cat_stego.png`, `cat_tampered.png`,
`cat_diff.png` in this folder so you can see the LSB changes are
invisible until amplified.

---

## A2 — Crypto & Verdict layer (hashing, signatures, start location, verdicts)

Covers FR3, FR4, FR7, FR9, FR10. Self-contained in `a2_crypto/`; imports
nothing from the other packages.

```bash
pip install cryptography                # a2_crypto's only dependency

python -m a2_crypto.selftest            # 18 internal cases -> "ALL CHECKS PASSED"
python a2_integration.py                # same pipeline over the real PNG and WAV
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
