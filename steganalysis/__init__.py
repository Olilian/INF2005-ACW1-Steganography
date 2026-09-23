"""
steganalysis/ - optional challenge: Steganalysis.

Standalone from the rest of the project on purpose: this package imports
nothing from a2_crypto, the codecs or the bitstream engine, and needs none
of the passphrase/key material the rest of the app uses. It plays the role
of an outside analyst with only the stego file in hand.

See chi_square_attack.py and docs/STEGANALYSIS_README.md.
"""
