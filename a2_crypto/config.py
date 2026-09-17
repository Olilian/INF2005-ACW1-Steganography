"""
config.py - every tunable in the A2 layer.

Plug-and-play rule 5: nothing in this package hardcodes an algorithm name,
a length, a label or a magic byte inline. It lives here, so swapping a
scheme is a config edit rather than a refactor.
"""
from __future__ import annotations

# --- versioning -------------------------------------------------------------
API_VERSION = "1.0"          # public surface version, checked by the host app
PAYLOAD_SCHEMA_VERSION = 1   # bumped when the payload JSON shape changes

# --- signature scheme -------------------------------------------------------
# Key into the SIGNERS registry in signing.py.
# ed25519      : 32-byte public key, fixed 64-byte signature, no parameters
#                to get wrong. Chosen as default because signature size is
#                capacity at 1 LSB in a small WAV.
# rsa2048-pss  : registered alternative, 256-byte signature.
DEFAULT_SIGN_ALGO = "ed25519"

RSA_KEY_SIZE = 2048

# --- hashing ----------------------------------------------------------------
HASH_NAME = "sha256"
HASH_LEN = 32

# --- KDF / secret derivation ------------------------------------------------
# HKDF-SHA256. One passphrase -> several independent keys, separated by the
# info label so a compromise of one does not hand over the others.
KDF_SALT = b"INF2005-ACW1"
INFO_START_LOCATION = b"start-location"
INFO_PAYLOAD_ENCRYPTION = b"payload-encryption"
SECRET_LEN = 32

# --- message encryption -----------------------------------------------------
AEAD_NAME = "aes-256-gcm"
AEAD_NONE = "none"
GCM_IV_LEN = 12
GCM_TAG_LEN = 16

# --- payload ----------------------------------------------------------------
NONCE_LEN = 12               # bytes of randomness -> 24 hex chars
TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%SZ"

DEFAULT_META = {
    "team": "P1-4",
    "issuer": "A2-crypto-v1.0",
    "purpose": "release-verification",
}

# --- reference bitstream header ---------------------------------------------
# MAGIC(4) | VER u8 | ALG u8 | N_LSB u8 | FLAGS u8 | PAYLOAD_LEN u32 | SIG_LEN u16
MAGIC = b"INF2"
BITSTREAM_VERSION = 1
HEADER_STRUCT = ">4sBBBBIH"
HEADER_SIZE_BYTES = 14

# Algorithm ids stored in the header byte, so a decoder knows which verifier
# to use before it has parsed the payload.
ALGO_IDS = {"ed25519": 1, "rsa2048-pss": 2}
ALGO_BY_ID = {v: k for k, v in ALGO_IDS.items()}

# --- start location ---------------------------------------------------------
# Ceiling on the embedded stream, which sizes the reserved tail behind the
# keyed placement window (see location.py). 32 KiB is far above the spec's
# "large message" case while leaving most of a real cover usable as placement
# range. Raising it shrinks the range an attacker must brute-force.
MAX_STREAM_BITS = 262144        # 32 KiB
# Cap on how many candidate offsets the bounded scan will accept as magic
# hits before giving up. The scan exists only to tell "wrong location" apart
# from "nothing embedded" - it is not an extraction path.
MAX_SCAN_HITS = 64

# --- limits -----------------------------------------------------------------
MAX_LSB = 8
MIN_LSB = 1
MAX_PAYLOAD_BYTES = 1 << 20  # sanity ceiling when parsing a declared length
