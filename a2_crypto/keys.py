"""
keys.py - keypair generation, PEM storage, and passphrase -> secret derivation.

Two distinct kinds of secret live here and must not be confused:

  * the SIGNING keypair  - asymmetric. The private key proves who issued a
    payload; the public key is what a verifier needs and is safe to publish.
  * the SHARED PASSPHRASE - symmetric. Both sides need it, and it feeds HKDF
    to produce the start-location key and the message-encryption key.

Someone holding only the public key can check authenticity but cannot find
the payload. Someone holding only the passphrase can find and decrypt the
payload but cannot forge one. That separation is deliberate.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config
from .errors import KeyError_


# --- key bundle -------------------------------------------------------------
@dataclass
class KeyBundle:
    algo: str
    private_key: object
    public_key: object

    def public_bytes_raw(self) -> bytes:
        """Short public-key fingerprint material, for the trace panel."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def generate_keypair(algo: str = config.DEFAULT_SIGN_ALGO) -> KeyBundle:
    if algo == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
    elif algo == "rsa2048-pss":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=config.RSA_KEY_SIZE)
    else:
        raise KeyError_(f"Unknown signature algorithm {algo!r}. Known: {list(config.ALGO_IDS)}")
    return KeyBundle(algo=algo, private_key=priv, public_key=priv.public_key())


def save_keypair(kb: KeyBundle, priv_path: str, pub_path: str) -> None:
    priv_pem = kb.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = kb.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    for path, blob in ((priv_path, priv_pem), (pub_path, pub_pem)):
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(blob)


def load_private(path: str):
    try:
        with open(path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    except FileNotFoundError as exc:
        raise KeyError_(f"Private key not found: {path}") from exc
    except Exception as exc:
        raise KeyError_(f"Could not load private key from {path}: {exc}") from exc


def load_public(path: str):
    try:
        with open(path, "rb") as fh:
            return serialization.load_pem_public_key(fh.read())
    except FileNotFoundError as exc:
        raise KeyError_(f"Public key not found: {path}") from exc
    except Exception as exc:
        raise KeyError_(f"Could not load public key from {path}: {exc}") from exc


def algo_of_key(key) -> str:
    """Infer the registry name from a loaded key object."""
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "ed25519"
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "rsa2048-pss"
    raise KeyError_(f"Unsupported key type: {type(key).__name__}")


def public_fingerprint(pub) -> str:
    """First 8 hex chars of SHA-256 over the DER public key - shown in the GUI."""
    from .hashing import sha256
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(der).hex()[:16]


# --- passphrase -> secrets --------------------------------------------------
@dataclass(frozen=True)
class Secrets:
    """
    Derived key material. Frozen, and built fresh per call - no global state,
    so two verifications running back to back cannot influence each other.
    """
    k_loc: bytes   # start-location HMAC key
    k_enc: bytes   # AES-256-GCM message key

    def __repr__(self) -> str:   # never print key material
        return f"Secrets(k_loc=<{len(self.k_loc)}B>, k_enc=<{len(self.k_enc)}B>)"


def _hkdf(passphrase: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=config.SECRET_LEN,
        salt=config.KDF_SALT,
        info=info,
    ).derive(passphrase)


def derive_secrets(passphrase: str) -> Secrets:
    """
    One passphrase -> two independent keys, separated by HKDF info labels.
    Distinct labels mean recovering the start-location key tells an attacker
    nothing about the encryption key.
    """
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str")
    pw = passphrase.encode("utf-8")
    return Secrets(
        k_loc=_hkdf(pw, config.INFO_START_LOCATION),
        k_enc=_hkdf(pw, config.INFO_PAYLOAD_ENCRYPTION),
    )
