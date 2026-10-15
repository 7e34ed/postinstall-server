"""Ed25519-подпись для seal'ов."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def sign(privkey_pem: bytes | str, data: bytes) -> str:
    if isinstance(privkey_pem, str):
        privkey_pem = privkey_pem.encode()
    priv = serialization.load_pem_private_key(privkey_pem, password=None)
    sig = priv.sign(data)
    return base64.b64encode(sig).decode()


def verify(pubkey_pem: bytes | str, data: bytes, signature_b64: str) -> bool:
    if isinstance(pubkey_pem, str):
        pubkey_pem = pubkey_pem.encode()
    try:
        pub = serialization.load_pem_public_key(pubkey_pem)
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except Exception:
        return False