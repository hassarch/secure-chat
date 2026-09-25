"""
Cryptographic primitives wrapper module.

This module provides a clean interface to libsodium primitives via PyNaCl
and additional crypto functions from the cryptography library.

All primitives are from vetted libraries - NO custom crypto is implemented.
"""

from .primitives import (
    generate_x25519_keypair,
    x25519_dh,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    hkdf_derive,
    aead_encrypt,
    aead_decrypt,
    derive_key_from_password,
    constant_time_compare,
    generate_random_bytes,
)

__all__ = [
    "generate_x25519_keypair",
    "x25519_dh",
    "generate_ed25519_keypair",
    "ed25519_sign",
    "ed25519_verify",
    "hkdf_derive",
    "aead_encrypt",
    "aead_decrypt",
    "derive_key_from_password",
    "constant_time_compare",
    "generate_random_bytes",
]
