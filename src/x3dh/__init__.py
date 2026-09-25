"""
X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol

This module implements the X3DH protocol for asynchronous key agreement.
X3DH allows two parties to establish a shared secret even when one is offline.

Key components:
- Prekey generation and management
- X3DH handshake (initiator and receiver sides)
- Signature verification for authentication

Reference: https://signal.org/docs/specifications/x3dh/
"""

from .prekeys import (
    IdentityKeyPair,
    SignedPrekeyPair,
    OneTimePrekeyPair,
    PrekeyBundle,
    PrekeyStore,
    generate_identity_keypair,
    generate_signed_prekey,
    generate_one_time_prekeys,
    create_prekey_bundle,
)

from .handshake import (
    X3DHResult,
    X3DHInitiator,
    X3DHReceiver,
    verify_shared_secrets_match,
    X3DH_INFO,
    X3DH_SALT,
)

__all__ = [
    # Prekey types
    "IdentityKeyPair",
    "SignedPrekeyPair",
    "OneTimePrekeyPair",
    "PrekeyBundle",
    "PrekeyStore",
    # Prekey functions
    "generate_identity_keypair",
    "generate_signed_prekey",
    "generate_one_time_prekeys",
    "create_prekey_bundle",
    # Handshake
    "X3DHResult",
    "X3DHInitiator",
    "X3DHReceiver",
    "verify_shared_secrets_match",
    # Constants
    "X3DH_INFO",
    "X3DH_SALT",
]
