"""
Double Ratchet Algorithm for Ongoing Message Encryption

This module implements the Double Ratchet algorithm which provides:
- Forward secrecy: Past messages remain secure even if keys are compromised
- Post-compromise security: Future messages secure after compromise is detected
- Out-of-order message handling: Skipped message keys cached for later delivery

The algorithm uses two types of ratcheting:
1. Symmetric-key ratchet: KDF chains for deriving message keys
2. DH ratchet: Periodic Diffie-Hellman to rotate root keys

Reference: https://signal.org/docs/specifications/doubleratchet/
"""

from .state import (
    RatchetState,
    MessageHeader,
    TooManySkippedKeysError,
    DecryptionError,
    MAX_SKIP,
    SKIPPED_KEY_TTL,
)

from .ratchet import (
    kdf_rk,
    kdf_ck,
    initialize_sender,
    initialize_receiver,
    ratchet_encrypt,
    ratchet_decrypt,
    dh_ratchet_step,
    skip_message_keys,
    try_skipped_message_keys,
    INFO_ROOT_KEY,
    INFO_MESSAGE_KEY,
)

__all__ = [
    # State management
    "RatchetState",
    "MessageHeader",
    # Initialization
    "initialize_sender",
    "initialize_receiver",
    # Core operations
    "ratchet_encrypt",
    "ratchet_decrypt",
    # Low-level functions
    "kdf_rk",
    "kdf_ck",
    "dh_ratchet_step",
    "skip_message_keys",
    "try_skipped_message_keys",
    # Exceptions
    "TooManySkippedKeysError",
    "DecryptionError",
    # Constants
    "MAX_SKIP",
    "SKIPPED_KEY_TTL",
    "INFO_ROOT_KEY",
    "INFO_MESSAGE_KEY",
]
