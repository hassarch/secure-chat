"""
Double Ratchet Algorithm Implementation

This module implements the Double Ratchet algorithm for ongoing
message encryption with forward secrecy and post-compromise security.

Reference: Signal Double Ratchet Specification
https://signal.org/docs/specifications/doubleratchet/
"""

from typing import Tuple, Optional
import hmac
import hashlib
import time

from src.crypto.primitives import (
    generate_x25519_keypair,
    x25519_dh,
    hkdf_derive,
    aead_encrypt,
    aead_decrypt,
)
from src.ratchet.state import (
    RatchetState,
    MessageHeader,
    TooManySkippedKeysError,
    DecryptionError,
    MAX_SKIP,
)


# KDF constants
INFO_ROOT_KEY = b"DoubleRatchet-RootKey-v1"
INFO_MESSAGE_KEY = b"DoubleRatchet-MessageKey-v1"


def kdf_rk(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    Root Key KDF - Derive new root key and chain key from DH output.
    
    This is called during a DH ratchet step to rotate the root key
    and derive a new chain key.
    
    Args:
        root_key: Current root key (32 bytes)
        dh_output: Diffie-Hellman shared secret (32 bytes)
        
    Returns:
        Tuple of (new_root_key, chain_key), both 32 bytes
        
    Reference:
        Double Ratchet spec section 5.2 - KDF chains
    """
    output = hkdf_derive(
        input_key_material=dh_output,
        length=64,
        salt=root_key,
        info=INFO_ROOT_KEY
    )
    
    new_root_key = output[:32]
    chain_key = output[32:64]
    
    return new_root_key, chain_key


def kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    Chain Key KDF - Derive new chain key and message key.
    
    This implements the symmetric-key ratchet using HMAC-SHA256.
    Each step derives both the next chain key and a message key.
    
    Args:
        chain_key: Current chain key (32 bytes)
        
    Returns:
        Tuple of (new_chain_key, message_key), both 32 bytes
        
    Reference:
        Double Ratchet spec section 5.2 - KDF chains
        Uses HMAC-based construction for efficiency
    """
    # Derive new chain key: HMAC-SHA256(ck, 0x01)
    new_chain_key = hmac.new(
        chain_key,
        b'\x01',
        hashlib.sha256
    ).digest()
    
    # Derive message key: HMAC-SHA256(ck, 0x02)
    message_key = hmac.new(
        chain_key,
        b'\x02',
        hashlib.sha256
    ).digest()
    
    return new_chain_key, message_key


def initialize_sender(shared_secret: bytes, remote_public_key: bytes) -> RatchetState:
    """
    Initialize Double Ratchet as the sender (Alice).
    
    Called after X3DH completes. Alice performs an initial DH ratchet
    step to derive the first sending chain key.
    
    Args:
        shared_secret: 32-byte shared secret from X3DH
        remote_public_key: Bob's initial DH public key (32 bytes)
        
    Returns:
        Initialized RatchetState ready to send messages
        
    Reference:
        Double Ratchet spec section 3.2 - Initialization
    """
    # Generate our DH keypair
    dh_private, dh_public = generate_x25519_keypair()
    
    # Perform initial DH ratchet
    dh_output = x25519_dh(dh_private, remote_public_key)
    root_key, chain_key_send = kdf_rk(shared_secret, dh_output)
    
    return RatchetState(
        root_key=root_key,
        chain_key_send=chain_key_send,
        chain_key_recv=None,  # Will be set when receiving first message
        dh_private=dh_private,
        dh_public=dh_public,
        dh_remote=remote_public_key,
        send_msg_num=0,
        recv_msg_num=0,
        prev_chain_length=0,
        skipped_keys={}
    )


def initialize_receiver(shared_secret: bytes) -> RatchetState:
    """
    Initialize Double Ratchet as the receiver (Bob).
    
    Called after X3DH completes. Bob waits for Alice's first message
    to perform the first DH ratchet step.
    
    Args:
        shared_secret: 32-byte shared secret from X3DH
        
    Returns:
        Initialized RatchetState ready to receive messages
        
    Reference:
        Double Ratchet spec section 3.2 - Initialization
    """
    # Generate our DH keypair
    dh_private, dh_public = generate_x25519_keypair()
    
    return RatchetState(
        root_key=shared_secret,
        chain_key_send=None,  # Will be set after first DH ratchet
        chain_key_recv=None,  # Will be set when receiving first message
        dh_private=dh_private,
        dh_public=dh_public,
        dh_remote=None,  # Will be set from Alice's first message
        send_msg_num=0,
        recv_msg_num=0,
        prev_chain_length=0,
        skipped_keys={}
    )


def ratchet_encrypt(
    state: RatchetState,
    plaintext: bytes,
    associated_data: bytes = b""
) -> Tuple[MessageHeader, bytes, bytes]:
    """
    Encrypt a message using the Double Ratchet.
    
    Derives a new message key, encrypts the plaintext, and returns
    the header and ciphertext to send.
    
    Args:
        state: Current ratchet state (modified in place)
        plaintext: Message to encrypt
        associated_data: Additional authenticated data
        
    Returns:
        Tuple of (header, ciphertext, nonce)
        
    Reference:
        Double Ratchet spec section 2.3 - Encryption
    """
    # Derive message key from send chain key
    state.chain_key_send, message_key = kdf_ck(state.chain_key_send)
    
    # Create message header
    header = MessageHeader(
        dh_public=state.dh_public,
        prev_chain_length=state.prev_chain_length,
        message_number=state.send_msg_num
    )
    
    # Increment send counter
    state.send_msg_num += 1
    
    # Encrypt: AEAD(message_key, plaintext, header || AD)
    header_bytes = header.encode()
    full_ad = header_bytes + associated_data
    ciphertext, nonce = aead_encrypt(message_key, plaintext, full_ad)
    
    # Securely delete message key (forward secrecy)
    del message_key
    
    return header, ciphertext, nonce


def ratchet_decrypt(
    state: RatchetState,
    header: MessageHeader,
    ciphertext: bytes,
    nonce: bytes,
    associated_data: bytes = b""
) -> bytes:
    """
    Decrypt a message using the Double Ratchet.
    
    Handles DH ratchet steps and skipped messages automatically.
    
    Args:
        state: Current ratchet state (modified in place)
        header: Message header
        ciphertext: Encrypted message
        nonce: AEAD nonce
        associated_data: Additional authenticated data
        
    Returns:
        Decrypted plaintext
        
    Raises:
        DecryptionError: If decryption fails
        TooManySkippedKeysError: If too many messages skipped
        
    Reference:
        Double Ratchet spec section 2.4 - Decryption
    """
    # Try to decrypt with a skipped message key first
    plaintext = try_skipped_message_keys(state, header, ciphertext, nonce, associated_data)
    if plaintext is not None:
        return plaintext
    
    # Check if we need to perform a DH ratchet step
    if header.dh_public != state.dh_remote:
        # New DH public key from sender - perform DH ratchet
        skip_message_keys(state, header.prev_chain_length)
        dh_ratchet_step(state, header)
    
    # Skip message keys if needed (out-of-order delivery)
    skip_message_keys(state, header.message_number)
    
    # Derive message key from receive chain key
    state.chain_key_recv, message_key = kdf_ck(state.chain_key_recv)
    state.recv_msg_num += 1
    
    # Decrypt: AEAD_DECRYPT(message_key, ciphertext, header || AD)
    header_bytes = header.encode()
    full_ad = header_bytes + associated_data
    
    try:
        plaintext = aead_decrypt(message_key, ciphertext, nonce, full_ad)
    except Exception as e:
        raise DecryptionError(f"Failed to decrypt message: {e}")
    finally:
        # Securely delete message key
        del message_key
    
    return plaintext


def dh_ratchet_step(state: RatchetState, header: MessageHeader):
    """
    Perform a DH ratchet step.
    
    This is triggered when receiving a message with a new DH public key.
    It derives new root and chain keys through two DH operations.
    
    Args:
        state: Ratchet state (modified in place)
        header: Message header with new DH public key
        
    Reference:
        Double Ratchet spec section 2.2 - DH ratchet
    """
    # Save previous send chain length
    state.prev_chain_length = state.send_msg_num
    
    # Update remote DH public key
    state.dh_remote = header.dh_public
    
    # DH ratchet step 1: Receive
    # Compute DH with remote's new key using our current key
    dh_recv = x25519_dh(state.dh_private, state.dh_remote)
    state.root_key, state.chain_key_recv = kdf_rk(state.root_key, dh_recv)
    state.recv_msg_num = 0
    
    # Generate new DH keypair
    state.dh_private, state.dh_public = generate_x25519_keypair()
    
    # DH ratchet step 2: Send
    # Compute DH with remote's key using our new key
    dh_send = x25519_dh(state.dh_private, state.dh_remote)
    state.root_key, state.chain_key_send = kdf_rk(state.root_key, dh_send)
    state.send_msg_num = 0


def skip_message_keys(state: RatchetState, until: int):
    """
    Store message keys for skipped messages.
    
    This handles out-of-order message delivery by deriving and storing
    message keys for messages we haven't received yet.
    
    Args:
        state: Ratchet state (modified in place)
        until: Message number to skip to (exclusive)
        
    Raises:
        TooManySkippedKeysError: If skipping would exceed MAX_SKIP
        
    Reference:
        Double Ratchet spec section 2.4 - Out-of-order messages
    """
    if state.chain_key_recv is None:
        # Can't skip if we don't have a receive chain yet
        return
    
    # Check if we would skip too many keys
    if state.recv_msg_num + MAX_SKIP < until:
        raise TooManySkippedKeysError(
            f"Cannot skip {until - state.recv_msg_num} messages "
            f"(max {MAX_SKIP}). Possible desync or attack."
        )
    
    # Derive and store message keys for skipped messages
    while state.recv_msg_num < until:
        state.chain_key_recv, message_key = kdf_ck(state.chain_key_recv)
        
        # Store skipped message key with timestamp
        key = (state.dh_remote, state.recv_msg_num)
        state.skipped_keys[key] = (message_key, time.time())
        
        state.recv_msg_num += 1


def try_skipped_message_keys(
    state: RatchetState,
    header: MessageHeader,
    ciphertext: bytes,
    nonce: bytes,
    associated_data: bytes
) -> Optional[bytes]:
    """
    Attempt to decrypt message with a skipped message key.
    
    Args:
        state: Ratchet state
        header: Message header
        ciphertext: Encrypted message
        nonce: AEAD nonce
        associated_data: Additional authenticated data
        
    Returns:
        Decrypted plaintext if successful, None otherwise
    """
    key = (header.dh_public, header.message_number)
    
    if key not in state.skipped_keys:
        return None
    
    # Retrieve and delete the skipped message key
    message_key, timestamp = state.skipped_keys[key]
    del state.skipped_keys[key]
    
    # Try to decrypt
    header_bytes = header.encode()
    full_ad = header_bytes + associated_data
    
    try:
        plaintext = aead_decrypt(message_key, ciphertext, nonce, full_ad)
        return plaintext
    except Exception:
        # Decryption failed - key might have been for wrong message
        # Re-store the key for future attempts
        state.skipped_keys[key] = (message_key, timestamp)
        return None
    finally:
        del message_key
