"""
Cryptographic primitives using PyNaCl (libsodium) and cryptography library.

This module wraps vetted crypto implementations and provides a clean API.
NO custom cryptographic algorithms are implemented.

References:
- libsodium: https://doc.libsodium.org/
- PyNaCl: https://pynacl.readthedocs.io/
"""

import os
import hmac
from typing import Tuple

import nacl.bindings
import nacl.signing
import nacl.public
import nacl.secret
import nacl.utils
import nacl.pwhash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Type aliases for clarity
PrivateKey = bytes
PublicKey = bytes
Signature = bytes
Nonce = bytes
Ciphertext = bytes
SharedSecret = bytes


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of random bytes to generate
        
    Returns:
        Random bytes of specified length
    """
    return nacl.utils.random(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)


# ============================================================================
# X25519 (Elliptic Curve Diffie-Hellman)
# Used for: DH ratchet in Double Ratchet, key agreement in X3DH
# ============================================================================

def generate_x25519_keypair() -> Tuple[PrivateKey, PublicKey]:
    """
    Generate an X25519 key pair for Diffie-Hellman key exchange.
    
    Returns:
        Tuple of (private_key, public_key) as raw bytes
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    
    return bytes(private_key), bytes(public_key)


def x25519_dh(private_key: PrivateKey, public_key: PublicKey) -> SharedSecret:
    """
    Perform X25519 Diffie-Hellman key exchange.
    
    Args:
        private_key: Local private key (32 bytes)
        public_key: Remote public key (32 bytes)
        
    Returns:
        Shared secret (32 bytes)
        
    Raises:
        ValueError: If key sizes are invalid
    """
    if len(private_key) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key)}")
    if len(public_key) != 32:
        raise ValueError(f"Public key must be 32 bytes, got {len(public_key)}")
    
    priv = nacl.public.PrivateKey(private_key)
    pub = nacl.public.PublicKey(public_key)
    
    # Compute shared secret
    shared = nacl.bindings.crypto_scalarmult(bytes(priv), bytes(pub))
    
    return shared


# ============================================================================
# Ed25519 (Digital Signatures)
# Used for: Signing prekeys, identity verification
# ============================================================================

def generate_ed25519_keypair() -> Tuple[PrivateKey, PublicKey]:
    """
    Generate an Ed25519 signing key pair.
    
    Returns:
        Tuple of (private_key, public_key) as raw bytes
    """
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    
    return bytes(signing_key), bytes(verify_key)


def ed25519_sign(private_key: PrivateKey, message: bytes) -> Signature:
    """
    Sign a message using Ed25519.
    
    Args:
        private_key: Ed25519 private key (32 bytes seed)
        message: Message to sign
        
    Returns:
        Signature (64 bytes)
    """
    signing_key = nacl.signing.SigningKey(private_key)
    signed = signing_key.sign(message)
    
    # Return just the signature, not the concatenated message
    return signed.signature


def ed25519_verify(public_key: PublicKey, message: bytes, signature: Signature) -> bool:
    """
    Verify an Ed25519 signature.
    
    Args:
        public_key: Ed25519 public key (32 bytes)
        message: Original message
        signature: Signature to verify (64 bytes)
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        verify_key = nacl.signing.VerifyKey(public_key)
        # Will raise if invalid
        verify_key.verify(message, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


# ============================================================================
# HKDF (HMAC-based Key Derivation Function)
# Used for: Deriving multiple keys from shared secrets
# Reference: RFC 5869
# ============================================================================

def hkdf_derive(
    input_key_material: bytes,
    length: int,
    salt: bytes = b"",
    info: bytes = b""
) -> bytes:
    """
    Derive key material using HKDF-SHA256.
    
    HKDF is used throughout the Signal Protocol to derive multiple
    independent keys from a single shared secret.
    
    Args:
        input_key_material: Source key material
        length: Number of bytes to derive
        salt: Optional salt value (improves security)
        info: Optional context/application info
        
    Returns:
        Derived key material of requested length
        
    Reference:
        Signal spec uses HKDF-SHA256 throughout
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(input_key_material)


# ============================================================================
# AEAD (Authenticated Encryption with Associated Data)
# Using ChaCha20-Poly1305
# Used for: Encrypting message content in Double Ratchet
# ============================================================================

def aead_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b""
) -> Tuple[Ciphertext, Nonce]:
    """
    Encrypt using ChaCha20-Poly1305 AEAD.
    
    Provides both confidentiality and authenticity. The associated_data
    is authenticated but not encrypted (useful for headers).
    
    Args:
        key: Encryption key (32 bytes)
        plaintext: Data to encrypt
        associated_data: Additional data to authenticate but not encrypt
        
    Returns:
        Tuple of (ciphertext, nonce)
        
    Note:
        Ciphertext includes the 16-byte Poly1305 authentication tag
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    # Generate random nonce (24 bytes for XChaCha20)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    
    # ChaCha20-Poly1305 encryption
    box = nacl.secret.SecretBox(key)
    ciphertext = box.encrypt(plaintext, nonce)
    
    # Remove the nonce from the ciphertext (we return it separately)
    ciphertext_only = ciphertext[nacl.secret.SecretBox.NONCE_SIZE:]
    
    return ciphertext_only, nonce


def aead_decrypt(
    key: bytes,
    ciphertext: Ciphertext,
    nonce: Nonce,
    associated_data: bytes = b""
) -> bytes:
    """
    Decrypt using ChaCha20-Poly1305 AEAD.
    
    Args:
        key: Decryption key (32 bytes)
        ciphertext: Encrypted data (includes auth tag)
        nonce: Nonce used during encryption
        associated_data: Additional authenticated data
        
    Returns:
        Decrypted plaintext
        
    Raises:
        nacl.exceptions.CryptoError: If authentication fails
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    box = nacl.secret.SecretBox(key)
    
    # Reconstruct the format expected by SecretBox
    encrypted = nonce + ciphertext
    
    try:
        plaintext = box.decrypt(encrypted)
        return plaintext
    except nacl.exceptions.CryptoError:
        raise ValueError("Authentication failed: ciphertext has been tampered with")


# ============================================================================
# Password-based Key Derivation (Argon2)
# Used for: Deriving encryption keys from user passphrases
# ============================================================================

def derive_key_from_password(
    password: str,
    salt: bytes,
    key_length: int = 32
) -> bytes:
    """
    Derive a key from a password using Argon2id.
    
    Argon2id provides resistance against both side-channel and GPU attacks.
    Used to encrypt local session storage.
    
    Args:
        password: User password
        salt: Salt value (should be unique per user, at least 16 bytes)
        key_length: Length of derived key in bytes
        
    Returns:
        Derived key
        
    Note:
        Uses moderate parameters suitable for interactive login.
        For higher security, increase opslimit/memlimit.
    """
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")
    
    # Use Argon2id with moderate parameters
    derived = nacl.pwhash.argon2id.kdf(
        size=key_length,
        password=password.encode('utf-8'),
        salt=salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_MODERATE
    )
    
    return derived


# ============================================================================
# Utility Functions
# ============================================================================

def convert_ed25519_to_x25519_public(ed25519_public: PublicKey) -> PublicKey:
    """
    Convert an Ed25519 public key to X25519 (Curve25519) for DH.
    
    This is used in the Signal Protocol where the identity key can be
    used for both signing (Ed25519) and key agreement (X25519).
    
    Args:
        ed25519_public: Ed25519 public key (32 bytes)
        
    Returns:
        X25519 public key (32 bytes)
    """
    verify_key = nacl.signing.VerifyKey(ed25519_public)
    curve_key = verify_key.to_curve25519_public_key()
    return bytes(curve_key)


def convert_ed25519_to_x25519_private(ed25519_private: PrivateKey) -> PrivateKey:
    """
    Convert an Ed25519 private key to X25519 (Curve25519) for DH.
    
    Args:
        ed25519_private: Ed25519 private key seed (32 bytes)
        
    Returns:
        X25519 private key (32 bytes)
    """
    signing_key = nacl.signing.SigningKey(ed25519_private)
    curve_key = signing_key.to_curve25519_private_key()
    return bytes(curve_key)
