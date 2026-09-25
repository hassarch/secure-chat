"""
X3DH Prekey Bundle Generation and Management

This module handles the creation and management of prekey bundles:
- Identity keys (Ed25519)
- Signed prekeys (X25519, signed with identity key)
- One-time prekeys (X25519, ephemeral)

Reference: Signal X3DH Specification
https://signal.org/docs/specifications/x3dh/
"""

from dataclasses import dataclass
from typing import List, Optional
import json

from src.crypto.primitives import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    ed25519_sign,
    ed25519_verify,
    convert_ed25519_to_x25519_public,
)


@dataclass
class IdentityKeyPair:
    """Ed25519 identity key pair (long-term)"""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 32 bytes
    
    def to_dict(self) -> dict:
        return {
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "IdentityKeyPair":
        return cls(
            private_key=bytes.fromhex(data["private_key"]),
            public_key=bytes.fromhex(data["public_key"]),
        )


@dataclass
class SignedPrekeyPair:
    """X25519 signed prekey pair (medium-term, rotated periodically)"""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 32 bytes
    signature: bytes    # 64 bytes (Ed25519 signature)
    key_id: int        # Identifier for key rotation
    
    def to_dict(self) -> dict:
        return {
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
            "signature": self.signature.hex(),
            "key_id": self.key_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SignedPrekeyPair":
        return cls(
            private_key=bytes.fromhex(data["private_key"]),
            public_key=bytes.fromhex(data["public_key"]),
            signature=bytes.fromhex(data["signature"]),
            key_id=data["key_id"],
        )


@dataclass
class OneTimePrekeyPair:
    """X25519 one-time prekey pair (ephemeral, single use)"""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 32 bytes
    key_id: int        # Unique identifier
    
    def to_dict(self) -> dict:
        return {
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
            "key_id": self.key_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "OneTimePrekeyPair":
        return cls(
            private_key=bytes.fromhex(data["private_key"]),
            public_key=bytes.fromhex(data["public_key"]),
            key_id=data["key_id"],
        )


@dataclass
class PrekeyBundle:
    """
    Complete prekey bundle for X3DH protocol.
    
    Published to server for other users to fetch when initiating conversation.
    """
    identity_key: bytes           # Ed25519 public key (32 bytes)
    signed_prekey: bytes          # X25519 public key (32 bytes)
    signed_prekey_signature: bytes  # Ed25519 signature (64 bytes)
    signed_prekey_id: int         # Signed prekey identifier
    one_time_prekey: Optional[bytes]  # X25519 public key (32 bytes) or None
    one_time_prekey_id: Optional[int]  # One-time prekey identifier or None
    
    def to_dict(self) -> dict:
        return {
            "identity_key": self.identity_key.hex(),
            "signed_prekey": self.signed_prekey.hex(),
            "signed_prekey_signature": self.signed_prekey_signature.hex(),
            "signed_prekey_id": self.signed_prekey_id,
            "one_time_prekey": self.one_time_prekey.hex() if self.one_time_prekey else None,
            "one_time_prekey_id": self.one_time_prekey_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "PrekeyBundle":
        return cls(
            identity_key=bytes.fromhex(data["identity_key"]),
            signed_prekey=bytes.fromhex(data["signed_prekey"]),
            signed_prekey_signature=bytes.fromhex(data["signed_prekey_signature"]),
            signed_prekey_id=data["signed_prekey_id"],
            one_time_prekey=bytes.fromhex(data["one_time_prekey"]) if data["one_time_prekey"] else None,
            one_time_prekey_id=data["one_time_prekey_id"],
        )
    
    def verify_signature(self) -> bool:
        """
        Verify that the signed prekey signature is valid.
        
        This is critical for preventing MITM attacks. The initiator
        MUST verify this before proceeding with X3DH.
        
        Returns:
            True if signature is valid, False otherwise
        """
        return ed25519_verify(
            self.identity_key,
            self.signed_prekey,
            self.signed_prekey_signature
        )


def generate_identity_keypair() -> IdentityKeyPair:
    """
    Generate a new Ed25519 identity key pair.
    
    This is the user's long-term cryptographic identity.
    Should be stored securely and backed up.
    
    Returns:
        IdentityKeyPair with private and public keys
    """
    private_key, public_key = generate_ed25519_keypair()
    return IdentityKeyPair(private_key=private_key, public_key=public_key)


def generate_signed_prekey(
    identity_keypair: IdentityKeyPair,
    key_id: int = 1
) -> SignedPrekeyPair:
    """
    Generate a new signed prekey signed with the identity key.
    
    The signature proves that the signed prekey belongs to the owner
    of the identity key, preventing key substitution attacks.
    
    Args:
        identity_keypair: The identity key to sign with
        key_id: Identifier for this signed prekey (for rotation)
        
    Returns:
        SignedPrekeyPair including signature
        
    Reference:
        X3DH spec section 2.1 - Signed Prekey
    """
    # Generate X25519 key pair
    private_key, public_key = generate_x25519_keypair()
    
    # Sign the public key with identity private key
    signature = ed25519_sign(identity_keypair.private_key, public_key)
    
    return SignedPrekeyPair(
        private_key=private_key,
        public_key=public_key,
        signature=signature,
        key_id=key_id
    )


def generate_one_time_prekeys(count: int, start_id: int = 1) -> List[OneTimePrekeyPair]:
    """
    Generate multiple one-time prekeys.
    
    One-time prekeys provide forward secrecy from the first message.
    Each is used once and then deleted.
    
    Args:
        count: Number of one-time prekeys to generate
        start_id: Starting ID for key identification
        
    Returns:
        List of OneTimePrekeyPair objects
        
    Reference:
        X3DH spec section 2.1 - One-time Prekeys
    """
    prekeys = []
    for i in range(count):
        private_key, public_key = generate_x25519_keypair()
        prekeys.append(OneTimePrekeyPair(
            private_key=private_key,
            public_key=public_key,
            key_id=start_id + i
        ))
    return prekeys


def create_prekey_bundle(
    identity_key_public: bytes,
    signed_prekey: SignedPrekeyPair,
    one_time_prekey: Optional[OneTimePrekeyPair] = None
) -> PrekeyBundle:
    """
    Create a prekey bundle for publishing to the server.
    
    This bundle contains everything another user needs to initiate
    an X3DH handshake.
    
    Args:
        identity_key_public: Public identity key (Ed25519)
        signed_prekey: Signed prekey with signature
        one_time_prekey: Optional one-time prekey
        
    Returns:
        PrekeyBundle ready to publish
    """
    return PrekeyBundle(
        identity_key=identity_key_public,
        signed_prekey=signed_prekey.public_key,
        signed_prekey_signature=signed_prekey.signature,
        signed_prekey_id=signed_prekey.key_id,
        one_time_prekey=one_time_prekey.public_key if one_time_prekey else None,
        one_time_prekey_id=one_time_prekey.key_id if one_time_prekey else None
    )


class PrekeyStore:
    """
    Local storage for user's own prekeys.
    
    Manages rotation and replenishment of prekeys.
    """
    
    def __init__(self, identity_keypair: IdentityKeyPair):
        self.identity_keypair = identity_keypair
        self.signed_prekey: Optional[SignedPrekeyPair] = None
        self.one_time_prekeys: List[OneTimePrekeyPair] = []
        self.next_signed_prekey_id = 1
        self.next_one_time_prekey_id = 1
    
    def generate_signed_prekey(self) -> SignedPrekeyPair:
        """Generate and store a new signed prekey"""
        self.signed_prekey = generate_signed_prekey(
            self.identity_keypair,
            self.next_signed_prekey_id
        )
        self.next_signed_prekey_id += 1
        return self.signed_prekey
    
    def generate_one_time_prekeys(self, count: int) -> List[OneTimePrekeyPair]:
        """Generate and store new one-time prekeys"""
        new_prekeys = generate_one_time_prekeys(count, self.next_one_time_prekey_id)
        self.one_time_prekeys.extend(new_prekeys)
        self.next_one_time_prekey_id += count
        return new_prekeys
    
    def get_one_time_prekey(self, key_id: int) -> Optional[OneTimePrekeyPair]:
        """Retrieve a one-time prekey by ID"""
        for prekey in self.one_time_prekeys:
            if prekey.key_id == key_id:
                return prekey
        return None
    
    def remove_one_time_prekey(self, key_id: int) -> bool:
        """Remove a used one-time prekey"""
        for i, prekey in enumerate(self.one_time_prekeys):
            if prekey.key_id == key_id:
                del self.one_time_prekeys[i]
                return True
        return False
    
    def needs_replenishment(self, threshold: int = 20) -> bool:
        """Check if one-time prekeys need replenishment"""
        return len(self.one_time_prekeys) < threshold
    
    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            "identity_keypair": self.identity_keypair.to_dict(),
            "signed_prekey": self.signed_prekey.to_dict() if self.signed_prekey else None,
            "one_time_prekeys": [pk.to_dict() for pk in self.one_time_prekeys],
            "next_signed_prekey_id": self.next_signed_prekey_id,
            "next_one_time_prekey_id": self.next_one_time_prekey_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "PrekeyStore":
        """Deserialize from dictionary"""
        identity_keypair = IdentityKeyPair.from_dict(data["identity_keypair"])
        store = cls(identity_keypair)
        
        if data["signed_prekey"]:
            store.signed_prekey = SignedPrekeyPair.from_dict(data["signed_prekey"])
        
        store.one_time_prekeys = [
            OneTimePrekeyPair.from_dict(pk) for pk in data["one_time_prekeys"]
        ]
        store.next_signed_prekey_id = data["next_signed_prekey_id"]
        store.next_one_time_prekey_id = data["next_one_time_prekey_id"]
        
        return store
