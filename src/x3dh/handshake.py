"""
X3DH Key Agreement Protocol Implementation

This module implements the Extended Triple Diffie-Hellman (X3DH) protocol
for asynchronous key agreement between two parties.

Reference: Signal X3DH Specification
https://signal.org/docs/specifications/x3dh/
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from src.crypto.primitives import (
    generate_x25519_keypair,
    x25519_dh,
    hkdf_derive,
    convert_ed25519_to_x25519_public,
    convert_ed25519_to_x25519_private,
)
from src.x3dh.prekeys import PrekeyBundle, IdentityKeyPair


# X3DH Protocol Constants
X3DH_INFO = b"SecureChat-X3DH-v1"
X3DH_SALT = b"SecureChat-Salt"


@dataclass
class X3DHResult:
    """
    Result of X3DH key agreement.
    
    Contains the shared secret and associated data needed to
    initialize the Double Ratchet protocol.
    """
    shared_secret: bytes  # 32 bytes - SK from X3DH
    associated_data: bytes  # AD = IK_a || IK_b
    ephemeral_public: bytes  # Alice's ephemeral public key (sent to Bob)
    one_time_prekey_id: Optional[int]  # ID of used one-time prekey (if any)


class X3DHInitiator:
    """
    Alice's side of X3DH - initiating a conversation.
    
    Performs the X3DH handshake from the initiator's perspective:
    1. Fetches Bob's prekey bundle
    2. Verifies signed prekey signature
    3. Performs 3-4 DH operations
    4. Derives shared secret with HKDF
    """
    
    def __init__(self, identity_keypair: IdentityKeyPair):
        """
        Initialize X3DH initiator.
        
        Args:
            identity_keypair: Alice's identity key pair
        """
        self.identity_keypair = identity_keypair
    
    def perform_handshake(self, recipient_bundle: PrekeyBundle) -> X3DHResult:
        """
        Perform X3DH key agreement with recipient's prekey bundle.
        
        This is called by Alice to establish a shared secret with Bob.
        
        Args:
            recipient_bundle: Bob's prekey bundle from server
            
        Returns:
            X3DHResult containing shared secret and metadata
            
        Raises:
            ValueError: If signature verification fails
            
        Reference:
            X3DH spec section 3.3 - Sending the initial message
        """
        # Step 1: Verify the signed prekey signature
        if not recipient_bundle.verify_signature():
            raise ValueError(
                "Signed prekey signature verification failed. "
                "Possible MITM attack or corrupted bundle."
            )
        
        # Step 2: Generate ephemeral key pair
        ek_private, ek_public = generate_x25519_keypair()
        
        # Step 3: Convert identity keys to X25519 for DH
        # Alice's identity key (Ed25519 -> X25519)
        ik_a_x25519_private = convert_ed25519_to_x25519_private(
            self.identity_keypair.private_key
        )
        ik_a_x25519_public = convert_ed25519_to_x25519_public(
            self.identity_keypair.public_key
        )
        
        # Bob's identity key (Ed25519 -> X25519)
        ik_b_x25519_public = convert_ed25519_to_x25519_public(
            recipient_bundle.identity_key
        )
        
        # Step 4: Perform DH operations
        # DH1 = DH(IK_a, SPK_b)
        dh1 = x25519_dh(ik_a_x25519_private, recipient_bundle.signed_prekey)
        
        # DH2 = DH(EK_a, IK_b)
        dh2 = x25519_dh(ek_private, ik_b_x25519_public)
        
        # DH3 = DH(EK_a, SPK_b)
        dh3 = x25519_dh(ek_private, recipient_bundle.signed_prekey)
        
        # DH4 = DH(EK_a, OPK_b) [if one-time prekey available]
        if recipient_bundle.one_time_prekey:
            dh4 = x25519_dh(ek_private, recipient_bundle.one_time_prekey)
            dh_output = dh1 + dh2 + dh3 + dh4
        else:
            # No one-time prekey available (server ran out)
            dh_output = dh1 + dh2 + dh3
        
        # Step 5: Derive shared secret using HKDF
        # SK = HKDF(DH outputs)
        shared_secret = hkdf_derive(
            input_key_material=dh_output,
            length=32,
            salt=X3DH_SALT,
            info=X3DH_INFO
        )
        
        # Step 6: Create associated data
        # AD = Encode(IK_a) || Encode(IK_b)
        associated_data = self.identity_keypair.public_key + recipient_bundle.identity_key
        
        return X3DHResult(
            shared_secret=shared_secret,
            associated_data=associated_data,
            ephemeral_public=ek_public,
            one_time_prekey_id=recipient_bundle.one_time_prekey_id
        )


class X3DHReceiver:
    """
    Bob's side of X3DH - receiving a conversation initiation.
    
    Completes the X3DH handshake from the receiver's perspective:
    1. Receives Alice's identity key and ephemeral key
    2. Performs the same DH operations
    3. Derives the same shared secret
    """
    
    def __init__(
        self,
        identity_keypair: IdentityKeyPair,
        signed_prekey_private: bytes,
    ):
        """
        Initialize X3DH receiver.
        
        Args:
            identity_keypair: Bob's identity key pair
            signed_prekey_private: Bob's signed prekey private key (X25519)
        """
        self.identity_keypair = identity_keypair
        self.signed_prekey_private = signed_prekey_private
    
    def complete_handshake(
        self,
        sender_identity_key: bytes,  # Alice's IK public (Ed25519)
        sender_ephemeral_key: bytes,  # Alice's EK public (X25519)
        one_time_prekey_private: Optional[bytes] = None  # Bob's OPK private (X25519)
    ) -> X3DHResult:
        """
        Complete X3DH key agreement from initial message.
        
        This is called by Bob upon receiving Alice's initial message.
        
        Args:
            sender_identity_key: Alice's Ed25519 identity public key
            sender_ephemeral_key: Alice's X25519 ephemeral public key
            one_time_prekey_private: Bob's one-time prekey private key (if used)
            
        Returns:
            X3DHResult containing shared secret and metadata
            
        Reference:
            X3DH spec section 3.4 - Receiving the initial message
        """
        # Step 1: Convert identity keys to X25519 for DH
        # Bob's identity key (Ed25519 -> X25519)
        ik_b_x25519_private = convert_ed25519_to_x25519_private(
            self.identity_keypair.private_key
        )
        ik_b_x25519_public = convert_ed25519_to_x25519_public(
            self.identity_keypair.public_key
        )
        
        # Alice's identity key (Ed25519 -> X25519)
        ik_a_x25519_public = convert_ed25519_to_x25519_public(sender_identity_key)
        
        # Step 2: Perform DH operations (same as Alice, but reversed)
        # DH1 = DH(SPK_b, IK_a)
        dh1 = x25519_dh(self.signed_prekey_private, ik_a_x25519_public)
        
        # DH2 = DH(IK_b, EK_a)
        dh2 = x25519_dh(ik_b_x25519_private, sender_ephemeral_key)
        
        # DH3 = DH(SPK_b, EK_a)
        dh3 = x25519_dh(self.signed_prekey_private, sender_ephemeral_key)
        
        # DH4 = DH(OPK_b, EK_a) [if one-time prekey was used]
        if one_time_prekey_private:
            dh4 = x25519_dh(one_time_prekey_private, sender_ephemeral_key)
            dh_output = dh1 + dh2 + dh3 + dh4
        else:
            dh_output = dh1 + dh2 + dh3
        
        # Step 3: Derive shared secret (should match Alice's)
        shared_secret = hkdf_derive(
            input_key_material=dh_output,
            length=32,
            salt=X3DH_SALT,
            info=X3DH_INFO
        )
        
        # Step 4: Create associated data (should match Alice's)
        # AD = Encode(IK_a) || Encode(IK_b)
        associated_data = sender_identity_key + self.identity_keypair.public_key
        
        return X3DHResult(
            shared_secret=shared_secret,
            associated_data=associated_data,
            ephemeral_public=sender_ephemeral_key,  # Store for reference
            one_time_prekey_id=None  # Bob doesn't need this
        )


def verify_shared_secrets_match(alice_result: X3DHResult, bob_result: X3DHResult) -> bool:
    """
    Utility function to verify both parties derived the same shared secret.
    
    This is for testing purposes only. In production, parties can't directly
    compare secrets (they're on different machines).
    
    Args:
        alice_result: X3DH result from Alice's side
        bob_result: X3DH result from Bob's side
        
    Returns:
        True if shared secrets and AD match, False otherwise
    """
    return (
        alice_result.shared_secret == bob_result.shared_secret and
        alice_result.associated_data == bob_result.associated_data
    )
