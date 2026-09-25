"""
Session Manager

Coordinates X3DH key agreement and Double Ratchet encryption for secure messaging.
Manages session lifecycle, message encryption/decryption, and safety number generation.
"""

import hashlib
import logging
from typing import Optional, Tuple
from dataclasses import dataclass

from ..crypto.primitives import (
    generate_x25519_keypair,
    generate_ed25519_keypair,
    ed25519_sign,
    convert_ed25519_to_x25519_public,
)
from ..x3dh.handshake import X3DHInitiator, X3DHReceiver
from ..x3dh.prekeys import PrekeyBundle, SignedPrekeyPair, OneTimePrekeyPair
from ..ratchet.ratchet import DoubleRatchet
from ..ratchet.state import RatchetState
from .storage import SecureStorage
from .transport import Transport


logger = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    """Information about an active session"""
    contact_id: str
    send_count: int
    recv_count: int
    safety_number: str
    verified: bool


class SessionError(Exception):
    """Session-related errors"""
    pass


class SessionManager:
    """
    Manages encrypted sessions with contacts.
    
    Responsibilities:
    - Initialize new sessions via X3DH
    - Encrypt/decrypt messages with Double Ratchet
    - Maintain session state in secure storage
    - Generate and verify safety numbers
    """
    
    def __init__(self, storage: SecureStorage, transport: Transport):
        """
        Initialize session manager.
        
        Args:
            storage: Secure storage for keys and sessions
            transport: Transport layer for server communication
        """
        self.storage = storage
        self.transport = transport
        self._ratchets = {}  # Cache of active ratchets: contact_id -> DoubleRatchet
        
    async def initialize_session(self, recipient_id: str) -> bool:
        """
        Initialize new session with recipient using X3DH.
        
        This is called by the initiator when starting a conversation.
        
        Args:
            recipient_id: Contact to initiate session with
            
        Returns:
            True if session initialized successfully
            
        Raises:
            SessionError: If initialization fails
        """
        try:
            # Get our identity
            identity_data = self.storage.get_identity()
            if not identity_data:
                raise SessionError("No local identity found - register first")
            
            user_id, identity_private, identity_public, signed_prekey, _ = identity_data
            
            # Fetch recipient's prekey bundle
            logger.info(f"Fetching prekey bundle for {recipient_id}")
            bundle_data = await self.transport.fetch_prekey_bundle(recipient_id)
            
            if not bundle_data:
                raise SessionError(f"Prekey bundle not found for {recipient_id}")
            
            # Parse prekey bundle
            recipient_bundle = self._parse_prekey_bundle(bundle_data)
            
            # Generate ephemeral key for X3DH
            ek_private, ek_public = generate_x25519_keypair()
            
            # Perform X3DH as initiator
            logger.info(f"Performing X3DH handshake with {recipient_id}")
            initiator = X3DHInitiator()
            
            # Convert identity keys to X25519
            ik_private_x25519 = convert_ed25519_to_x25519_public(identity_private)
            
            shared_secret = initiator.perform_handshake(
                identity_private=ik_private_x25519,
                ephemeral_private=ek_private,
                recipient_bundle=recipient_bundle
            )
            
            # Initialize Double Ratchet as sender
            logger.info(f"Initializing Double Ratchet for {recipient_id}")
            ratchet = DoubleRatchet()
            
            # Get recipient's signed prekey for initial DH
            recipient_dh_public = recipient_bundle.signed_prekey.public_key
            
            state = ratchet.init_sender(
                shared_secret=shared_secret,
                remote_dh_public=recipient_dh_public
            )
            
            # Save session
            self.storage.save_session(recipient_id, state)
            self._ratchets[recipient_id] = ratchet
            
            # Add contact if not exists
            contact = self.storage.get_contact(recipient_id)
            if not contact:
                self.storage.add_contact(
                    recipient_id,
                    recipient_bundle.identity_key,
                    verified=False
                )
            
            logger.info(f"Session initialized with {recipient_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize session with {recipient_id}: {e}")
            raise SessionError(f"Session initialization failed: {e}")
            
    async def handle_incoming_handshake(
        self,
        sender_id: str,
        ephemeral_key: bytes,
        initial_message: Optional[bytes] = None
    ) -> Optional[bytes]:
        """
        Handle incoming X3DH handshake (receiver side).
        
        Args:
            sender_id: Sender's user ID
            ephemeral_key: Sender's ephemeral public key
            initial_message: Optional initial encrypted message
            
        Returns:
            Decrypted initial message if provided
            
        Raises:
            SessionError: If handshake fails
        """
        try:
            # Get our identity
            identity_data = self.storage.get_identity()
            if not identity_data:
                raise SessionError("No local identity found")
            
            user_id, identity_private, identity_public, signed_prekey, _ = identity_data
            
            # Fetch sender's identity key
            bundle_data = await self.transport.fetch_prekey_bundle(sender_id)
            if not bundle_data:
                raise SessionError(f"Could not fetch identity for {sender_id}")
            
            sender_bundle = self._parse_prekey_bundle(bundle_data)
            sender_identity = sender_bundle.identity_key
            
            # Perform X3DH as receiver
            logger.info(f"Performing X3DH handshake (receiver) with {sender_id}")
            receiver = X3DHReceiver()
            
            # Convert keys to X25519
            ik_private_x25519 = convert_ed25519_to_x25519_public(identity_private)
            sender_ik_x25519 = convert_ed25519_to_x25519_public(sender_identity)
            
            shared_secret = receiver.perform_handshake(
                identity_private=ik_private_x25519,
                signed_prekey_private=signed_prekey.private_key,
                sender_identity_key=sender_ik_x25519,
                sender_ephemeral_key=ephemeral_key,
                one_time_prekey_private=None  # TODO: Support one-time prekeys
            )
            
            # Initialize Double Ratchet as receiver
            logger.info(f"Initializing Double Ratchet (receiver) for {sender_id}")
            ratchet = DoubleRatchet()
            
            state = ratchet.init_receiver(
                shared_secret=shared_secret,
                our_dh_private=signed_prekey.private_key
            )
            
            # Save session
            self.storage.save_session(sender_id, state)
            self._ratchets[sender_id] = ratchet
            
            # Add contact if not exists
            contact = self.storage.get_contact(sender_id)
            if not contact:
                self.storage.add_contact(
                    sender_id,
                    sender_identity,
                    verified=False
                )
            
            logger.info(f"Session established (receiver) with {sender_id}")
            
            # Decrypt initial message if provided
            if initial_message:
                return await self.decrypt_message(sender_id, initial_message)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to handle handshake from {sender_id}: {e}")
            raise SessionError(f"Handshake failed: {e}")
            
    async def encrypt_message(self, recipient_id: str, plaintext: bytes) -> bytes:
        """
        Encrypt message for recipient.
        
        Args:
            recipient_id: Recipient user ID
            plaintext: Message to encrypt
            
        Returns:
            Encrypted message bytes
            
        Raises:
            SessionError: If encryption fails
        """
        try:
            # Load or get cached ratchet
            ratchet = self._get_ratchet(recipient_id)
            if not ratchet:
                raise SessionError(f"No session with {recipient_id} - initialize first")
            
            # Load session state
            state = self.storage.load_session(recipient_id)
            if not state:
                raise SessionError(f"Session state not found for {recipient_id}")
            
            # Encrypt message
            ciphertext, new_state = ratchet.encrypt(plaintext, state)
            
            # Save updated state
            self.storage.save_session(recipient_id, new_state)
            
            logger.debug(f"Encrypted message for {recipient_id}")
            return ciphertext
            
        except Exception as e:
            logger.error(f"Failed to encrypt message for {recipient_id}: {e}")
            raise SessionError(f"Encryption failed: {e}")
            
    async def decrypt_message(self, sender_id: str, ciphertext: bytes) -> bytes:
        """
        Decrypt message from sender.
        
        Args:
            sender_id: Sender user ID
            ciphertext: Encrypted message
            
        Returns:
            Decrypted plaintext
            
        Raises:
            SessionError: If decryption fails
        """
        try:
            # Load or get cached ratchet
            ratchet = self._get_ratchet(sender_id)
            if not ratchet:
                raise SessionError(f"No session with {sender_id}")
            
            # Load session state
            state = self.storage.load_session(sender_id)
            if not state:
                raise SessionError(f"Session state not found for {sender_id}")
            
            # Decrypt message
            plaintext, new_state = ratchet.decrypt(ciphertext, state)
            
            # Save updated state
            self.storage.save_session(sender_id, new_state)
            
            logger.debug(f"Decrypted message from {sender_id}")
            return plaintext
            
        except Exception as e:
            logger.error(f"Failed to decrypt message from {sender_id}: {e}")
            raise SessionError(f"Decryption failed: {e}")
            
    def get_session_info(self, contact_id: str) -> Optional[SessionInfo]:
        """
        Get information about a session.
        
        Args:
            contact_id: Contact user ID
            
        Returns:
            SessionInfo or None if no session exists
        """
        state = self.storage.load_session(contact_id)
        if not state:
            return None
        
        contact = self.storage.get_contact(contact_id)
        if not contact:
            return None
        
        # Compute safety number
        safety_number = self.compute_safety_number(contact_id)
        
        return SessionInfo(
            contact_id=contact_id,
            send_count=state.send_msg_num,
            recv_count=state.recv_msg_num,
            safety_number=safety_number,
            verified=contact.verified
        )
        
    async def delete_session(self, contact_id: str):
        """
        Delete session with contact.
        
        Args:
            contact_id: Contact user ID
        """
        self.storage.delete_session(contact_id)
        
        if contact_id in self._ratchets:
            del self._ratchets[contact_id]
        
        logger.info(f"Deleted session with {contact_id}")
        
    def compute_safety_number(self, contact_id: str) -> str:
        """
        Compute safety number for identity verification.
        
        The safety number is a fingerprint of both parties' identity keys,
        used for out-of-band verification to detect MITM attacks.
        
        Args:
            contact_id: Contact user ID
            
        Returns:
            Safety number as formatted string
            
        Raises:
            SessionError: If keys not found
        """
        # Get our identity
        identity_data = self.storage.get_identity()
        if not identity_data:
            raise SessionError("No local identity found")
        
        _, _, our_identity_public, _, _ = identity_data
        
        # Get contact identity
        contact = self.storage.get_contact(contact_id)
        if not contact:
            raise SessionError(f"Contact {contact_id} not found")
        
        contact_identity = contact.identity_key
        
        # Compute fingerprint: SHA256(our_key || their_key)
        # Sort keys to ensure same result regardless of who computes
        keys = sorted([our_identity_public, contact_identity])
        combined = keys[0] + keys[1]
        
        fingerprint = hashlib.sha256(combined).digest()
        
        # Format as groups of 5 digits (total 12 groups)
        # Convert to numeric string
        numeric = int.from_bytes(fingerprint[:8], 'big')  # Use first 8 bytes
        numeric_str = str(numeric).zfill(15)  # Pad to 15 digits
        
        # Format: XXXXX XXXXX XXXXX
        parts = [numeric_str[i:i+5] for i in range(0, 15, 5)]
        return ' '.join(parts)
        
    def _get_ratchet(self, contact_id: str) -> Optional[DoubleRatchet]:
        """
        Get ratchet instance for contact (cached or new).
        
        Args:
            contact_id: Contact user ID
            
        Returns:
            DoubleRatchet instance or None if no session
        """
        # Check cache
        if contact_id in self._ratchets:
            return self._ratchets[contact_id]
        
        # Check if session exists
        state = self.storage.load_session(contact_id)
        if not state:
            return None
        
        # Create and cache ratchet
        ratchet = DoubleRatchet()
        self._ratchets[contact_id] = ratchet
        return ratchet
        
    def _parse_prekey_bundle(self, data: Dict[str, Any]) -> PrekeyBundle:
        """
        Parse prekey bundle from server response.
        
        Args:
            data: Bundle data from server
            
        Returns:
            PrekeyBundle instance
        """
        from typing import Dict, Any
        
        # Parse signed prekey
        signed_data = data.get("signed_prekey", {})
        signed_prekey = SignedPrekeyPair(
            key_id=signed_data["key_id"],
            public_key=bytes.fromhex(signed_data["public_key"]),
            private_key=b"",  # Server doesn't send private key
            signature=bytes.fromhex(signed_data["signature"])
        )
        
        # Parse one-time prekey if present
        onetime_prekey = None
        if "onetime_prekey" in data and data["onetime_prekey"]:
            onetime_data = data["onetime_prekey"]
            onetime_prekey = OneTimePrekeyPair(
                key_id=onetime_data["key_id"],
                public_key=bytes.fromhex(onetime_data["public_key"]),
                private_key=b""  # Server doesn't send private key
            )
        
        return PrekeyBundle(
            identity_key=bytes.fromhex(data["identity_key"]),
            signed_prekey=signed_prekey,
            onetime_prekey=onetime_prekey,
            registration_id=data.get("registration_id", 0)
        )
