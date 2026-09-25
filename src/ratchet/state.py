"""
Double Ratchet State Management

This module manages the state for the Double Ratchet algorithm,
including serialization and key storage.

Reference: Signal Double Ratchet Specification
https://signal.org/docs/specifications/doubleratchet/
"""

from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
import json
import time


# Constants
MAX_SKIP = 1000  # Maximum number of skipped message keys to store
SKIPPED_KEY_TTL = 7 * 24 * 3600  # 7 days in seconds


@dataclass
class MessageHeader:
    """
    Header for encrypted messages in the Double Ratchet protocol.
    
    The header is authenticated as associated data in the AEAD encryption,
    preventing tampering with message ordering or DH keys.
    """
    dh_public: bytes  # Current DH ratchet public key (32 bytes)
    prev_chain_length: int  # Length of previous sending chain
    message_number: int  # Message number in current chain
    
    def encode(self) -> bytes:
        """
        Encode header to bytes for transmission.
        
        Format: dh_public (32 bytes) || prev_chain_length (4 bytes) || message_number (4 bytes)
        Total: 40 bytes
        """
        import struct
        return (
            self.dh_public +
            struct.pack('>I', self.prev_chain_length) +
            struct.pack('>I', self.message_number)
        )
    
    @classmethod
    def decode(cls, data: bytes) -> "MessageHeader":
        """
        Decode header from bytes.
        
        Args:
            data: 40 bytes of header data
            
        Returns:
            MessageHeader instance
        """
        import struct
        if len(data) != 40:
            raise ValueError(f"Header must be 40 bytes, got {len(data)}")
        
        dh_public = data[:32]
        prev_chain_length = struct.unpack('>I', data[32:36])[0]
        message_number = struct.unpack('>I', data[36:40])[0]
        
        return cls(
            dh_public=dh_public,
            prev_chain_length=prev_chain_length,
            message_number=message_number
        )
    
    def to_dict(self) -> dict:
        return {
            "dh_public": self.dh_public.hex(),
            "prev_chain_length": self.prev_chain_length,
            "message_number": self.message_number,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "MessageHeader":
        return cls(
            dh_public=bytes.fromhex(data["dh_public"]),
            prev_chain_length=data["prev_chain_length"],
            message_number=data["message_number"],
        )


@dataclass
class RatchetState:
    """
    State for the Double Ratchet algorithm.
    
    This contains all the information needed to send and receive
    encrypted messages in an ongoing conversation.
    """
    # Root key (rotated on each DH ratchet step)
    root_key: bytes  # 32 bytes
    
    # Chain keys (for symmetric-key ratchet)
    chain_key_send: Optional[bytes]  # 32 bytes or None
    chain_key_recv: Optional[bytes]  # 32 bytes or None
    
    # DH ratchet keys
    dh_private: bytes  # Our current DH private key (32 bytes)
    dh_public: bytes   # Our current DH public key (32 bytes)
    dh_remote: Optional[bytes]  # Remote's current DH public key (32 bytes or None)
    
    # Message counters
    send_msg_num: int = 0  # Messages sent in current sending chain
    recv_msg_num: int = 0  # Messages received in current receiving chain
    prev_chain_length: int = 0  # Length of previous sending chain
    
    # Skipped message keys: (dh_public, msg_num) -> (message_key, timestamp)
    skipped_keys: Dict[Tuple[bytes, int], Tuple[bytes, float]] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize state to dictionary"""
        return {
            "root_key": self.root_key.hex(),
            "chain_key_send": self.chain_key_send.hex() if self.chain_key_send else None,
            "chain_key_recv": self.chain_key_recv.hex() if self.chain_key_recv else None,
            "dh_private": self.dh_private.hex(),
            "dh_public": self.dh_public.hex(),
            "dh_remote": self.dh_remote.hex() if self.dh_remote else None,
            "send_msg_num": self.send_msg_num,
            "recv_msg_num": self.recv_msg_num,
            "prev_chain_length": self.prev_chain_length,
            "skipped_keys": [
                {
                    "dh_public": dh_pub.hex(),
                    "msg_num": msg_num,
                    "message_key": mk.hex(),
                    "timestamp": ts,
                }
                for (dh_pub, msg_num), (mk, ts) in self.skipped_keys.items()
            ],
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "RatchetState":
        """Deserialize state from dictionary"""
        skipped_keys = {}
        for item in data["skipped_keys"]:
            key = (bytes.fromhex(item["dh_public"]), item["msg_num"])
            value = (bytes.fromhex(item["message_key"]), item["timestamp"])
            skipped_keys[key] = value
        
        return cls(
            root_key=bytes.fromhex(data["root_key"]),
            chain_key_send=bytes.fromhex(data["chain_key_send"]) if data["chain_key_send"] else None,
            chain_key_recv=bytes.fromhex(data["chain_key_recv"]) if data["chain_key_recv"] else None,
            dh_private=bytes.fromhex(data["dh_private"]),
            dh_public=bytes.fromhex(data["dh_public"]),
            dh_remote=bytes.fromhex(data["dh_remote"]) if data["dh_remote"] else None,
            send_msg_num=data["send_msg_num"],
            recv_msg_num=data["recv_msg_num"],
            prev_chain_length=data["prev_chain_length"],
            skipped_keys=skipped_keys,
        )
    
    def cleanup_skipped_keys(self, max_age: float = SKIPPED_KEY_TTL):
        """
        Remove expired skipped message keys.
        
        This prevents unbounded growth of the skipped keys cache
        and limits exposure if the cache is compromised.
        
        Args:
            max_age: Maximum age in seconds (default: 7 days)
        """
        current_time = time.time()
        expired_keys = []
        
        for key, (mk, timestamp) in self.skipped_keys.items():
            if current_time - timestamp > max_age:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.skipped_keys[key]
    
    def count_skipped_keys(self) -> int:
        """Return the number of skipped message keys stored"""
        return len(self.skipped_keys)


class TooManySkippedKeysError(Exception):
    """
    Raised when attempting to skip more message keys than allowed.
    
    This could indicate:
    - A desynchronization attack
    - A DoS attempt to fill the skipped keys cache
    - Severe network issues causing massive reordering
    """
    pass


class DecryptionError(Exception):
    """Raised when message decryption fails"""
    pass
