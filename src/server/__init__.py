"""
SecureChat Relay Server

WebSocket-based relay server for routing encrypted messages
and managing prekey bundles.

The server cannot decrypt message content but can see metadata.
"""

from .database import Database, DatabaseError
from .handler import MessageHandler, ConnectedClient
from .main import SecureChatServer

__all__ = [
    "Database",
    "DatabaseError",
    "MessageHandler",
    "ConnectedClient",
    "SecureChatServer",
]
