"""
WebSocket Transport Layer

Handles communication with the relay server over WebSocket protocol.
Provides automatic reconnection, message queuing, and error handling.
"""

import asyncio
import json
import logging
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass
from enum import Enum

import websockets
from websockets.client import WebSocketClientProtocol
from websockets.exceptions import ConnectionClosed, WebSocketException


logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Message types for client-server communication"""
    # Client -> Server
    REGISTER = "register"
    UPLOAD_PREKEYS = "upload_prekeys"
    FETCH_PREKEY_BUNDLE = "fetch_prekey_bundle"
    SEND_MESSAGE = "send_message"
    ACK = "ack"
    
    # Server -> Client
    REGISTERED = "registered"
    PREKEYS_UPLOADED = "prekeys_uploaded"
    PREKEY_BUNDLE = "prekey_bundle"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    ERROR = "error"


@dataclass
class Message:
    """Incoming message from server"""
    sender_id: str
    message_id: str
    ciphertext: bytes
    timestamp: float


class TransportError(Exception):
    """Transport-related errors"""
    pass


class Transport:
    """
    WebSocket client for communicating with relay server.
    
    Features:
    - Automatic reconnection with exponential backoff
    - Message queue for offline messages
    - Async message handling
    - Connection state management
    """
    
    def __init__(
        self,
        server_url: str,
        user_id: str,
        max_reconnect_attempts: int = 5,
        reconnect_delay: float = 1.0
    ):
        """
        Initialize transport layer.
        
        Args:
            server_url: WebSocket server URL (e.g., "wss://server.com")
            user_id: User identifier for this client
            max_reconnect_attempts: Maximum reconnection attempts
            reconnect_delay: Initial reconnect delay in seconds
        """
        self.server_url = server_url
        self.user_id = user_id
        self.max_reconnect_attempts = max_reconnect_attempts
        self.reconnect_delay = reconnect_delay
        
        self._ws: Optional[WebSocketClientProtocol] = None
        self._connected = False
        self._message_handler: Optional[Callable[[Message], None]] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._pending_requests: Dict[str, asyncio.Future] = {}
        self._request_id_counter = 0
        
    async def connect(self) -> bool:
        """
        Connect to server with automatic reconnection.
        
        Returns:
            True if connected successfully
            
        Raises:
            TransportError: If connection fails after all attempts
        """
        attempts = 0
        delay = self.reconnect_delay
        
        while attempts < self.max_reconnect_attempts:
            try:
                logger.info(f"Connecting to {self.server_url} (attempt {attempts + 1})")
                self._ws = await websockets.connect(
                    self.server_url,
                    ping_interval=30,
                    ping_timeout=10,
                    close_timeout=5
                )
                self._connected = True
                
                # Start receive loop
                self._receive_task = asyncio.create_task(self._receive_loop())
                
                logger.info(f"Connected to {self.server_url}")
                return True
                
            except (ConnectionRefusedError, WebSocketException) as e:
                attempts += 1
                logger.warning(f"Connection attempt {attempts} failed: {e}")
                
                if attempts < self.max_reconnect_attempts:
                    logger.info(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60)  # Exponential backoff, max 60s
                else:
                    raise TransportError(f"Failed to connect after {attempts} attempts: {e}")
        
        raise TransportError(f"Failed to connect after {self.max_reconnect_attempts} attempts")
        
    async def disconnect(self):
        """Disconnect from server and cleanup"""
        self._connected = False
        
        # Cancel receive task
        if self._receive_task and not self._receive_task.done():
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
        
        # Close WebSocket
        if self._ws:
            await self._ws.close()
            self._ws = None
        
        # Cancel pending requests
        for future in self._pending_requests.values():
            if not future.done():
                future.cancel()
        self._pending_requests.clear()
        
        logger.info("Disconnected from server")
        
    def is_connected(self) -> bool:
        """Check if connected to server"""
        return self._connected and self._ws is not None and not self._ws.closed
        
    def set_message_handler(self, handler: Callable[[Message], None]):
        """
        Set handler for incoming messages.
        
        Args:
            handler: Async callback for incoming messages
        """
        self._message_handler = handler
        
    async def register(self, identity_key: bytes, signed_prekey_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register user with server.
        
        Args:
            identity_key: User's identity public key
            signed_prekey_data: Signed prekey bundle data
            
        Returns:
            Registration response
            
        Raises:
            TransportError: If registration fails
        """
        if not self.is_connected():
            raise TransportError("Not connected to server")
        
        request = {
            "type": MessageType.REGISTER.value,
            "user_id": self.user_id,
            "identity_key": identity_key.hex(),
            "signed_prekey": signed_prekey_data
        }
        
        response = await self._send_request(request)
        
        if response.get("type") == MessageType.ERROR.value:
            raise TransportError(f"Registration failed: {response.get('error')}")
        
        return response
        
    async def upload_prekeys(self, prekeys: list) -> bool:
        """
        Upload one-time prekeys to server.
        
        Args:
            prekeys: List of one-time prekey data
            
        Returns:
            True if upload successful
            
        Raises:
            TransportError: If upload fails
        """
        if not self.is_connected():
            raise TransportError("Not connected to server")
        
        request = {
            "type": MessageType.UPLOAD_PREKEYS.value,
            "user_id": self.user_id,
            "prekeys": prekeys
        }
        
        response = await self._send_request(request)
        
        if response.get("type") == MessageType.ERROR.value:
            raise TransportError(f"Prekey upload failed: {response.get('error')}")
        
        return response.get("type") == MessageType.PREKEYS_UPLOADED.value
        
    async def fetch_prekey_bundle(self, recipient_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch prekey bundle for a recipient.
        
        Args:
            recipient_id: Target user ID
            
        Returns:
            Prekey bundle data or None if not found
            
        Raises:
            TransportError: If fetch fails
        """
        if not self.is_connected():
            raise TransportError("Not connected to server")
        
        request = {
            "type": MessageType.FETCH_PREKEY_BUNDLE.value,
            "user_id": self.user_id,
            "recipient_id": recipient_id
        }
        
        response = await self._send_request(request)
        
        if response.get("type") == MessageType.ERROR.value:
            error_msg = response.get("error", "")
            if "not found" in error_msg.lower():
                return None
            raise TransportError(f"Prekey fetch failed: {error_msg}")
        
        if response.get("type") == MessageType.PREKEY_BUNDLE.value:
            return response.get("bundle")
        
        return None
        
    async def send_message(self, recipient_id: str, ciphertext: bytes) -> bool:
        """
        Send encrypted message to recipient.
        
        Args:
            recipient_id: Target user ID
            ciphertext: Encrypted message bytes
            
        Returns:
            True if message sent successfully
            
        Raises:
            TransportError: If send fails
        """
        if not self.is_connected():
            raise TransportError("Not connected to server")
        
        request = {
            "type": MessageType.SEND_MESSAGE.value,
            "sender_id": self.user_id,
            "recipient_id": recipient_id,
            "ciphertext": ciphertext.hex()
        }
        
        response = await self._send_request(request)
        
        if response.get("type") == MessageType.ERROR.value:
            raise TransportError(f"Message send failed: {response.get('error')}")
        
        return response.get("type") == MessageType.MESSAGE_SENT.value
        
    async def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request and wait for response.
        
        Args:
            request: Request data
            
        Returns:
            Response data
            
        Raises:
            TransportError: If request fails
        """
        if not self._ws:
            raise TransportError("WebSocket not connected")
        
        # Add request ID for tracking
        request_id = str(self._request_id_counter)
        self._request_id_counter += 1
        request["request_id"] = request_id
        
        # Create future for response
        future = asyncio.Future()
        self._pending_requests[request_id] = future
        
        try:
            # Send request
            await self._ws.send(json.dumps(request))
            
            # Wait for response with timeout
            response = await asyncio.wait_for(future, timeout=30.0)
            return response
            
        except asyncio.TimeoutError:
            raise TransportError("Request timed out")
        except ConnectionClosed:
            raise TransportError("Connection closed during request")
        finally:
            # Cleanup
            if request_id in self._pending_requests:
                del self._pending_requests[request_id]
                
    async def _receive_loop(self):
        """
        Main receive loop for incoming messages.
        
        Handles both request responses and incoming messages.
        """
        try:
            while self._connected and self._ws:
                try:
                    data = await self._ws.recv()
                    
                    # Parse message
                    try:
                        msg = json.loads(data)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON received: {data}")
                        continue
                    
                    # Handle request response
                    request_id = msg.get("request_id")
                    if request_id and request_id in self._pending_requests:
                        future = self._pending_requests[request_id]
                        if not future.done():
                            future.set_result(msg)
                        continue
                    
                    # Handle incoming message
                    if msg.get("type") == MessageType.MESSAGE_RECEIVED.value:
                        await self._handle_incoming_message(msg)
                    else:
                        logger.warning(f"Unhandled message type: {msg.get('type')}")
                        
                except ConnectionClosed:
                    logger.warning("Connection closed")
                    self._connected = False
                    break
                except Exception as e:
                    logger.error(f"Error in receive loop: {e}", exc_info=True)
                    
        except asyncio.CancelledError:
            logger.info("Receive loop cancelled")
        except Exception as e:
            logger.error(f"Fatal error in receive loop: {e}", exc_info=True)
        finally:
            self._connected = False
            
    async def _handle_incoming_message(self, msg: Dict[str, Any]):
        """
        Handle incoming message from server.
        
        Args:
            msg: Message data
        """
        try:
            message = Message(
                sender_id=msg.get("sender_id", ""),
                message_id=msg.get("message_id", ""),
                ciphertext=bytes.fromhex(msg.get("ciphertext", "")),
                timestamp=msg.get("timestamp", 0.0)
            )
            
            # Send ACK to server
            ack = {
                "type": MessageType.ACK.value,
                "user_id": self.user_id,
                "message_id": message.message_id
            }
            
            if self._ws:
                await self._ws.send(json.dumps(ack))
            
            # Call message handler
            if self._message_handler:
                if asyncio.iscoroutinefunction(self._message_handler):
                    await self._message_handler(message)
                else:
                    self._message_handler(message)
                    
        except Exception as e:
            logger.error(f"Error handling incoming message: {e}", exc_info=True)
            
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
        return False
