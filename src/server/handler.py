"""
WebSocket message handler for SecureChat relay server.

Handles all client message types and routes them appropriately.
"""

import json
import asyncio
import logging
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass
import re

from src.server.database import Database, MESSAGE_RETENTION_DAYS


# Configure logging
logger = logging.getLogger(__name__)


# Constants
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,32}$')
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB


@dataclass
class ConnectedClient:
    """Represents a connected client"""
    username: str
    websocket: Any  # websockets.WebSocketServerProtocol
    
    async def send(self, message: Dict[str, Any]):
        """Send a JSON message to the client"""
        try:
            await self.websocket.send(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send message to {self.username}: {e}")


class MessageHandler:
    """
    Handles WebSocket messages and routes them to appropriate handlers.
    """
    
    def __init__(self, database: Database):
        """
        Initialize message handler.
        
        Args:
            database: Database instance
        """
        self.db = database
        self.clients: Dict[str, ConnectedClient] = {}  # username -> client
        self.websocket_to_username: Dict[Any, str] = {}  # websocket -> username
    
    async def handle_connection(self, websocket, path):
        """
        Handle a new WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            path: Connection path
        """
        logger.info(f"New connection from {websocket.remote_address}")
        username = None
        
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    
                    if 'type' not in data:
                        await self._send_error(websocket, "INVALID_REQUEST", "Missing 'type' field")
                        continue
                    
                    msg_type = data['type']
                    msg_data = data.get('data', {})
                    
                    # Handle message based on type
                    if msg_type == 'register':
                        username = await self._handle_register(websocket, msg_data)
                    elif msg_type == 'upload_prekeys':
                        await self._handle_upload_prekeys(websocket, msg_data)
                    elif msg_type == 'fetch_prekeys':
                        await self._handle_fetch_prekeys(websocket, msg_data)
                    elif msg_type == 'send_message':
                        await self._handle_send_message(websocket, msg_data)
                    elif msg_type == 'fetch_messages':
                        await self._handle_fetch_messages(websocket, msg_data)
                    elif msg_type == 'message_ack':
                        await self._handle_message_ack(websocket, msg_data)
                    elif msg_type == 'presence':
                        await self._handle_presence(websocket, msg_data)
                    elif msg_type == 'prekey_count':
                        await self._handle_prekey_count(websocket, msg_data)
                    else:
                        await self._send_error(websocket, "INVALID_REQUEST", f"Unknown message type: {msg_type}")
                
                except json.JSONDecodeError:
                    await self._send_error(websocket, "INVALID_REQUEST", "Invalid JSON")
                except Exception as e:
                    logger.error(f"Error handling message: {e}", exc_info=True)
                    await self._send_error(websocket, "INTERNAL_ERROR", str(e))
        
        finally:
            # Clean up on disconnect
            if username:
                self._disconnect_client(username)
                self.db.update_user_status(username, 'offline')
                logger.info(f"User {username} disconnected")
    
    # ========================================================================
    # Message Handlers
    # ========================================================================
    
    async def _handle_register(self, websocket, data: Dict[str, Any]) -> Optional[str]:
        """Handle user registration"""
        username = data.get('username')
        identity_key_hex = data.get('identity_key')
        
        # Validate username
        if not username or not USERNAME_PATTERN.match(username):
            await self._send_error(
                websocket, 
                "INVALID_USERNAME",
                "Username must be 3-32 characters, alphanumeric + underscore"
            )
            return None
        
        # Validate identity key
        if not identity_key_hex:
            await self._send_error(websocket, "INVALID_REQUEST", "Missing identity_key")
            return None
        
        try:
            identity_key = bytes.fromhex(identity_key_hex)
        except ValueError:
            await self._send_error(websocket, "INVALID_REQUEST", "Invalid identity_key format")
            return None
        
        # Register user
        if self.db.register_user(username, identity_key):
            # Success - add to connected clients
            client = ConnectedClient(username, websocket)
            self.clients[username] = client
            self.websocket_to_username[websocket] = username
            self.db.update_user_status(username, 'online')
            
            await client.send({
                'type': 'register_response',
                'success': True,
                'data': {
                    'username': username,
                    'registered_at': self.db.get_user(username)['registered_at']
                }
            })
            
            logger.info(f"User {username} registered successfully")
            return username
        else:
            await self._send_error(websocket, "USER_EXISTS", "Username already taken")
            return None
    
    async def _handle_upload_prekeys(self, websocket, data: Dict[str, Any]):
        """Handle prekey upload"""
        username = data.get('username')
        
        if not self._validate_user(websocket, username):
            return
        
        # Upload signed prekey
        signed_prekey = data.get('signed_prekey')
        if signed_prekey:
            try:
                self.db.upload_signed_prekey(
                    username,
                    bytes.fromhex(signed_prekey['public_key']),
                    bytes.fromhex(signed_prekey['signature']),
                    signed_prekey['key_id']
                )
            except (KeyError, ValueError) as e:
                await self._send_error(websocket, "INVALID_REQUEST", f"Invalid signed_prekey: {e}")
                return
        
        # Upload one-time prekeys
        one_time_prekeys = data.get('one_time_prekeys', [])
        if one_time_prekeys:
            try:
                prekey_tuples = [
                    (bytes.fromhex(opk['public_key']), opk['key_id'])
                    for opk in one_time_prekeys
                ]
                self.db.upload_one_time_prekeys(username, prekey_tuples)
            except (KeyError, ValueError) as e:
                await self._send_error(websocket, "INVALID_REQUEST", f"Invalid one_time_prekeys: {e}")
                return
        
        # Send response
        opk_count = self.db.count_one_time_prekeys(username)
        await self.clients[username].send({
            'type': 'upload_prekeys_response',
            'success': True,
            'data': {
                'signed_prekey_id': signed_prekey['key_id'] if signed_prekey else None,
                'one_time_prekey_count': opk_count,
                'uploaded_at': int(asyncio.get_event_loop().time())
            }
        })
        
        logger.info(f"User {username} uploaded prekeys (OPK count: {opk_count})")
    
    async def _handle_fetch_prekeys(self, websocket, data: Dict[str, Any]):
        """Handle prekey bundle fetch"""
        target_username = data.get('username')
        
        if not target_username:
            await self._send_error(websocket, "INVALID_REQUEST", "Missing username")
            return
        
        # Fetch prekey bundle
        bundle = self.db.fetch_prekey_bundle(target_username)
        
        if not bundle:
            await self._send_error(websocket, "USER_NOT_FOUND", f"User {target_username} not found or has no prekeys")
            return
        
        # Convert bytes to hex for JSON
        response_bundle = {
            'username': bundle['username'],
            'identity_key': bundle['identity_key'].hex(),
            'signed_prekey': {
                'public_key': bundle['signed_prekey']['public_key'].hex(),
                'signature': bundle['signed_prekey']['signature'].hex(),
                'key_id': bundle['signed_prekey']['key_id']
            },
            'one_time_prekey': None
        }
        
        if bundle['one_time_prekey']:
            response_bundle['one_time_prekey'] = {
                'public_key': bundle['one_time_prekey']['public_key'].hex(),
                'key_id': bundle['one_time_prekey']['key_id']
            }
        
        await self._send_json(websocket, {
            'type': 'fetch_prekeys_response',
            'success': True,
            'data': response_bundle
        })
        
        logger.info(f"Prekey bundle fetched for {target_username} (OPK: {bundle['one_time_prekey'] is not None})")
    
    async def _handle_send_message(self, websocket, data: Dict[str, Any]):
        """Handle message send"""
        sender = data.get('from')
        recipient = data.get('to')
        message = data.get('message')
        
        if not all([sender, recipient, message]):
            await self._send_error(websocket, "INVALID_REQUEST", "Missing required fields")
            return
        
        if not self._validate_user(websocket, sender):
            return
        
        # Check recipient exists
        if not self.db.user_exists(recipient):
            await self._send_error(websocket, "USER_NOT_FOUND", f"Recipient {recipient} not found")
            return
        
        # Serialize message
        message_blob = json.dumps({
            'from': sender,
            'to': recipient,
            'message': message,
            'x3dh_initial': data.get('x3dh_initial'),
            'timestamp': int(asyncio.get_event_loop().time())
        }).encode('utf-8')
        
        # Check message size
        if len(message_blob) > MAX_MESSAGE_SIZE:
            await self._send_error(websocket, "MESSAGE_TOO_LARGE", f"Message exceeds {MAX_MESSAGE_SIZE} bytes")
            return
        
        # Queue the message
        message_id = self.db.queue_message(sender, recipient, message_blob)
        
        # Try to deliver immediately if recipient is online
        delivered = False
        if recipient in self.clients:
            try:
                incoming_message = json.loads(message_blob)
                incoming_message['message_id'] = message_id
                incoming_message['type'] = 'incoming_message'
                
                await self.clients[recipient].send({'type': 'incoming_message', 'data': incoming_message})
                delivered = True
                logger.info(f"Message {message_id} delivered immediately to {recipient}")
            except Exception as e:
                logger.error(f"Failed to deliver message immediately: {e}")
        
        # Send response to sender
        await self.clients[sender].send({
            'type': 'send_message_response',
            'success': True,
            'data': {
                'message_id': message_id,
                'delivered': delivered,
                'queued': not delivered
            }
        })
    
    async def _handle_fetch_messages(self, websocket, data: Dict[str, Any]):
        """Handle queued message fetch"""
        username = data.get('username')
        
        if not self._validate_user(websocket, username):
            return
        
        # Get queued messages
        messages = self.db.get_queued_messages(username)
        
        # Convert to response format
        response_messages = []
        for msg in messages:
            try:
                msg_data = json.loads(msg['message_blob'])
                msg_data['message_id'] = msg['message_id']
                response_messages.append(msg_data)
            except json.JSONDecodeError:
                logger.error(f"Failed to decode message {msg['message_id']}")
                continue
        
        await self.clients[username].send({
            'type': 'fetch_messages_response',
            'success': True,
            'data': {
                'messages': response_messages
            }
        })
        
        logger.info(f"User {username} fetched {len(response_messages)} queued messages")
    
    async def _handle_message_ack(self, websocket, data: Dict[str, Any]):
        """Handle message acknowledgment"""
        message_id = data.get('message_id')
        
        if not message_id:
            await self._send_error(websocket, "INVALID_REQUEST", "Missing message_id")
            return
        
        # Delete the message
        self.db.mark_message_delivered(message_id)
        logger.debug(f"Message {message_id} acknowledged and deleted")
    
    async def _handle_presence(self, websocket, data: Dict[str, Any]):
        """Handle presence/status update"""
        username = data.get('username')
        status = data.get('status', 'online')
        
        if not self._validate_user(websocket, username):
            return
        
        if status not in ['online', 'away', 'offline']:
            status = 'online'
        
        self.db.update_user_status(username, status)
        
        user = self.db.get_user(username)
        await self.clients[username].send({
            'type': 'presence_response',
            'success': True,
            'data': {
                'status': status,
                'last_seen': user['last_seen']
            }
        })
    
    async def _handle_prekey_count(self, websocket, data: Dict[str, Any]):
        """Handle prekey count request"""
        username = data.get('username')
        
        if not self._validate_user(websocket, username):
            return
        
        count = self.db.count_one_time_prekeys(username)
        
        await self.clients[username].send({
            'type': 'prekey_count_response',
            'success': True,
            'data': {
                'count': count,
                'needs_replenishment': count < 20
            }
        })
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _validate_user(self, websocket, username: str) -> bool:
        """Validate that the websocket belongs to the user"""
        if username not in self.clients:
            asyncio.create_task(self._send_error(
                websocket, 
                "AUTHENTICATION_FAILED",
                "User not authenticated"
            ))
            return False
        
        if self.clients[username].websocket != websocket:
            asyncio.create_task(self._send_error(
                websocket,
                "AUTHENTICATION_FAILED",
                "Websocket mismatch"
            ))
            return False
        
        return True
    
    def _disconnect_client(self, username: str):
        """Clean up a disconnected client"""
        if username in self.clients:
            websocket = self.clients[username].websocket
            del self.clients[username]
            if websocket in self.websocket_to_username:
                del self.websocket_to_username[websocket]
    
    async def _send_error(self, websocket, error_code: str, message: str):
        """Send an error message"""
        await self._send_json(websocket, {
            'type': 'error',
            'error_code': error_code,
            'message': message
        })
    
    async def _send_json(self, websocket, data: Dict[str, Any]):
        """Send JSON data to websocket"""
        try:
            await websocket.send(json.dumps(data))
        except Exception as e:
            logger.error(f"Failed to send JSON: {e}")
