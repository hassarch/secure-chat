"""
SecureChat CLI Interface

Command-line interface for encrypted messaging.
Provides user registration, messaging, contact management, and session operations.
"""

import asyncio
import sys
import os
import logging
from pathlib import Path
from typing import Optional
import argparse

from .storage import SecureStorage, StorageError
from .transport import Transport, TransportError, Message
from .session import SessionManager, SessionError
from ..crypto.primitives import generate_ed25519_keypair, generate_x25519_keypair, ed25519_sign
from ..x3dh.prekeys import SignedPrekeyPair


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class SecureChatCLI:
    """
    Command-line interface for SecureChat.
    
    Provides commands for user management, messaging, and session operations.
    """
    
    DEFAULT_SERVER = "ws://localhost:8000"
    DEFAULT_DB_DIR = Path.home() / ".securechat"
    
    def __init__(self, user_id: Optional[str] = None, server_url: Optional[str] = None):
        """
        Initialize CLI.
        
        Args:
            user_id: User identifier (loaded from config if not provided)
            server_url: Server URL (uses default if not provided)
        """
        self.user_id = user_id
        self.server_url = server_url or self.DEFAULT_SERVER
        
        self.db_dir = self.DEFAULT_DB_DIR
        self.db_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        self.storage: Optional[SecureStorage] = None
        self.transport: Optional[Transport] = None
        self.session_manager: Optional[SessionManager] = None
        
    async def register(self, password: str) -> bool:
        """
        Register new user with server.
        
        Args:
            password: Password for local storage encryption
            
        Returns:
            True if registration successful
        """
        try:
            if not self.user_id:
                print("Error: User ID required for registration")
                return False
            
            # Create storage
            db_path = self.db_dir / f"{self.user_id}.db"
            if db_path.exists():
                print(f"Error: User {self.user_id} already exists")
                return False
            
            self.storage = SecureStorage(str(db_path), password)
            
            # Generate identity keys
            print("Generating identity keys...")
            identity_private, identity_public = generate_ed25519_keypair()
            
            # Generate signed prekey
            print("Generating signed prekey...")
            spk_private, spk_public = generate_x25519_keypair()
            spk_signature = ed25519_sign(identity_private, spk_public)
            
            signed_prekey = SignedPrekeyPair(
                key_id=1,
                public_key=spk_public,
                private_key=spk_private,
                signature=spk_signature
            )
            
            # Save identity to storage
            registration_id = int.from_bytes(os.urandom(4), 'big')
            self.storage.initialize_identity(
                self.user_id,
                identity_private,
                identity_public,
                signed_prekey,
                registration_id
            )
            
            # Connect to server
            print(f"Connecting to {self.server_url}...")
            self.transport = Transport(self.server_url, self.user_id)
            await self.transport.connect()
            
            # Register with server
            print("Registering with server...")
            signed_prekey_data = {
                "key_id": signed_prekey.key_id,
                "public_key": signed_prekey.public_key.hex(),
                "signature": signed_prekey.signature.hex()
            }
            
            response = await self.transport.register(identity_public, signed_prekey_data)
            
            await self.transport.disconnect()
            self.storage.close()
            
            print(f"✓ Registration successful!")
            print(f"User ID: {self.user_id}")
            print(f"Identity: {identity_public[:8].hex()}...")
            
            return True
            
        except Exception as e:
            logger.error(f"Registration failed: {e}", exc_info=True)
            print(f"✗ Registration failed: {e}")
            return False
            
    async def login(self, password: str) -> bool:
        """
        Login (unlock storage with password).
        
        Args:
            password: Password for storage decryption
            
        Returns:
            True if login successful
        """
        try:
            if not self.user_id:
                print("Error: User ID required")
                return False
            
            db_path = self.db_dir / f"{self.user_id}.db"
            if not db_path.exists():
                print(f"Error: User {self.user_id} not found. Register first.")
                return False
            
            # Open storage
            self.storage = SecureStorage(str(db_path), password)
            
            # Verify password by trying to load identity
            identity = self.storage.get_identity()
            if not identity:
                print("Error: Could not load identity")
                return False
            
            print(f"✓ Logged in as {self.user_id}")
            return True
            
        except StorageError as e:
            print(f"✗ Login failed: {e}")
            return False
            
    async def send_message(self, recipient: str, message: str) -> bool:
        """
        Send encrypted message to recipient.
        
        Args:
            recipient: Recipient user ID
            message: Message text
            
        Returns:
            True if message sent successfully
        """
        try:
            if not await self._ensure_connected():
                return False
            
            plaintext = message.encode('utf-8')
            
            # Check if session exists
            session_info = self.session_manager.get_session_info(recipient)
            
            if not session_info:
                # Initialize new session
                print(f"Initializing session with {recipient}...")
                success = await self.session_manager.initialize_session(recipient)
                if not success:
                    print(f"✗ Failed to initialize session with {recipient}")
                    return False
                print(f"✓ Session established with {recipient}")
            
            # Encrypt message
            ciphertext = await self.session_manager.encrypt_message(recipient, plaintext)
            
            # Send to server
            success = await self.transport.send_message(recipient, ciphertext)
            
            if success:
                print(f"✓ Message sent to {recipient}")
                return True
            else:
                print(f"✗ Failed to send message")
                return False
                
        except (SessionError, TransportError) as e:
            print(f"✗ Send failed: {e}")
            return False
            
    async def receive_messages(self, continuous: bool = False):
        """
        Receive and decrypt messages.
        
        Args:
            continuous: If True, listen continuously; otherwise poll once
        """
        try:
            if not await self._ensure_connected():
                return
            
            # Set message handler
            received_count = 0
            
            async def handle_message(msg: Message):
                nonlocal received_count
                try:
                    # Decrypt message
                    plaintext = await self.session_manager.decrypt_message(
                        msg.sender_id,
                        msg.ciphertext
                    )
                    
                    text = plaintext.decode('utf-8', errors='replace')
                    print(f"\n[{msg.sender_id}]: {text}")
                    received_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to decrypt message: {e}")
                    print(f"✗ Failed to decrypt message from {msg.sender_id}")
            
            self.transport.set_message_handler(handle_message)
            
            if continuous:
                print("Listening for messages (Ctrl+C to stop)...")
                print(f"Connected as: {self.user_id}")
                
                # Keep running until interrupted
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    print(f"\n✓ Received {received_count} message(s)")
            else:
                # Poll for a short time
                print("Checking for messages...")
                await asyncio.sleep(5)
                print(f"✓ Received {received_count} message(s)")
                
        except Exception as e:
            logger.error(f"Receive failed: {e}", exc_info=True)
            print(f"✗ Receive failed: {e}")
            
    async def list_contacts(self):
        """List all contacts and session info"""
        try:
            if not self.storage:
                print("Error: Not logged in")
                return
            
            contacts = self.storage.list_contacts()
            
            if not contacts:
                print("No contacts yet")
                return
            
            print(f"\nContacts ({len(contacts)}):")
            print("-" * 80)
            
            for contact in contacts:
                verified_str = "✓ Verified" if contact.verified else "⚠ Unverified"
                print(f"\nUser ID: {contact.contact_id}")
                print(f"  Status: {verified_str}")
                print(f"  Identity: {contact.identity_key[:8].hex()}...")
                
                # Check if session exists
                if await self._ensure_connected():
                    session_info = self.session_manager.get_session_info(contact.contact_id)
                    if session_info:
                        print(f"  Session: Active")
                        print(f"  Messages sent: {session_info.send_count}")
                        print(f"  Messages received: {session_info.recv_count}")
                        print(f"  Safety number: {session_info.safety_number}")
                    else:
                        print(f"  Session: Not initialized")
                        
        except Exception as e:
            logger.error(f"List contacts failed: {e}")
            print(f"✗ Failed to list contacts: {e}")
            
    async def verify_contact(self, contact_id: str, safety_number: str):
        """
        Verify contact's identity with safety number.
        
        Args:
            contact_id: Contact user ID
            safety_number: Safety number to verify
        """
        try:
            if not await self._ensure_connected():
                return
            
            # Get session info
            session_info = self.session_manager.get_session_info(contact_id)
            if not session_info:
                print(f"Error: No session with {contact_id}")
                return
            
            # Compare safety numbers
            computed = session_info.safety_number
            provided = safety_number.replace(" ", "")
            computed_clean = computed.replace(" ", "")
            
            if computed_clean == provided:
                self.storage.verify_contact(contact_id, computed)
                print(f"✓ Contact {contact_id} verified successfully")
            else:
                print(f"✗ Safety number mismatch!")
                print(f"Expected: {computed}")
                print(f"Got:      {safety_number}")
                print("\nWARNING: This could indicate a man-in-the-middle attack!")
                
        except Exception as e:
            print(f"✗ Verification failed: {e}")
            
    async def show_status(self):
        """Show connection and identity status"""
        try:
            if not self.storage:
                print("Not logged in")
                return
            
            identity = self.storage.get_identity()
            if not identity:
                print("No identity found")
                return
            
            user_id, _, identity_public, signed_prekey, registration_id = identity
            
            print(f"\nStatus:")
            print(f"  User ID: {user_id}")
            print(f"  Identity: {identity_public.hex()}")
            print(f"  Registration ID: {registration_id}")
            print(f"  Signed Prekey ID: {signed_prekey.key_id}")
            
            if self.transport and self.transport.is_connected():
                print(f"  Connection: ✓ Connected to {self.server_url}")
            else:
                print(f"  Connection: ✗ Not connected")
                
        except Exception as e:
            print(f"✗ Status check failed: {e}")
            
    async def delete_session(self, contact_id: str):
        """
        Delete session with contact.
        
        Args:
            contact_id: Contact user ID
        """
        try:
            if not await self._ensure_connected():
                return
            
            await self.session_manager.delete_session(contact_id)
            print(f"✓ Session with {contact_id} deleted")
            
        except Exception as e:
            print(f"✗ Delete session failed: {e}")
            
    async def _ensure_connected(self) -> bool:
        """Ensure storage, transport, and session manager are ready"""
        if not self.storage:
            print("Error: Not logged in")
            return False
        
        if not self.transport or not self.transport.is_connected():
            # Connect to server
            print(f"Connecting to {self.server_url}...")
            self.transport = Transport(self.server_url, self.user_id)
            try:
                await self.transport.connect()
            except TransportError as e:
                print(f"✗ Connection failed: {e}")
                return False
        
        if not self.session_manager:
            self.session_manager = SessionManager(self.storage, self.transport)
        
        return True
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.transport:
            await self.transport.disconnect()
        if self.storage:
            self.storage.close()


async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SecureChat - End-to-End Encrypted Messaging",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global options
    parser.add_argument('--user', '-u', dest='user_id', help='User ID')
    parser.add_argument('--server', '-s', help='Server URL (default: ws://localhost:8000)')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Register
    register_parser = subparsers.add_parser('register', help='Register new user')
    register_parser.add_argument('username', help='Username to register')
    register_parser.add_argument('--password', '-p', required=True, help='Password for encryption')
    
    # Login
    login_parser = subparsers.add_parser('login', help='Login (unlock storage)')
    login_parser.add_argument('username', help='Username to login')
    login_parser.add_argument('--password', '-p', required=True, help='Password')
    
    # Send
    send_parser = subparsers.add_parser('send', help='Send message')
    send_parser.add_argument('recipient', help='Recipient user ID')
    send_parser.add_argument('message', help='Message text')
    send_parser.add_argument('--password', '-p', required=True, help='Password')
    
    # Receive
    receive_parser = subparsers.add_parser('receive', help='Receive messages')
    receive_parser.add_argument('--password', '-p', required=True, help='Password')
    
    # Listen
    listen_parser = subparsers.add_parser('listen', help='Listen for messages continuously')
    listen_parser.add_argument('--password', '-p', required=True, help='Password')
    
    # Contacts
    contacts_parser = subparsers.add_parser('contacts', help='Manage contacts')
    contacts_subparsers = contacts_parser.add_subparsers(dest='contacts_command')
    
    list_parser = contacts_subparsers.add_parser('list', help='List contacts')
    list_parser.add_argument('--password', '-p', required=True, help='Password')
    
    verify_parser = contacts_subparsers.add_parser('verify', help='Verify contact')
    verify_parser.add_argument('contact_id', help='Contact user ID')
    verify_parser.add_argument('safety_number', help='Safety number')
    verify_parser.add_argument('--password', '-p', required=True, help='Password')
    
    # Status
    status_parser = subparsers.add_parser('status', help='Show status')
    status_parser.add_argument('--password', '-p', required=True, help='Password')
    
    # Session
    session_parser = subparsers.add_parser('session', help='Manage sessions')
    session_subparsers = session_parser.add_subparsers(dest='session_command')
    
    delete_parser = session_subparsers.add_parser('delete', help='Delete session')
    delete_parser.add_argument('contact_id', help='Contact user ID')
    delete_parser.add_argument('--password', '-p', required=True, help='Password')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Determine user_id
    user_id = args.user_id
    if args.command == 'register':
        user_id = args.username
    elif args.command == 'login':
        user_id = args.username
    
    if not user_id and args.command not in ['register', 'login']:
        print("Error: --user required")
        return 1
    
    # Create CLI instance
    cli = SecureChatCLI(user_id, args.server)
    
    try:
        # Execute command
        if args.command == 'register':
            success = await cli.register(args.password)
            return 0 if success else 1
            
        elif args.command == 'login':
            success = await cli.login(args.password)
            return 0 if success else 1
            
        elif args.command == 'send':
            await cli.login(args.password)
            success = await cli.send_message(args.recipient, args.message)
            return 0 if success else 1
            
        elif args.command == 'receive':
            await cli.login(args.password)
            await cli.receive_messages(continuous=False)
            return 0
            
        elif args.command == 'listen':
            await cli.login(args.password)
            await cli.receive_messages(continuous=True)
            return 0
            
        elif args.command == 'contacts':
            if args.contacts_command == 'list':
                await cli.login(args.password)
                await cli.list_contacts()
                return 0
            elif args.contacts_command == 'verify':
                await cli.login(args.password)
                await cli.verify_contact(args.contact_id, args.safety_number)
                return 0
                
        elif args.command == 'status':
            await cli.login(args.password)
            await cli.show_status()
            return 0
            
        elif args.command == 'session':
            if args.session_command == 'delete':
                await cli.login(args.password)
                await cli.delete_session(args.contact_id)
                return 0
        
        return 0
        
    finally:
        await cli.cleanup()


def run():
    """Entry point for CLI script"""
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    run()
