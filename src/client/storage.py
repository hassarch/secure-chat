"""
Encrypted Storage Layer

Securely stores identity keys, sessions, and contacts using password-based encryption.
All sensitive data is encrypted at rest using Argon2id-derived keys.
"""

import os
import sqlite3
import json
from typing import Optional, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import nacl.secret
import nacl.pwhash
import nacl.utils
from nacl.encoding import Base64Encoder

from ..x3dh.prekeys import SignedPrekeyPair
from ..ratchet.state import RatchetState


@dataclass
class Contact:
    """Contact information and verification status"""
    contact_id: str
    identity_key: bytes
    verified: bool = False
    safety_number: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_updated: Optional[datetime] = None


class StorageError(Exception):
    """Storage-related errors"""
    pass


class SecureStorage:
    """
    Encrypted storage for identity keys, sessions, and contacts.
    
    Uses Argon2id for password-based key derivation and XChaCha20-Poly1305
    for authenticated encryption of sensitive data.
    """
    
    # Argon2id parameters (following OWASP recommendations)
    ARGON2_OPSLIMIT = nacl.pwhash.argon2id.OPSLIMIT_MODERATE  # 3
    ARGON2_MEMLIMIT = nacl.pwhash.argon2id.MEMLIMIT_MODERATE  # 64MB
    
    def __init__(self, db_path: str, password: str):
        """
        Initialize secure storage with password-based encryption.
        
        Args:
            db_path: Path to SQLite database file
            password: User password for key derivation
            
        Raises:
            StorageError: If initialization fails
        """
        self.db_path = db_path
        self._password = password.encode('utf-8')
        self._master_key: Optional[bytes] = None
        self._conn: Optional[sqlite3.Connection] = None
        
        # Create database directory if needed
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, mode=0o700)
        
        # Initialize database
        self._init_database()
        
    def _init_database(self):
        """Initialize database schema and derive master key"""
        # Check if database exists
        db_exists = os.path.exists(self.db_path)
        
        # Connect with secure settings
        self._conn = sqlite3.connect(
            self.db_path,
            isolation_level=None,  # Autocommit mode
            check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        
        # Enable WAL mode for better concurrency
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        
        # Check if metadata table exists (more reliable than file existence)
        cursor = self._conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='metadata'
        """)
        metadata_exists = cursor.fetchone() is not None
        
        if not metadata_exists:
            # New database - generate salt and create schema
            salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
            self._create_schema(salt)
        else:
            # Existing database - load salt
            salt = self._load_salt()
            if salt is None:
                raise StorageError("Database exists but salt not found - corrupted database?")
        
        # Derive master key from password
        self._master_key = nacl.pwhash.argon2id.kdf(
            size=nacl.secret.SecretBox.KEY_SIZE,
            password=self._password,
            salt=salt,
            opslimit=self.ARGON2_OPSLIMIT,
            memlimit=self.ARGON2_MEMLIMIT
        )
        
    def _create_schema(self, salt: bytes):
        """Create database schema"""
        cursor = self._conn.cursor()
        
        # Metadata table for salt and version
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
        """)
        
        # Store salt
        cursor.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            ('salt', salt)
        )
        cursor.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            ('version', b'1.0')
        )
        
        # Identity table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity (
                user_id TEXT PRIMARY KEY,
                identity_private_key BLOB NOT NULL,
                identity_public_key BLOB NOT NULL,
                signed_prekey_private BLOB NOT NULL,
                signed_prekey_public BLOB NOT NULL,
                signed_prekey_signature BLOB NOT NULL,
                prekey_id INTEGER NOT NULL,
                registration_id INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Contacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                contact_id TEXT PRIMARY KEY,
                identity_key BLOB NOT NULL,
                verified INTEGER DEFAULT 0,
                safety_number TEXT,
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_updated TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                contact_id TEXT PRIMARY KEY,
                session_state BLOB NOT NULL,
                last_message_time TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contact_id) REFERENCES contacts(contact_id)
            )
        """)
        
        # Pending messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_messages (
                message_id TEXT PRIMARY KEY,
                recipient_id TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (recipient_id) REFERENCES contacts(contact_id)
            )
        """)
        
        # Create indexes
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_time 
            ON sessions(last_message_time)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pending_time 
            ON pending_messages(created_at)
        """)
        
        self._conn.commit()
        
    def _load_salt(self) -> Optional[bytes]:
        """Load salt from metadata table"""
        cursor = self._conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = ?", ('salt',))
        row = cursor.fetchone()
        return row[0] if row else None
        
    def _encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with master key"""
        if not self._master_key:
            raise StorageError("Master key not initialized")
        box = nacl.secret.SecretBox(self._master_key)
        return box.encrypt(plaintext)
        
    def _decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with master key"""
        if not self._master_key:
            raise StorageError("Master key not initialized")
        try:
            box = nacl.secret.SecretBox(self._master_key)
            return box.decrypt(ciphertext)
        except nacl.exceptions.CryptoError as e:
            raise StorageError(f"Decryption failed - wrong password or corrupted data: {e}")
            
    def initialize_identity(
        self,
        user_id: str,
        identity_private_key: bytes,
        identity_public_key: bytes,
        signed_prekey: SignedPrekeyPair,
        registration_id: int
    ):
        """
        Initialize user identity (first-time setup).
        
        Args:
            user_id: User identifier
            identity_private_key: Ed25519 private key
            identity_public_key: Ed25519 public key
            signed_prekey: Signed prekey bundle
            registration_id: Registration ID
            
        Raises:
            StorageError: If identity already exists
        """
        cursor = self._conn.cursor()
        
        # Check if identity already exists
        cursor.execute("SELECT user_id FROM identity WHERE user_id = ?", (user_id,))
        if cursor.fetchone():
            raise StorageError(f"Identity for {user_id} already exists")
        
        # Encrypt private keys
        encrypted_identity_key = self._encrypt(identity_private_key)
        encrypted_prekey = self._encrypt(signed_prekey.private_key)
        
        # Insert identity
        cursor.execute("""
            INSERT INTO identity (
                user_id, identity_private_key, identity_public_key,
                signed_prekey_private, signed_prekey_public, signed_prekey_signature,
                prekey_id, registration_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            encrypted_identity_key,
            identity_public_key,
            encrypted_prekey,
            signed_prekey.public_key,
            signed_prekey.signature,
            signed_prekey.key_id,
            registration_id
        ))
        
        self._conn.commit()
        
    def get_identity(self) -> Optional[Tuple[str, bytes, bytes, SignedPrekeyPair, int]]:
        """
        Get user identity.
        
        Returns:
            Tuple of (user_id, identity_private_key, identity_public_key, signed_prekey, registration_id)
            or None if not initialized
        """
        cursor = self._conn.cursor()
        cursor.execute("""
            SELECT user_id, identity_private_key, identity_public_key,
                   signed_prekey_private, signed_prekey_public, signed_prekey_signature,
                   prekey_id, registration_id
            FROM identity LIMIT 1
        """)
        
        row = cursor.fetchone()
        if not row:
            return None
        
        # Decrypt private keys
        identity_private = self._decrypt(row['identity_private_key'])
        prekey_private = self._decrypt(row['signed_prekey_private'])
        
        signed_prekey = SignedPrekeyPair(
            key_id=row['prekey_id'],
            public_key=row['signed_prekey_public'],
            private_key=prekey_private,
            signature=row['signed_prekey_signature']
        )
        
        return (
            row['user_id'],
            identity_private,
            row['identity_public_key'],
            signed_prekey,
            row['registration_id']
        )
        
    def save_session(self, contact_id: str, state: RatchetState):
        """
        Save Double Ratchet session state.
        
        Args:
            contact_id: Contact identifier
            state: Ratchet state to save
        """
        # Serialize and encrypt session state
        state_dict = state.to_dict()
        state_json = json.dumps(state_dict).encode('utf-8')
        encrypted_state = self._encrypt(state_json)
        
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO sessions (contact_id, session_state, last_message_time)
            VALUES (?, ?, ?)
        """, (contact_id, encrypted_state, datetime.utcnow().isoformat()))
        
        self._conn.commit()
        
    def load_session(self, contact_id: str) -> Optional[RatchetState]:
        """
        Load Double Ratchet session state.
        
        Args:
            contact_id: Contact identifier
            
        Returns:
            RatchetState or None if no session exists
        """
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT session_state FROM sessions WHERE contact_id = ?",
            (contact_id,)
        )
        
        row = cursor.fetchone()
        if not row:
            return None
        
        # Decrypt and deserialize
        try:
            state_json = self._decrypt(row['session_state'])
            state_dict = json.loads(state_json)
            return RatchetState.from_dict(state_dict)
        except (json.JSONDecodeError, KeyError) as e:
            raise StorageError(f"Failed to deserialize session state: {e}")
            
    def add_contact(
        self,
        contact_id: str,
        identity_key: bytes,
        verified: bool = False,
        safety_number: Optional[str] = None
    ):
        """
        Add or update a contact.
        
        Args:
            contact_id: Contact identifier
            identity_key: Contact's identity public key
            verified: Whether identity is verified
            safety_number: Safety number (fingerprint)
        """
        cursor = self._conn.cursor()
        
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO contacts (contact_id, identity_key, verified, safety_number, first_seen, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(contact_id) DO UPDATE SET
                identity_key = excluded.identity_key,
                verified = excluded.verified,
                safety_number = excluded.safety_number,
                last_updated = excluded.last_updated
        """, (contact_id, identity_key, int(verified), safety_number, now, now))
        
        self._conn.commit()
        
    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """
        Get contact information.
        
        Args:
            contact_id: Contact identifier
            
        Returns:
            Contact or None if not found
        """
        cursor = self._conn.cursor()
        cursor.execute("""
            SELECT contact_id, identity_key, verified, safety_number, first_seen, last_updated
            FROM contacts WHERE contact_id = ?
        """, (contact_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        return Contact(
            contact_id=row['contact_id'],
            identity_key=row['identity_key'],
            verified=bool(row['verified']),
            safety_number=row['safety_number'],
            first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
            last_updated=datetime.fromisoformat(row['last_updated']) if row['last_updated'] else None
        )
        
    def list_contacts(self) -> List[Contact]:
        """
        List all contacts.
        
        Returns:
            List of Contact objects
        """
        cursor = self._conn.cursor()
        cursor.execute("""
            SELECT contact_id, identity_key, verified, safety_number, first_seen, last_updated
            FROM contacts
            ORDER BY last_updated DESC
        """)
        
        contacts = []
        for row in cursor.fetchall():
            contacts.append(Contact(
                contact_id=row['contact_id'],
                identity_key=row['identity_key'],
                verified=bool(row['verified']),
                safety_number=row['safety_number'],
                first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
                last_updated=datetime.fromisoformat(row['last_updated']) if row['last_updated'] else None
            ))
        
        return contacts
        
    def verify_contact(self, contact_id: str, safety_number: str):
        """
        Mark contact as verified with safety number.
        
        Args:
            contact_id: Contact identifier
            safety_number: Verified safety number
        """
        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE contacts 
            SET verified = 1, safety_number = ?, last_updated = ?
            WHERE contact_id = ?
        """, (safety_number, datetime.utcnow().isoformat(), contact_id))
        
        if cursor.rowcount == 0:
            raise StorageError(f"Contact {contact_id} not found")
        
        self._conn.commit()
        
    def delete_session(self, contact_id: str):
        """
        Delete session with contact.
        
        Args:
            contact_id: Contact identifier
        """
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE contact_id = ?", (contact_id,))
        self._conn.commit()
        
    def delete_contact(self, contact_id: str):
        """
        Delete contact and associated session.
        
        Args:
            contact_id: Contact identifier
        """
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE contact_id = ?", (contact_id,))
        cursor.execute("DELETE FROM contacts WHERE contact_id = ?", (contact_id,))
        cursor.execute("DELETE FROM pending_messages WHERE recipient_id = ?", (contact_id,))
        self._conn.commit()
        
    def close(self):
        """Close database connection and clear sensitive data"""
        if self._conn:
            self._conn.close()
            self._conn = None
        
        # Clear master key from memory
        if self._master_key:
            # Overwrite with zeros before deletion
            self._master_key = b'\x00' * len(self._master_key)
            self._master_key = None
        
        # Clear password
        if self._password:
            self._password = b'\x00' * len(self._password)
            self._password = None
            
    def __enter__(self):
        """Context manager entry"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False
