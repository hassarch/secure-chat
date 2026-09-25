"""
Database layer for SecureChat relay server.

Provides storage for:
- User registrations
- Prekey bundles
- Message queue

Uses SQLite for simplicity (easily upgradeable to PostgreSQL).
"""

import sqlite3
import time
import uuid
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from pathlib import Path


# Constants
MESSAGE_RETENTION_DAYS = 30
PREKEY_LOW_THRESHOLD = 20


class DatabaseError(Exception):
    """Base exception for database errors"""
    pass


class Database:
    """
    SQLite database for relay server.
    
    Thread-safe through connection pooling (one connection per thread).
    """
    
    def __init__(self, db_path: str = "securechat.db"):
        """
        Initialize database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Get a database connection (context manager)"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Access columns by name
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Create database schema if it doesn't exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    identity_key BLOB NOT NULL,
                    registered_at INTEGER NOT NULL,
                    last_seen INTEGER,
                    status TEXT DEFAULT 'offline'
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_status 
                ON users(status)
            """)
            
            # Signed prekeys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS signed_prekeys (
                    username TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    key_id INTEGER NOT NULL,
                    uploaded_at INTEGER NOT NULL,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
            """)
            
            # One-time prekeys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS one_time_prekeys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    key_id INTEGER NOT NULL,
                    uploaded_at INTEGER NOT NULL,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_opk_username 
                ON one_time_prekeys(username)
            """)
            
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_opk_user_keyid 
                ON one_time_prekeys(username, key_id)
            """)
            
            # Message queue table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS message_queue (
                    message_id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    message_blob BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    delivered BOOLEAN DEFAULT 0,
                    FOREIGN KEY (recipient) REFERENCES users(username) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_mq_recipient 
                ON message_queue(recipient, delivered)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_mq_expires 
                ON message_queue(expires_at)
            """)
    
    # ========================================================================
    # User Management
    # ========================================================================
    
    def register_user(self, username: str, identity_key: bytes) -> bool:
        """
        Register a new user.
        
        Args:
            username: Unique username
            identity_key: Ed25519 public key
            
        Returns:
            True if registered, False if username taken
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, identity_key, registered_at, status)
                    VALUES (?, ?, ?, 'offline')
                """, (username, identity_key, int(time.time())))
                return True
        except sqlite3.IntegrityError:
            return False
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user information.
        
        Args:
            username: Username to look up
            
        Returns:
            Dict with user info or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT username, identity_key, registered_at, last_seen, status
                FROM users WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    def user_exists(self, username: str) -> bool:
        """Check if a user exists"""
        return self.get_user(username) is not None
    
    def update_user_status(self, username: str, status: str):
        """
        Update user's online status.
        
        Args:
            username: Username
            status: 'online', 'away', or 'offline'
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET status = ?, last_seen = ?
                WHERE username = ?
            """, (status, int(time.time()), username))
    
    # ========================================================================
    # Prekey Management
    # ========================================================================
    
    def upload_signed_prekey(
        self,
        username: str,
        public_key: bytes,
        signature: bytes,
        key_id: int
    ):
        """
        Upload/replace signed prekey.
        
        Args:
            username: User uploading the key
            public_key: X25519 public key
            signature: Ed25519 signature
            key_id: Key identifier for rotation
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO signed_prekeys 
                (username, public_key, signature, key_id, uploaded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (username, public_key, signature, key_id, int(time.time())))
    
    def upload_one_time_prekeys(
        self,
        username: str,
        prekeys: List[Tuple[bytes, int]]
    ):
        """
        Upload one-time prekeys.
        
        Args:
            username: User uploading keys
            prekeys: List of (public_key, key_id) tuples
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            timestamp = int(time.time())
            
            for public_key, key_id in prekeys:
                try:
                    cursor.execute("""
                        INSERT INTO one_time_prekeys 
                        (username, public_key, key_id, uploaded_at)
                        VALUES (?, ?, ?, ?)
                    """, (username, public_key, key_id, timestamp))
                except sqlite3.IntegrityError:
                    # Duplicate key_id - skip
                    continue
    
    def fetch_prekey_bundle(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a user's prekey bundle.
        
        Consumes one one-time prekey (if available).
        
        Args:
            username: User whose prekeys to fetch
            
        Returns:
            Dict with identity_key, signed_prekey, and one_time_prekey (or None)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get user and signed prekey
            cursor.execute("""
                SELECT u.identity_key, 
                       s.public_key as spk_public, 
                       s.signature as spk_signature,
                       s.key_id as spk_key_id
                FROM users u
                LEFT JOIN signed_prekeys s ON u.username = s.username
                WHERE u.username = ?
            """, (username,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            if not row['spk_public']:
                # User has no signed prekey uploaded
                return None
            
            bundle = {
                'username': username,
                'identity_key': row['identity_key'],
                'signed_prekey': {
                    'public_key': row['spk_public'],
                    'signature': row['spk_signature'],
                    'key_id': row['spk_key_id']
                },
                'one_time_prekey': None
            }
            
            # Try to get and consume one-time prekey
            cursor.execute("""
                SELECT id, public_key, key_id
                FROM one_time_prekeys
                WHERE username = ?
                LIMIT 1
            """, (username,))
            
            opk_row = cursor.fetchone()
            if opk_row:
                bundle['one_time_prekey'] = {
                    'public_key': opk_row['public_key'],
                    'key_id': opk_row['key_id']
                }
                
                # Delete the consumed prekey
                cursor.execute("""
                    DELETE FROM one_time_prekeys WHERE id = ?
                """, (opk_row['id'],))
            
            return bundle
    
    def count_one_time_prekeys(self, username: str) -> int:
        """
        Count available one-time prekeys for a user.
        
        Args:
            username: User to check
            
        Returns:
            Number of available one-time prekeys
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM one_time_prekeys
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            return row['count'] if row else 0
    
    # ========================================================================
    # Message Queue
    # ========================================================================
    
    def queue_message(
        self,
        sender: str,
        recipient: str,
        message_blob: bytes
    ) -> str:
        """
        Queue a message for delivery.
        
        Args:
            sender: Sender username
            recipient: Recipient username
            message_blob: Serialized message (JSON or protobuf)
            
        Returns:
            Message ID (UUID)
        """
        message_id = str(uuid.uuid4())
        current_time = int(time.time())
        expires_at = current_time + (MESSAGE_RETENTION_DAYS * 24 * 3600)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO message_queue 
                (message_id, sender, recipient, message_blob, created_at, expires_at, delivered)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (message_id, sender, recipient, message_blob, current_time, expires_at))
        
        return message_id
    
    def get_queued_messages(self, username: str) -> List[Dict[str, Any]]:
        """
        Get all queued messages for a user.
        
        Args:
            username: Recipient username
            
        Returns:
            List of message dicts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_id, sender, message_blob, created_at
                FROM message_queue
                WHERE recipient = ? AND delivered = 0
                ORDER BY created_at ASC
            """, (username,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def mark_message_delivered(self, message_id: str):
        """
        Mark a message as delivered (and delete it).
        
        Args:
            message_id: Message UUID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM message_queue WHERE message_id = ?
            """, (message_id,))
    
    def cleanup_expired_messages(self) -> int:
        """
        Delete expired messages.
        
        Returns:
            Number of messages deleted
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM message_queue WHERE expires_at < ?
            """, (int(time.time()),))
            return cursor.rowcount
    
    # ========================================================================
    # Maintenance
    # ========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dict with various stats
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # User count
            cursor.execute("SELECT COUNT(*) as count FROM users")
            user_count = cursor.fetchone()['count']
            
            # Online users
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE status = 'online'")
            online_count = cursor.fetchone()['count']
            
            # Queued messages
            cursor.execute("SELECT COUNT(*) as count FROM message_queue WHERE delivered = 0")
            queued_count = cursor.fetchone()['count']
            
            # Total one-time prekeys
            cursor.execute("SELECT COUNT(*) as count FROM one_time_prekeys")
            opk_count = cursor.fetchone()['count']
            
            return {
                'users': user_count,
                'online_users': online_count,
                'queued_messages': queued_count,
                'one_time_prekeys': opk_count
            }
    
    def vacuum(self):
        """Optimize database (reclaim space)"""
        with self._get_connection() as conn:
            conn.execute("VACUUM")
