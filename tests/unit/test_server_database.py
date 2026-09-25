"""
Unit tests for server database layer.

Tests verify:
1. User registration and lookup
2. Prekey storage and retrieval
3. Message queue operations
4. Database maintenance
"""

import pytest
import tempfile
import time
from pathlib import Path

from src.server.database import Database


@pytest.fixture
def db():
    """Create a temporary database for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        database = Database(str(db_path))
        yield database


class TestUserManagement:
    """Test user registration and management"""
    
    def test_register_user(self, db):
        """Test user registration"""
        identity_key = b"test_identity_key_32_bytes_long!"
        
        # Register user
        success = db.register_user("alice", identity_key)
        assert success is True
        
        # Verify user exists
        user = db.get_user("alice")
        assert user is not None
        assert user['username'] == "alice"
        assert user['identity_key'] == identity_key
        assert user['status'] == 'offline'
    
    def test_register_duplicate_user(self, db):
        """Test that duplicate registration fails"""
        identity_key = b"test_key"
        
        db.register_user("alice", identity_key)
        success = db.register_user("alice", b"different_key")
        
        assert success is False
    
    def test_user_exists(self, db):
        """Test user existence check"""
        db.register_user("alice", b"key")
        
        assert db.user_exists("alice") is True
        assert db.user_exists("bob") is False
    
    def test_update_user_status(self, db):
        """Test updating user status"""
        db.register_user("alice", b"key")
        
        db.update_user_status("alice", "online")
        user = db.get_user("alice")
        assert user['status'] == "online"
        assert user['last_seen'] is not None


class TestPrekeyManagement:
    """Test prekey storage and retrieval"""
    
    def test_upload_signed_prekey(self, db):
        """Test uploading signed prekey"""
        db.register_user("alice", b"identity_key")
        
        public_key = b"spk_public_key"
        signature = b"spk_signature"
        key_id = 1
        
        db.upload_signed_prekey("alice", public_key, signature, key_id)
        
        # Fetch bundle to verify
        bundle = db.fetch_prekey_bundle("alice")
        assert bundle is not None
        assert bundle['signed_prekey']['public_key'] == public_key
        assert bundle['signed_prekey']['signature'] == signature
        assert bundle['signed_prekey']['key_id'] == key_id
    
    def test_replace_signed_prekey(self, db):
        """Test that uploading new signed prekey replaces old one"""
        db.register_user("alice", b"identity_key")
        
        db.upload_signed_prekey("alice", b"old_key", b"old_sig", 1)
        db.upload_signed_prekey("alice", b"new_key", b"new_sig", 2)
        
        bundle = db.fetch_prekey_bundle("alice")
        assert bundle['signed_prekey']['public_key'] == b"new_key"
        assert bundle['signed_prekey']['key_id'] == 2
    
    def test_upload_one_time_prekeys(self, db):
        """Test uploading one-time prekeys"""
        db.register_user("alice", b"identity_key")
        
        prekeys = [
            (b"opk_1", 1),
            (b"opk_2", 2),
            (b"opk_3", 3)
        ]
        
        db.upload_one_time_prekeys("alice", prekeys)
        
        count = db.count_one_time_prekeys("alice")
        assert count == 3
    
    def test_fetch_prekey_bundle_consumes_opk(self, db):
        """Test that fetching bundle consumes one OPK"""
        db.register_user("alice", b"identity_key")
        db.upload_signed_prekey("alice", b"spk", b"sig", 1)
        db.upload_one_time_prekeys("alice", [(b"opk_1", 1), (b"opk_2", 2)])
        
        # First fetch
        bundle1 = db.fetch_prekey_bundle("alice")
        assert bundle1['one_time_prekey'] is not None
        assert db.count_one_time_prekeys("alice") == 1
        
        # Second fetch
        bundle2 = db.fetch_prekey_bundle("alice")
        assert bundle2['one_time_prekey'] is not None
        assert db.count_one_time_prekeys("alice") == 0
        
        # Third fetch (no OPK available)
        bundle3 = db.fetch_prekey_bundle("alice")
        assert bundle3['one_time_prekey'] is None
    
    def test_fetch_nonexistent_user(self, db):
        """Test fetching bundle for nonexistent user"""
        bundle = db.fetch_prekey_bundle("nobody")
        assert bundle is None
    
    def test_count_one_time_prekeys(self, db):
        """Test counting one-time prekeys"""
        db.register_user("alice", b"key")
        
        assert db.count_one_time_prekeys("alice") == 0
        
        db.upload_one_time_prekeys("alice", [(b"opk", i) for i in range(10)])
        assert db.count_one_time_prekeys("alice") == 10


class TestMessageQueue:
    """Test message queue operations"""
    
    def test_queue_message(self, db):
        """Test queuing a message"""
        db.register_user("alice", b"key1")
        db.register_user("bob", b"key2")
        
        message_id = db.queue_message("alice", "bob", b"encrypted_message")
        
        assert message_id is not None
        assert len(message_id) > 0  # UUID format
    
    def test_get_queued_messages(self, db):
        """Test retrieving queued messages"""
        db.register_user("alice", b"key1")
        db.register_user("bob", b"key2")
        
        # Queue some messages
        msg_id_1 = db.queue_message("alice", "bob", b"message_1")
        msg_id_2 = db.queue_message("alice", "bob", b"message_2")
        
        # Get queued messages
        messages = db.get_queued_messages("bob")
        
        assert len(messages) == 2
        assert messages[0]['sender'] == "alice"
        assert messages[0]['message_blob'] == b"message_1"
    
    def test_mark_message_delivered(self, db):
        """Test marking message as delivered"""
        db.register_user("alice", b"key1")
        db.register_user("bob", b"key2")
        
        message_id = db.queue_message("alice", "bob", b"message")
        
        # Mark delivered
        db.mark_message_delivered(message_id)
        
        # Should no longer be in queue
        messages = db.get_queued_messages("bob")
        assert len(messages) == 0
    
    def test_cleanup_expired_messages(self, db):
        """Test cleanup of expired messages"""
        db.register_user("alice", b"key1")
        db.register_user("bob", b"key2")
        
        # Queue a message
        message_id = db.queue_message("alice", "bob", b"message")
        
        # Manually set expiry to past
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE message_queue 
                SET expires_at = ?
                WHERE message_id = ?
            """, (int(time.time()) - 3600, message_id))
        
        # Run cleanup
        deleted = db.cleanup_expired_messages()
        assert deleted == 1
        
        # Verify message gone
        messages = db.get_queued_messages("bob")
        assert len(messages) == 0


class TestDatabaseStats:
    """Test database statistics and maintenance"""
    
    def test_get_stats(self, db):
        """Test getting database statistics"""
        # Add some data
        db.register_user("alice", b"key1")
        db.register_user("bob", b"key2")
        db.update_user_status("alice", "online")
        
        db.upload_one_time_prekeys("alice", [(b"opk", i) for i in range(5)])
        db.queue_message("alice", "bob", b"message")
        
        # Get stats
        stats = db.get_stats()
        
        assert stats['users'] == 2
        assert stats['online_users'] == 1
        assert stats['one_time_prekeys'] == 5
        assert stats['queued_messages'] == 1
    
    def test_vacuum(self, db):
        """Test database vacuum operation"""
        # Just verify it doesn't crash
        db.vacuum()


class TestEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_upload_duplicate_opk(self, db):
        """Test uploading duplicate one-time prekey IDs"""
        db.register_user("alice", b"key")
        
        # Upload same key_id twice
        db.upload_one_time_prekeys("alice", [(b"opk_1", 1)])
        db.upload_one_time_prekeys("alice", [(b"opk_2", 1)])  # Duplicate ID
        
        # Should only have one (first one wins)
        assert db.count_one_time_prekeys("alice") == 1
    
    def test_fetch_bundle_without_signed_prekey(self, db):
        """Test fetching bundle when user has no signed prekey"""
        db.register_user("alice", b"key")
        # Don't upload signed prekey
        
        bundle = db.fetch_prekey_bundle("alice")
        assert bundle is None
    
    def test_queue_message_for_nonexistent_user(self, db):
        """Test queuing message for user that doesn't exist"""
        db.register_user("alice", b"key")
        
        # This should work (queue is checked at send time)
        # Database doesn't enforce recipient existence at queue time
        message_id = db.queue_message("alice", "nobody", b"message")
        assert message_id is not None
