"""
Tests for encrypted storage layer
"""

import pytest
import os
import tempfile
from datetime import datetime

from src.client.storage import SecureStorage, Contact, StorageError
from src.x3dh.prekeys import SignedPrekeyPair
from src.ratchet.state import RatchetState
from src.crypto.primitives import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    ed25519_sign,
    generate_random_bytes,
)


@pytest.fixture
def temp_db():
    """Create temporary database file"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)
    # Clean up WAL files
    for suffix in ['-wal', '-shm']:
        wal_file = path + suffix
        if os.path.exists(wal_file):
            os.unlink(wal_file)


@pytest.fixture
def storage(temp_db):
    """Create storage instance"""
    storage = SecureStorage(temp_db, "test_password_123456")
    yield storage
    storage.close()


@pytest.fixture
def identity_keys():
    """Generate identity key pair"""
    private, public = generate_ed25519_keypair()
    return private, public


@pytest.fixture
def signed_prekey(identity_keys):
    """Generate signed prekey"""
    identity_private, _ = identity_keys
    prekey_private, prekey_public = generate_x25519_keypair()
    signature = ed25519_sign(identity_private, prekey_public)
    return SignedPrekeyPair(
        key_id=1,
        public_key=prekey_public,
        private_key=prekey_private,
        signature=signature
    )


class TestStorageInitialization:
    """Test storage initialization and setup"""
    
    def test_create_new_database(self, temp_db):
        """Test creating new database"""
        storage = SecureStorage(temp_db, "test_password")
        assert os.path.exists(temp_db)
        storage.close()
    
    def test_open_existing_database(self, temp_db):
        """Test opening existing database"""
        # Create first storage
        storage1 = SecureStorage(temp_db, "test_password")
        storage1.close()
        
        # Open again with same password
        storage2 = SecureStorage(temp_db, "test_password")
        storage2.close()
    
    def test_wrong_password_fails(self, temp_db, identity_keys, signed_prekey):
        """Test that wrong password cannot decrypt data"""
        # Create storage with data
        storage1 = SecureStorage(temp_db, "correct_password")
        identity_private, identity_public = identity_keys
        storage1.initialize_identity("alice", identity_private, identity_public, signed_prekey, 12345)
        storage1.close()
        
        # Try to open with wrong password
        storage2 = SecureStorage(temp_db, "wrong_password")
        
        # Should fail to decrypt
        with pytest.raises(StorageError, match="Decryption failed"):
            storage2.get_identity()
        
        storage2.close()
    
    def test_auto_create_directory(self, temp_db):
        """Test automatic directory creation"""
        nested_path = os.path.join(os.path.dirname(temp_db), "nested", "dir", "test.db")
        storage = SecureStorage(nested_path, "test_password")
        assert os.path.exists(nested_path)
        storage.close()
        
        # Cleanup
        os.unlink(nested_path)
        os.rmdir(os.path.dirname(nested_path))


class TestIdentityManagement:
    """Test identity storage and retrieval"""
    
    def test_initialize_identity(self, storage, identity_keys, signed_prekey):
        """Test initializing user identity"""
        identity_private, identity_public = identity_keys
        
        storage.initialize_identity(
            "alice",
            identity_private,
            identity_public,
            signed_prekey,
            12345
        )
        
        # Verify stored
        result = storage.get_identity()
        assert result is not None
        
        user_id, priv_key, pub_key, prekey, reg_id = result
        assert user_id == "alice"
        assert priv_key == identity_private
        assert pub_key == identity_public
        assert prekey.key_id == signed_prekey.key_id
        assert prekey.public_key == signed_prekey.public_key
        assert prekey.signature == signed_prekey.signature
        assert reg_id == 12345
    
    def test_initialize_identity_twice_fails(self, storage, identity_keys, signed_prekey):
        """Test that initializing identity twice fails"""
        identity_private, identity_public = identity_keys
        
        storage.initialize_identity("alice", identity_private, identity_public, signed_prekey, 12345)
        
        # Try again
        with pytest.raises(StorageError, match="already exists"):
            storage.initialize_identity("alice", identity_private, identity_public, signed_prekey, 12345)
    
    def test_get_identity_when_empty(self, storage):
        """Test getting identity when none exists"""
        result = storage.get_identity()
        assert result is None
    
    def test_identity_private_keys_encrypted(self, temp_db, identity_keys, signed_prekey):
        """Test that private keys are encrypted at rest"""
        import sqlite3
        
        identity_private, identity_public = identity_keys
        
        # Store identity
        storage = SecureStorage(temp_db, "test_password")
        storage.initialize_identity("alice", identity_private, identity_public, signed_prekey, 12345)
        storage.close()
        
        # Open database directly and check keys are encrypted
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT identity_private_key, signed_prekey_private FROM identity")
        row = cursor.fetchone()
        conn.close()
        
        # Encrypted keys should not match plaintext
        assert row[0] != identity_private
        assert row[1] != signed_prekey.private_key
        
        # Should be longer due to encryption overhead (nonce + ciphertext + tag)
        assert len(row[0]) > len(identity_private)
        assert len(row[1]) > len(signed_prekey.private_key)


class TestContactManagement:
    """Test contact storage and retrieval"""
    
    def test_add_contact(self, storage):
        """Test adding a contact"""
        _, identity_key = generate_ed25519_keypair()
        
        storage.add_contact("bob", identity_key, verified=False)
        
        contact = storage.get_contact("bob")
        assert contact is not None
        assert contact.contact_id == "bob"
        assert contact.identity_key == identity_key
        assert contact.verified is False
        assert contact.safety_number is None
        assert contact.first_seen is not None
        assert contact.last_updated is not None
    
    def test_update_contact(self, storage):
        """Test updating existing contact"""
        _, identity_key = generate_ed25519_keypair()
        
        # Add contact
        storage.add_contact("bob", identity_key, verified=False)
        
        # Update with verification
        storage.add_contact("bob", identity_key, verified=True, safety_number="123456")
        
        contact = storage.get_contact("bob")
        assert contact.verified is True
        assert contact.safety_number == "123456"
    
    def test_get_nonexistent_contact(self, storage):
        """Test getting contact that doesn't exist"""
        contact = storage.get_contact("nobody")
        assert contact is None
    
    def test_list_contacts(self, storage):
        """Test listing all contacts"""
        # Add multiple contacts
        for name in ["alice", "bob", "charlie"]:
            _, identity_key = generate_ed25519_keypair()
            storage.add_contact(name, identity_key)
        
        contacts = storage.list_contacts()
        assert len(contacts) == 3
        contact_ids = {c.contact_id for c in contacts}
        assert contact_ids == {"alice", "bob", "charlie"}
    
    def test_list_contacts_empty(self, storage):
        """Test listing contacts when none exist"""
        contacts = storage.list_contacts()
        assert len(contacts) == 0
    
    def test_verify_contact(self, storage):
        """Test verifying a contact"""
        _, identity_key = generate_ed25519_keypair()
        storage.add_contact("bob", identity_key, verified=False)
        
        # Verify
        storage.verify_contact("bob", "SAFETY123456")
        
        contact = storage.get_contact("bob")
        assert contact.verified is True
        assert contact.safety_number == "SAFETY123456"
    
    def test_verify_nonexistent_contact_fails(self, storage):
        """Test verifying contact that doesn't exist"""
        with pytest.raises(StorageError, match="not found"):
            storage.verify_contact("nobody", "123456")
    
    def test_delete_contact(self, storage):
        """Test deleting a contact"""
        _, identity_key = generate_ed25519_keypair()
        storage.add_contact("bob", identity_key)
        
        storage.delete_contact("bob")
        
        assert storage.get_contact("bob") is None


class TestSessionManagement:
    """Test session storage and retrieval"""
    
    def test_save_and_load_session(self, storage):
        """Test saving and loading session state"""
        # Create session state
        root_key = generate_random_bytes(32)
        chain_key_send = generate_random_bytes(32)
        chain_key_recv = generate_random_bytes(32)
        dh_send_private, dh_send_public = generate_x25519_keypair()
        _, dh_recv_public = generate_x25519_keypair()
        
        state = RatchetState(
            root_key=root_key,
            chain_key_send=chain_key_send,
            chain_key_recv=chain_key_recv,
            dh_private=dh_send_private,
            dh_public=dh_send_public,
            dh_remote=dh_recv_public,
            send_msg_num=5,
            recv_msg_num=3,
            prev_chain_length=2
        )
        
        # Save session
        storage.save_session("bob", state)
        
        # Load session
        loaded_state = storage.load_session("bob")
        assert loaded_state is not None
        assert loaded_state.root_key == state.root_key
        assert loaded_state.chain_key_send == state.chain_key_send
        assert loaded_state.chain_key_recv == state.chain_key_recv
        assert loaded_state.dh_private == state.dh_private
        assert loaded_state.dh_public == state.dh_public
        assert loaded_state.dh_remote == state.dh_remote
        assert loaded_state.send_msg_num == state.send_msg_num
        assert loaded_state.recv_msg_num == state.recv_msg_num
        assert loaded_state.prev_chain_length == state.prev_chain_length
    
    def test_load_nonexistent_session(self, storage):
        """Test loading session that doesn't exist"""
        state = storage.load_session("nobody")
        assert state is None
    
    def test_update_session(self, storage):
        """Test updating existing session"""
        # Create and save initial state
        root_key = generate_random_bytes(32)
        chain_key = generate_random_bytes(32)
        dh_private, dh_public = generate_x25519_keypair()
        
        state1 = RatchetState(
            root_key=root_key,
            chain_key_send=chain_key,
            chain_key_recv=chain_key,
            dh_private=dh_private,
            dh_public=dh_public,
            dh_remote=dh_public,
            send_msg_num=1,
            recv_msg_num=0,
            prev_chain_length=0
        )
        storage.save_session("bob", state1)
        
        # Update with new counters
        state2 = RatchetState(
            root_key=root_key,
            chain_key_send=chain_key,
            chain_key_recv=chain_key,
            dh_private=dh_private,
            dh_public=dh_public,
            dh_remote=dh_public,
            send_msg_num=10,
            recv_msg_num=5,
            prev_chain_length=3
        )
        storage.save_session("bob", state2)
        
        # Load and verify
        loaded = storage.load_session("bob")
        assert loaded.send_msg_num == 10
        assert loaded.recv_msg_num == 5
        assert loaded.prev_chain_length == 3
    
    def test_session_with_skipped_keys(self, storage):
        """Test session with skipped message keys"""
        import time
        root_key = generate_random_bytes(32)
        chain_key = generate_random_bytes(32)
        dh_private, dh_public = generate_x25519_keypair()
        
        state = RatchetState(
            root_key=root_key,
            chain_key_send=chain_key,
            chain_key_recv=chain_key,
            dh_private=dh_private,
            dh_public=dh_public,
            dh_remote=dh_public,
            send_msg_num=0,
            recv_msg_num=0,
            prev_chain_length=0
        )
        
        # Add skipped keys
        mk1 = generate_random_bytes(32)
        mk2 = generate_random_bytes(32)
        timestamp = time.time()
        state.skipped_keys[(dh_public, 5)] = (mk1, timestamp)
        state.skipped_keys[(dh_public, 7)] = (mk2, timestamp)
        
        # Save and load
        storage.save_session("bob", state)
        loaded = storage.load_session("bob")
        
        # Verify skipped keys preserved
        assert len(loaded.skipped_keys) == 2
        assert loaded.skipped_keys.get((dh_public, 5))[0] == mk1
        assert loaded.skipped_keys.get((dh_public, 7))[0] == mk2
    
    def test_delete_session(self, storage):
        """Test deleting a session"""
        # Create and save session
        root_key = generate_random_bytes(32)
        chain_key = generate_random_bytes(32)
        dh_private, dh_public = generate_x25519_keypair()
        
        state = RatchetState(
            root_key=root_key,
            chain_key_send=chain_key,
            chain_key_recv=chain_key,
            dh_private=dh_private,
            dh_public=dh_public,
            dh_remote=dh_public,
            send_msg_num=0,
            recv_msg_num=0,
            prev_chain_length=0
        )
        storage.save_session("bob", state)
        
        # Delete
        storage.delete_session("bob")
        
        # Verify gone
        assert storage.load_session("bob") is None
    
    def test_session_encrypted_at_rest(self, temp_db):
        """Test that session state is encrypted at rest"""
        import sqlite3
        
        # Create session
        root_key = generate_random_bytes(32)
        chain_key = generate_random_bytes(32)
        dh_private, dh_public = generate_x25519_keypair()
        
        state = RatchetState(
            root_key=root_key,
            chain_key_send=chain_key,
            chain_key_recv=chain_key,
            dh_private=dh_private,
            dh_public=dh_public,
            dh_remote=dh_public,
            send_msg_num=0,
            recv_msg_num=0,
            prev_chain_length=0
        )
        
        # Save with storage
        storage = SecureStorage(temp_db, "test_password")
        storage.save_session("bob", state)
        storage.close()
        
        # Check database directly
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT session_state FROM sessions WHERE contact_id = ?", ("bob",))
        row = cursor.fetchone()
        conn.close()
        
        encrypted_state = row[0]
        
        # Should not contain plaintext keys
        assert root_key not in encrypted_state
        assert chain_key not in encrypted_state
        assert dh_private not in encrypted_state


class TestContextManager:
    """Test context manager interface"""
    
    def test_context_manager(self, temp_db):
        """Test using storage as context manager"""
        with SecureStorage(temp_db, "test_password") as storage:
            # Should be usable
            result = storage.get_identity()
            assert result is None
        
        # Should be closed after
        assert storage._conn is None
        assert storage._master_key is None
    
    def test_context_manager_with_exception(self, temp_db):
        """Test context manager cleans up on exception"""
        try:
            with SecureStorage(temp_db, "test_password") as storage:
                raise ValueError("test error")
        except ValueError:
            pass
        
        # Should still be closed
        assert storage._conn is None


class TestSecurityFeatures:
    """Test security-related features"""
    
    def test_master_key_cleared_on_close(self, storage):
        """Test that master key is cleared from memory on close"""
        # Master key should exist
        assert storage._master_key is not None
        
        storage.close()
        
        # Should be cleared
        assert storage._master_key is None
    
    def test_password_cleared_on_close(self, storage):
        """Test that password is cleared from memory on close"""
        # Password should exist
        assert storage._password is not None
        
        storage.close()
        
        # Should be cleared
        assert storage._password is None
    
    def test_database_file_permissions(self, temp_db):
        """Test that database file has restricted permissions"""
        storage = SecureStorage(temp_db, "test_password")
        storage.close()
        
        # Check file permissions (on Unix systems)
        if os.name != 'nt':  # Skip on Windows
            stat_info = os.stat(temp_db)
            mode = stat_info.st_mode & 0o777
            # Should not be world-readable
            assert mode & 0o004 == 0
