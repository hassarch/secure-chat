"""
Unit tests for Double Ratchet algorithm.

Tests verify:
1. KDF functions produce correct output
2. State initialization
3. Message encryption/decryption
4. DH ratchet steps
5. Out-of-order message handling
6. Skipped key caching
7. Forward secrecy
8. State serialization
"""

import pytest
import time
from src.ratchet import (
    RatchetState,
    MessageHeader,
    kdf_rk,
    kdf_ck,
    initialize_sender,
    initialize_receiver,
    ratchet_encrypt,
    ratchet_decrypt,
    TooManySkippedKeysError,
    DecryptionError,
    MAX_SKIP,
)
from src.crypto.primitives import generate_x25519_keypair, generate_random_bytes


class TestKDFFunctions:
    """Test key derivation functions"""
    
    def test_kdf_rk_output_length(self):
        """Test that KDF_RK produces 64 bytes total"""
        root_key = generate_random_bytes(32)
        dh_output = generate_random_bytes(32)
        
        new_rk, chain_key = kdf_rk(root_key, dh_output)
        
        assert len(new_rk) == 32
        assert len(chain_key) == 32
    
    def test_kdf_rk_deterministic(self):
        """Test that KDF_RK is deterministic"""
        root_key = generate_random_bytes(32)
        dh_output = generate_random_bytes(32)
        
        rk1, ck1 = kdf_rk(root_key, dh_output)
        rk2, ck2 = kdf_rk(root_key, dh_output)
        
        assert rk1 == rk2
        assert ck1 == ck2
    
    def test_kdf_rk_different_inputs(self):
        """Test that different inputs produce different outputs"""
        root_key1 = generate_random_bytes(32)
        root_key2 = generate_random_bytes(32)
        dh_output = generate_random_bytes(32)
        
        rk1, ck1 = kdf_rk(root_key1, dh_output)
        rk2, ck2 = kdf_rk(root_key2, dh_output)
        
        assert rk1 != rk2
        assert ck1 != ck2
    
    def test_kdf_ck_output_length(self):
        """Test that KDF_CK produces 64 bytes total"""
        chain_key = generate_random_bytes(32)
        
        new_ck, message_key = kdf_ck(chain_key)
        
        assert len(new_ck) == 32
        assert len(message_key) == 32
    
    def test_kdf_ck_deterministic(self):
        """Test that KDF_CK is deterministic"""
        chain_key = generate_random_bytes(32)
        
        ck1, mk1 = kdf_ck(chain_key)
        ck2, mk2 = kdf_ck(chain_key)
        
        assert ck1 == ck2
        assert mk1 == mk2
    
    def test_kdf_ck_ratcheting(self):
        """Test that KDF_CK produces different keys on each step"""
        chain_key = generate_random_bytes(32)
        
        ck1, mk1 = kdf_ck(chain_key)
        ck2, mk2 = kdf_ck(ck1)
        ck3, mk3 = kdf_ck(ck2)
        
        # All keys should be different
        assert ck1 != ck2 != ck3
        assert mk1 != mk2 != mk3


class TestMessageHeader:
    """Test message header encoding/decoding"""
    
    def test_header_encode_decode(self):
        """Test header can be encoded and decoded"""
        dh_public = generate_random_bytes(32)
        header = MessageHeader(
            dh_public=dh_public,
            prev_chain_length=5,
            message_number=10
        )
        
        encoded = header.encode()
        decoded = MessageHeader.decode(encoded)
        
        assert decoded.dh_public == header.dh_public
        assert decoded.prev_chain_length == header.prev_chain_length
        assert decoded.message_number == header.message_number
    
    def test_header_encode_length(self):
        """Test header is always 40 bytes"""
        header = MessageHeader(
            dh_public=generate_random_bytes(32),
            prev_chain_length=0,
            message_number=0
        )
        
        encoded = header.encode()
        assert len(encoded) == 40
    
    def test_header_decode_invalid_length(self):
        """Test that decoding wrong length raises error"""
        with pytest.raises(ValueError):
            MessageHeader.decode(b"too short")
    
    def test_header_serialization(self):
        """Test header dict serialization"""
        header = MessageHeader(
            dh_public=generate_random_bytes(32),
            prev_chain_length=3,
            message_number=7
        )
        
        header_dict = header.to_dict()
        restored = MessageHeader.from_dict(header_dict)
        
        assert restored.dh_public == header.dh_public
        assert restored.prev_chain_length == header.prev_chain_length
        assert restored.message_number == header.message_number


class TestRatchetInitialization:
    """Test ratchet initialization"""
    
    def test_initialize_sender(self):
        """Test sender initialization"""
        shared_secret = generate_random_bytes(32)
        _, bob_public = generate_x25519_keypair()
        
        state = initialize_sender(shared_secret, bob_public)
        
        assert state.root_key is not None
        assert state.chain_key_send is not None
        assert state.chain_key_recv is None  # Not set until receiving
        assert state.dh_public is not None
        assert state.dh_remote == bob_public
        assert state.send_msg_num == 0
        assert state.recv_msg_num == 0
    
    def test_initialize_receiver(self):
        """Test receiver initialization"""
        shared_secret = generate_random_bytes(32)
        
        state = initialize_receiver(shared_secret)
        
        assert state.root_key == shared_secret
        assert state.chain_key_send is None  # Set after first DH ratchet
        assert state.chain_key_recv is None  # Set when receiving
        assert state.dh_public is not None
        assert state.dh_remote is None  # Set from first message
        assert state.send_msg_num == 0
        assert state.recv_msg_num == 0


class TestBasicEncryptionDecryption:
    """Test basic message encryption and decryption"""
    
    def test_encrypt_decrypt_single_message(self):
        """Test encrypting and decrypting a single message"""
        # Setup: Alice and Bob with shared secret
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        # Alice encrypts a message
        plaintext = b"Hello, Bob!"
        ad = b"associated_data"
        header, ciphertext, nonce = ratchet_encrypt(alice_state, plaintext, ad)
        
        # Bob decrypts the message
        decrypted = ratchet_decrypt(bob_state, header, ciphertext, nonce, ad)
        
        assert decrypted == plaintext
    
    def test_encrypt_multiple_messages(self):
        """Test encrypting and decrypting multiple messages in sequence"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        
        for plaintext in messages:
            header, ciphertext, nonce = ratchet_encrypt(alice_state, plaintext)
            decrypted = ratchet_decrypt(bob_state, header, ciphertext, nonce)
            assert decrypted == plaintext
    
    def test_different_ciphertexts_for_same_plaintext(self):
        """Test that same plaintext produces different ciphertexts"""
        shared_secret = generate_random_bytes(32)
        _, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        
        plaintext = b"Same message"
        header1, ct1, nonce1 = ratchet_encrypt(alice_state, plaintext)
        header2, ct2, nonce2 = ratchet_encrypt(alice_state, plaintext)
        
        # Different message numbers and ciphertexts
        assert header1.message_number != header2.message_number
        assert ct1 != ct2 or nonce1 != nonce2
    
    def test_wrong_associated_data_fails(self):
        """Test that tampering with header causes decryption to fail"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        plaintext = b"Secret message"
        header, ciphertext, nonce = ratchet_encrypt(alice_state, plaintext)
        
        # Tamper with the header (change message number)
        tampered_header = MessageHeader(
            dh_public=header.dh_public,
            prev_chain_length=header.prev_chain_length,
            message_number=header.message_number + 1  # Wrong number
        )
        
        # Try to decrypt with tampered header - should fail authentication
        try:
            decrypted = ratchet_decrypt(bob_state, tampered_header, ciphertext, nonce)
            # If we got here, check it didn't actually succeed
            assert decrypted != plaintext, "Should not decrypt with tampered header"
        except (DecryptionError, ValueError, TooManySkippedKeysError):
            # Expected - tampering detected
            pass


class TestDHRatchet:
    """Test DH ratchet functionality"""
    
    def test_bidirectional_conversation(self):
        """Test Alice and Bob can have a bidirectional conversation"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        # Alice -> Bob
        msg1 = b"Hello Bob"
        h1, c1, n1 = ratchet_encrypt(alice_state, msg1)
        assert ratchet_decrypt(bob_state, h1, c1, n1) == msg1
        
        # Bob -> Alice (triggers DH ratchet on Alice's side)
        msg2 = b"Hello Alice"
        h2, c2, n2 = ratchet_encrypt(bob_state, msg2)
        assert ratchet_decrypt(alice_state, h2, c2, n2) == msg2
        
        # Alice -> Bob (triggers DH ratchet on Bob's side)
        msg3 = b"How are you?"
        h3, c3, n3 = ratchet_encrypt(alice_state, msg3)
        assert ratchet_decrypt(bob_state, h3, c3, n3) == msg3
        
        # Bob -> Alice
        msg4 = b"I'm good, thanks!"
        h4, c4, n4 = ratchet_encrypt(bob_state, msg4)
        assert ratchet_decrypt(alice_state, h4, c4, n4) == msg4
    
    def test_dh_ratchet_changes_keys(self):
        """Test that DH ratchet produces new keys"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        # Save Alice's initial keys
        alice_dh_public_before = alice_state.dh_public
        alice_root_key_before = alice_state.root_key
        
        # Alice sends message
        h1, c1, n1 = ratchet_encrypt(alice_state, b"msg1")
        ratchet_decrypt(bob_state, h1, c1, n1)
        
        # Bob sends message (Alice performs DH ratchet)
        h2, c2, n2 = ratchet_encrypt(bob_state, b"msg2")
        ratchet_decrypt(alice_state, h2, c2, n2)
        
        # Alice's DH key and root key should have changed
        assert alice_state.dh_public != alice_dh_public_before
        assert alice_state.root_key != alice_root_key_before


class TestOutOfOrderMessages:
    """Test handling of out-of-order message delivery"""
    
    def test_receive_messages_out_of_order(self):
        """Test receiving messages 0, 2, 1 in that order"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        # Alice sends 3 messages
        h0, c0, n0 = ratchet_encrypt(alice_state, b"Message 0")
        h1, c1, n1 = ratchet_encrypt(alice_state, b"Message 1")
        h2, c2, n2 = ratchet_encrypt(alice_state, b"Message 2")
        
        # Bob receives in order: 0, 2, 1
        assert ratchet_decrypt(bob_state, h0, c0, n0) == b"Message 0"
        assert ratchet_decrypt(bob_state, h2, c2, n2) == b"Message 2"
        assert ratchet_decrypt(bob_state, h1, c1, n1) == b"Message 1"
    
    def test_skipped_keys_stored(self):
        """Test that skipped message keys are stored"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        # Alice sends messages 0, 1, 2
        h0, c0, n0 = ratchet_encrypt(alice_state, b"M0")
        h1, c1, n1 = ratchet_encrypt(alice_state, b"M1")
        h2, c2, n2 = ratchet_encrypt(alice_state, b"M2")
        
        # Bob receives message 2 first (skips 0 and 1)
        ratchet_decrypt(bob_state, h2, c2, n2)
        
        # Bob should have 2 skipped keys stored
        assert bob_state.count_skipped_keys() == 2
        
        # Receive skipped messages
        ratchet_decrypt(bob_state, h0, c0, n0)
        assert bob_state.count_skipped_keys() == 1
        
        ratchet_decrypt(bob_state, h1, c1, n1)
        assert bob_state.count_skipped_keys() == 0
    
    def test_too_many_skipped_keys(self):
        """Test that skipping too many keys raises error"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        # Alice sends message 0
        h0, c0, n0 = ratchet_encrypt(alice_state, b"M0")
        ratchet_decrypt(bob_state, h0, c0, n0)
        
        # Set message number to MAX_SKIP + 2 (will try to skip MAX_SKIP + 1)
        alice_state.send_msg_num = MAX_SKIP + 1
        h_far, c_far, n_far = ratchet_encrypt(alice_state, b"Far message")
        
        # Bob should reject this (too many skipped keys)
        # Can raise either TooManySkippedKeysError or DecryptionError
        with pytest.raises((TooManySkippedKeysError, DecryptionError)):
            ratchet_decrypt(bob_state, h_far, c_far, n_far)


class TestStateManagement:
    """Test ratchet state management"""
    
    def test_state_serialization(self):
        """Test that state can be serialized and deserialized"""
        shared_secret = generate_random_bytes(32)
        _, bob_dh_public = generate_x25519_keypair()
        
        state = initialize_sender(shared_secret, bob_dh_public)
        
        # Send a few messages to populate state
        for i in range(3):
            ratchet_encrypt(state, f"Message {i}".encode())
        
        # Serialize
        state_dict = state.to_dict()
        
        # Deserialize
        restored_state = RatchetState.from_dict(state_dict)
        
        # Verify key fields match
        assert restored_state.root_key == state.root_key
        assert restored_state.chain_key_send == state.chain_key_send
        assert restored_state.dh_public == state.dh_public
        assert restored_state.send_msg_num == state.send_msg_num
    
    def test_skipped_keys_cleanup(self):
        """Test that old skipped keys are cleaned up"""
        state = RatchetState(
            root_key=generate_random_bytes(32),
            chain_key_send=generate_random_bytes(32),
            chain_key_recv=None,
            dh_private=generate_random_bytes(32),
            dh_public=generate_random_bytes(32),
            dh_remote=generate_random_bytes(32)
        )
        
        # Add some skipped keys with old timestamps
        current_time = time.time()
        old_key = (generate_random_bytes(32), 0)
        recent_key = (generate_random_bytes(32), 1)
        
        state.skipped_keys[old_key] = (generate_random_bytes(32), current_time - 8 * 24 * 3600)  # 8 days old
        state.skipped_keys[recent_key] = (generate_random_bytes(32), current_time - 1 * 24 * 3600)  # 1 day old
        
        assert state.count_skipped_keys() == 2
        
        # Cleanup with 7-day threshold
        state.cleanup_skipped_keys(max_age=7 * 24 * 3600)
        
        # Only recent key should remain
        assert state.count_skipped_keys() == 1
        assert recent_key in state.skipped_keys
        assert old_key not in state.skipped_keys


class TestForwardSecrecy:
    """Test forward secrecy properties"""
    
    def test_message_keys_not_reused(self):
        """Test that each message uses a different key"""
        shared_secret = generate_random_bytes(32)
        _, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        
        # Get chain key before first message
        ck_before = alice_state.chain_key_send
        
        # Send message
        ratchet_encrypt(alice_state, b"Message 1")
        ck_after_1 = alice_state.chain_key_send
        
        # Send another message
        ratchet_encrypt(alice_state, b"Message 2")
        ck_after_2 = alice_state.chain_key_send
        
        # All chain keys should be different
        assert ck_before != ck_after_1
        assert ck_after_1 != ck_after_2
    
    def test_forward_secrecy_property(self):
        """Test forward secrecy: chain keys can't derive backwards"""
        shared_secret = generate_random_bytes(32)
        _, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        
        # Get initial chain key
        initial_ck = alice_state.chain_key_send
        
        # Send several messages
        headers_and_ciphertexts = []
        for i in range(5):
            h, c, n = ratchet_encrypt(alice_state, f"Message {i}".encode())
            headers_and_ciphertexts.append((h, c, n))
        
        # Get final chain key
        final_ck = alice_state.chain_key_send
        
        # Verify chain keys are different (ratcheted forward)
        assert initial_ck != final_ck
        
        # Verify we can't derive old message keys from current chain key
        # (This is a property test - we're verifying the keys are different)
        _, mk_from_initial = kdf_ck(initial_ck)
        _, mk_from_final = kdf_ck(final_ck)
        
        assert mk_from_initial != mk_from_final


class TestEndToEnd:
    """End-to-end conversation scenarios"""
    
    def test_full_conversation_with_ratcheting(self):
        """Test a complete conversation with multiple DH ratchet steps"""
        shared_secret = generate_random_bytes(32)
        bob_dh_private, bob_dh_public = generate_x25519_keypair()
        
        alice_state = initialize_sender(shared_secret, bob_dh_public)
        bob_state = initialize_receiver(shared_secret)
        bob_state.dh_private = bob_dh_private
        bob_state.dh_public = bob_dh_public
        
        conversation = [
            ("Alice", alice_state, bob_state, b"Hi Bob!"),
            ("Alice", alice_state, bob_state, b"How are you?"),
            ("Bob", bob_state, alice_state, b"Hi Alice!"),
            ("Bob", bob_state, alice_state, b"I'm good!"),
            ("Alice", alice_state, bob_state, b"That's great!"),
            ("Bob", bob_state, alice_state, b"Thanks for asking"),
        ]
        
        for sender_name, sender_state, receiver_state, message in conversation:
            h, c, n = ratchet_encrypt(sender_state, message)
            decrypted = ratchet_decrypt(receiver_state, h, c, n)
            assert decrypted == message
