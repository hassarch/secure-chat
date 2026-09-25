"""
Unit tests for X3DH key agreement protocol.

Tests verify:
1. Prekey generation and serialization
2. Signature verification
3. X3DH handshake (with and without one-time prekey)
4. Shared secret matching between parties
5. Error handling (invalid signatures, missing keys)
"""

import pytest
from src.x3dh import (
    generate_identity_keypair,
    generate_signed_prekey,
    generate_one_time_prekeys,
    create_prekey_bundle,
    PrekeyStore,
    PrekeyBundle,
    X3DHInitiator,
    X3DHReceiver,
    verify_shared_secrets_match,
)
from src.crypto.primitives import ed25519_sign, generate_x25519_keypair


class TestPrekeyGeneration:
    """Test prekey generation functions"""
    
    def test_generate_identity_keypair(self):
        """Test identity key generation"""
        keypair = generate_identity_keypair()
        
        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32
        assert keypair.private_key != keypair.public_key
    
    def test_generate_signed_prekey(self):
        """Test signed prekey generation"""
        identity = generate_identity_keypair()
        signed_prekey = generate_signed_prekey(identity, key_id=1)
        
        assert len(signed_prekey.private_key) == 32
        assert len(signed_prekey.public_key) == 32
        assert len(signed_prekey.signature) == 64
        assert signed_prekey.key_id == 1
    
    def test_generate_one_time_prekeys(self):
        """Test one-time prekey generation"""
        prekeys = generate_one_time_prekeys(count=10, start_id=1)
        
        assert len(prekeys) == 10
        for i, prekey in enumerate(prekeys):
            assert len(prekey.private_key) == 32
            assert len(prekey.public_key) == 32
            assert prekey.key_id == 1 + i
    
    def test_one_time_prekeys_unique(self):
        """Test that one-time prekeys are all different"""
        prekeys = generate_one_time_prekeys(count=5)
        
        public_keys = [pk.public_key for pk in prekeys]
        assert len(set(public_keys)) == 5  # All unique


class TestPrekeyBundle:
    """Test prekey bundle creation and verification"""
    
    def test_create_prekey_bundle_with_opk(self):
        """Test creating bundle with one-time prekey"""
        identity = generate_identity_keypair()
        signed_prekey = generate_signed_prekey(identity, key_id=1)
        one_time_prekey = generate_one_time_prekeys(count=1, start_id=1)[0]
        
        bundle = create_prekey_bundle(
            identity.public_key,
            signed_prekey,
            one_time_prekey
        )
        
        assert bundle.identity_key == identity.public_key
        assert bundle.signed_prekey == signed_prekey.public_key
        assert bundle.signed_prekey_signature == signed_prekey.signature
        assert bundle.one_time_prekey == one_time_prekey.public_key
        assert bundle.one_time_prekey_id == 1
    
    def test_create_prekey_bundle_without_opk(self):
        """Test creating bundle without one-time prekey"""
        identity = generate_identity_keypair()
        signed_prekey = generate_signed_prekey(identity, key_id=1)
        
        bundle = create_prekey_bundle(
            identity.public_key,
            signed_prekey,
            one_time_prekey=None
        )
        
        assert bundle.one_time_prekey is None
        assert bundle.one_time_prekey_id is None
    
    def test_verify_valid_signature(self):
        """Test signature verification succeeds for valid bundle"""
        identity = generate_identity_keypair()
        signed_prekey = generate_signed_prekey(identity, key_id=1)
        bundle = create_prekey_bundle(identity.public_key, signed_prekey)
        
        assert bundle.verify_signature() is True
    
    def test_verify_invalid_signature(self):
        """Test signature verification fails for tampered bundle"""
        identity = generate_identity_keypair()
        signed_prekey = generate_signed_prekey(identity, key_id=1)
        
        # Create bundle with different identity key (signature won't match)
        different_identity = generate_identity_keypair()
        bundle = create_prekey_bundle(
            different_identity.public_key,  # Wrong identity key
            signed_prekey
        )
        
        assert bundle.verify_signature() is False
    
    def test_bundle_serialization(self):
        """Test bundle can be serialized and deserialized"""
        identity = generate_identity_keypair()
        signed_prekey = generate_signed_prekey(identity, key_id=1)
        one_time_prekey = generate_one_time_prekeys(count=1, start_id=1)[0]
        
        bundle = create_prekey_bundle(
            identity.public_key,
            signed_prekey,
            one_time_prekey
        )
        
        # Serialize
        bundle_dict = bundle.to_dict()
        
        # Deserialize
        restored_bundle = PrekeyBundle.from_dict(bundle_dict)
        
        assert restored_bundle.identity_key == bundle.identity_key
        assert restored_bundle.signed_prekey == bundle.signed_prekey
        assert restored_bundle.signed_prekey_signature == bundle.signed_prekey_signature
        assert restored_bundle.one_time_prekey == bundle.one_time_prekey


class TestPrekeyStore:
    """Test prekey store management"""
    
    def test_prekey_store_initialization(self):
        """Test prekey store can be created"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        
        assert store.identity_keypair == identity
        assert store.signed_prekey is None
        assert len(store.one_time_prekeys) == 0
    
    def test_generate_and_store_signed_prekey(self):
        """Test generating signed prekey through store"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        
        signed_prekey = store.generate_signed_prekey()
        
        assert store.signed_prekey is not None
        assert store.signed_prekey.key_id == 1
        assert store.next_signed_prekey_id == 2
    
    def test_generate_and_store_one_time_prekeys(self):
        """Test generating one-time prekeys through store"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        
        prekeys = store.generate_one_time_prekeys(10)
        
        assert len(store.one_time_prekeys) == 10
        assert len(prekeys) == 10
        assert store.next_one_time_prekey_id == 11
    
    def test_get_one_time_prekey(self):
        """Test retrieving one-time prekey by ID"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        store.generate_one_time_prekeys(5)
        
        prekey = store.get_one_time_prekey(key_id=3)
        
        assert prekey is not None
        assert prekey.key_id == 3
    
    def test_remove_one_time_prekey(self):
        """Test removing used one-time prekey"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        store.generate_one_time_prekeys(5)
        
        assert len(store.one_time_prekeys) == 5
        
        removed = store.remove_one_time_prekey(key_id=3)
        
        assert removed is True
        assert len(store.one_time_prekeys) == 4
        assert store.get_one_time_prekey(key_id=3) is None
    
    def test_needs_replenishment(self):
        """Test detection of low one-time prekey inventory"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        
        # Empty store needs replenishment
        assert store.needs_replenishment(threshold=20) is True
        
        # Generate enough prekeys
        store.generate_one_time_prekeys(25)
        assert store.needs_replenishment(threshold=20) is False
        
        # Remove some, falls below threshold
        for i in range(1, 7):  # Remove 6 prekeys
            store.remove_one_time_prekey(key_id=i)
        
        assert len(store.one_time_prekeys) == 19
        assert store.needs_replenishment(threshold=20) is True
    
    def test_store_serialization(self):
        """Test prekey store can be saved and loaded"""
        identity = generate_identity_keypair()
        store = PrekeyStore(identity)
        store.generate_signed_prekey()
        store.generate_one_time_prekeys(10)
        
        # Serialize
        store_dict = store.to_dict()
        
        # Deserialize
        restored_store = PrekeyStore.from_dict(store_dict)
        
        assert restored_store.identity_keypair.public_key == identity.public_key
        assert restored_store.signed_prekey is not None
        assert len(restored_store.one_time_prekeys) == 10


class TestX3DHHandshake:
    """Test X3DH key agreement protocol"""
    
    def test_x3dh_with_one_time_prekey(self):
        """Test full X3DH handshake with one-time prekey"""
        # Bob generates prekeys
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        bob_one_time_prekey = generate_one_time_prekeys(count=1, start_id=1)[0]
        
        # Bob creates and publishes bundle
        bob_bundle = create_prekey_bundle(
            bob_identity.public_key,
            bob_signed_prekey,
            bob_one_time_prekey
        )
        
        # Alice generates identity
        alice_identity = generate_identity_keypair()
        
        # Alice performs X3DH
        alice_initiator = X3DHInitiator(alice_identity)
        alice_result = alice_initiator.perform_handshake(bob_bundle)
        
        # Bob completes X3DH
        bob_receiver = X3DHReceiver(bob_identity, bob_signed_prekey.private_key)
        bob_result = bob_receiver.complete_handshake(
            alice_identity.public_key,
            alice_result.ephemeral_public,
            bob_one_time_prekey.private_key
        )
        
        # Verify both derived the same shared secret
        assert verify_shared_secrets_match(alice_result, bob_result)
        assert alice_result.shared_secret == bob_result.shared_secret
        assert len(alice_result.shared_secret) == 32
    
    def test_x3dh_without_one_time_prekey(self):
        """Test X3DH handshake when no one-time prekey available"""
        # Bob generates prekeys (no one-time prekey)
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        
        # Bob creates bundle without OPK
        bob_bundle = create_prekey_bundle(
            bob_identity.public_key,
            bob_signed_prekey,
            one_time_prekey=None
        )
        
        # Alice generates identity
        alice_identity = generate_identity_keypair()
        
        # Alice performs X3DH (without OPK)
        alice_initiator = X3DHInitiator(alice_identity)
        alice_result = alice_initiator.perform_handshake(bob_bundle)
        
        # Bob completes X3DH (without OPK)
        bob_receiver = X3DHReceiver(bob_identity, bob_signed_prekey.private_key)
        bob_result = bob_receiver.complete_handshake(
            alice_identity.public_key,
            alice_result.ephemeral_public,
            one_time_prekey_private=None
        )
        
        # Verify both derived the same shared secret
        assert verify_shared_secrets_match(alice_result, bob_result)
        assert alice_result.shared_secret == bob_result.shared_secret
    
    def test_x3dh_different_with_without_opk(self):
        """Test that shared secret differs with/without one-time prekey"""
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        bob_one_time_prekey = generate_one_time_prekeys(count=1, start_id=1)[0]
        
        alice_identity = generate_identity_keypair()
        alice_initiator = X3DHInitiator(alice_identity)
        
        # With OPK
        bundle_with_opk = create_prekey_bundle(
            bob_identity.public_key,
            bob_signed_prekey,
            bob_one_time_prekey
        )
        result_with_opk = alice_initiator.perform_handshake(bundle_with_opk)
        
        # Without OPK
        bundle_without_opk = create_prekey_bundle(
            bob_identity.public_key,
            bob_signed_prekey,
            one_time_prekey=None
        )
        result_without_opk = alice_initiator.perform_handshake(bundle_without_opk)
        
        # Shared secrets should be different
        assert result_with_opk.shared_secret != result_without_opk.shared_secret
    
    def test_x3dh_invalid_signature_rejected(self):
        """Test that X3DH fails with invalid signature"""
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        
        # Corrupt the signature
        corrupted_signature = bytearray(bob_signed_prekey.signature)
        corrupted_signature[0] ^= 0xFF
        bob_signed_prekey.signature = bytes(corrupted_signature)
        
        bob_bundle = create_prekey_bundle(
            bob_identity.public_key,
            bob_signed_prekey
        )
        
        alice_identity = generate_identity_keypair()
        alice_initiator = X3DHInitiator(alice_identity)
        
        # Should raise ValueError due to signature verification failure
        with pytest.raises(ValueError, match="signature verification failed"):
            alice_initiator.perform_handshake(bob_bundle)
    
    def test_x3dh_associated_data_matches(self):
        """Test that associated data is correctly formed"""
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        bob_bundle = create_prekey_bundle(bob_identity.public_key, bob_signed_prekey)
        
        alice_identity = generate_identity_keypair()
        alice_initiator = X3DHInitiator(alice_identity)
        alice_result = alice_initiator.perform_handshake(bob_bundle)
        
        # AD should be IK_alice || IK_bob
        expected_ad = alice_identity.public_key + bob_identity.public_key
        assert alice_result.associated_data == expected_ad
    
    def test_x3dh_different_users_different_secrets(self):
        """Test that different users produce different shared secrets"""
        # Same Bob
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        bob_bundle = create_prekey_bundle(bob_identity.public_key, bob_signed_prekey)
        
        # Two different Alices
        alice1_identity = generate_identity_keypair()
        alice2_identity = generate_identity_keypair()
        
        alice1_initiator = X3DHInitiator(alice1_identity)
        alice2_initiator = X3DHInitiator(alice2_identity)
        
        result1 = alice1_initiator.perform_handshake(bob_bundle)
        result2 = alice2_initiator.perform_handshake(bob_bundle)
        
        # Different users should get different shared secrets
        assert result1.shared_secret != result2.shared_secret
    
    def test_x3dh_ephemeral_key_included_in_result(self):
        """Test that ephemeral public key is included in result"""
        bob_identity = generate_identity_keypair()
        bob_signed_prekey = generate_signed_prekey(bob_identity, key_id=1)
        bob_bundle = create_prekey_bundle(bob_identity.public_key, bob_signed_prekey)
        
        alice_identity = generate_identity_keypair()
        alice_initiator = X3DHInitiator(alice_identity)
        alice_result = alice_initiator.perform_handshake(bob_bundle)
        
        # Ephemeral public key should be present (32 bytes)
        assert alice_result.ephemeral_public is not None
        assert len(alice_result.ephemeral_public) == 32


class TestX3DHEndToEnd:
    """End-to-end X3DH scenarios"""
    
    def test_full_conversation_initiation(self):
        """Test complete flow of initiating a conversation"""
        # 1. Bob sets up his prekey store
        bob_identity = generate_identity_keypair()
        bob_store = PrekeyStore(bob_identity)
        bob_store.generate_signed_prekey()
        bob_store.generate_one_time_prekeys(100)
        
        # 2. Bob creates a bundle with one OPK
        bob_opk = bob_store.one_time_prekeys[0]
        bob_bundle = create_prekey_bundle(
            bob_identity.public_key,
            bob_store.signed_prekey,
            bob_opk
        )
        
        # 3. Alice fetches Bob's bundle and performs X3DH
        alice_identity = generate_identity_keypair()
        alice_initiator = X3DHInitiator(alice_identity)
        alice_result = alice_initiator.perform_handshake(bob_bundle)
        
        # 4. Alice sends message with: IK_a, EK_a, OPK_id
        # (Simulated - in real system this would go through server)
        message_header = {
            "sender_identity": alice_identity.public_key,
            "ephemeral_key": alice_result.ephemeral_public,
            "one_time_prekey_id": alice_result.one_time_prekey_id
        }
        
        # 5. Bob receives message and completes X3DH
        bob_receiver = X3DHReceiver(bob_identity, bob_store.signed_prekey.private_key)
        
        # Bob looks up the OPK that was used
        used_opk = bob_store.get_one_time_prekey(message_header["one_time_prekey_id"])
        
        bob_result = bob_receiver.complete_handshake(
            message_header["sender_identity"],
            message_header["ephemeral_key"],
            used_opk.private_key
        )
        
        # 6. Bob deletes the used OPK
        bob_store.remove_one_time_prekey(used_opk.key_id)
        
        # 7. Verify shared secrets match
        assert verify_shared_secrets_match(alice_result, bob_result)
        
        # 8. Check that OPK was actually removed
        assert len(bob_store.one_time_prekeys) == 99
        assert bob_store.get_one_time_prekey(used_opk.key_id) is None
