"""
Unit tests for cryptographic primitives.

Tests verify:
1. Key generation produces correct sizes
2. Signatures verify correctly
3. DH produces matching shared secrets
4. HKDF derives deterministic keys
5. AEAD encryption/decryption works correctly
6. Invalid inputs are rejected appropriately
"""

import pytest
from src.crypto.primitives import (
    generate_x25519_keypair,
    x25519_dh,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    hkdf_derive,
    aead_encrypt,
    aead_decrypt,
    derive_key_from_password,
    constant_time_compare,
    generate_random_bytes,
    convert_ed25519_to_x25519_public,
    convert_ed25519_to_x25519_private,
)


class TestX25519:
    """Test X25519 Diffie-Hellman key exchange"""
    
    def test_keypair_generation(self):
        """Test that X25519 keypairs have correct size"""
        private, public = generate_x25519_keypair()
        
        assert len(private) == 32
        assert len(public) == 32
        assert private != public
    
    def test_dh_shared_secret(self):
        """Test that DH produces matching shared secrets"""
        # Alice generates a keypair
        alice_private, alice_public = generate_x25519_keypair()
        
        # Bob generates a keypair
        bob_private, bob_public = generate_x25519_keypair()
        
        # Both compute the shared secret
        alice_shared = x25519_dh(alice_private, bob_public)
        bob_shared = x25519_dh(bob_private, alice_public)
        
        # Shared secrets should match
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32
    
    def test_dh_different_keypairs_different_secrets(self):
        """Test that different keypairs produce different secrets"""
        alice_private, alice_public = generate_x25519_keypair()
        bob_private, bob_public = generate_x25519_keypair()
        charlie_private, charlie_public = generate_x25519_keypair()
        
        secret_ab = x25519_dh(alice_private, bob_public)
        secret_ac = x25519_dh(alice_private, charlie_public)
        
        assert secret_ab != secret_ac
    
    def test_dh_invalid_key_size(self):
        """Test that invalid key sizes are rejected"""
        alice_private, alice_public = generate_x25519_keypair()
        
        with pytest.raises(ValueError):
            x25519_dh(alice_private[:16], alice_public)  # Too short
        
        with pytest.raises(ValueError):
            x25519_dh(alice_private, alice_public[:16])  # Too short


class TestEd25519:
    """Test Ed25519 digital signatures"""
    
    def test_keypair_generation(self):
        """Test that Ed25519 keypairs have correct size"""
        private, public = generate_ed25519_keypair()
        
        assert len(private) == 32  # Seed
        assert len(public) == 32
    
    def test_sign_and_verify(self):
        """Test that signatures verify correctly"""
        private, public = generate_ed25519_keypair()
        message = b"Hello, World!"
        
        signature = ed25519_sign(private, message)
        
        assert len(signature) == 64
        assert ed25519_verify(public, message, signature)
    
    def test_verify_wrong_message_fails(self):
        """Test that signature fails on different message"""
        private, public = generate_ed25519_keypair()
        message = b"Hello, World!"
        wrong_message = b"Goodbye, World!"
        
        signature = ed25519_sign(private, message)
        
        assert not ed25519_verify(public, wrong_message, signature)
    
    def test_verify_wrong_key_fails(self):
        """Test that signature fails with different public key"""
        private1, public1 = generate_ed25519_keypair()
        private2, public2 = generate_ed25519_keypair()
        message = b"Hello, World!"
        
        signature = ed25519_sign(private1, message)
        
        assert not ed25519_verify(public2, message, signature)
    
    def test_verify_corrupted_signature_fails(self):
        """Test that corrupted signature fails"""
        private, public = generate_ed25519_keypair()
        message = b"Hello, World!"
        
        signature = ed25519_sign(private, message)
        corrupted = signature[:32] + bytes([signature[32] ^ 0xFF]) + signature[33:]
        
        assert not ed25519_verify(public, message, corrupted)


class TestHKDF:
    """Test HKDF key derivation"""
    
    def test_hkdf_deterministic(self):
        """Test that HKDF produces deterministic output"""
        ikm = b"input key material"
        salt = b"salt"
        info = b"context info"
        
        derived1 = hkdf_derive(ikm, 32, salt, info)
        derived2 = hkdf_derive(ikm, 32, salt, info)
        
        assert derived1 == derived2
        assert len(derived1) == 32
    
    def test_hkdf_different_inputs(self):
        """Test that different inputs produce different outputs"""
        ikm1 = b"input1"
        ikm2 = b"input2"
        salt = b"salt"
        
        derived1 = hkdf_derive(ikm1, 32, salt)
        derived2 = hkdf_derive(ikm2, 32, salt)
        
        assert derived1 != derived2
    
    def test_hkdf_different_lengths(self):
        """Test deriving different lengths"""
        ikm = b"input key material"
        
        derived16 = hkdf_derive(ikm, 16)
        derived32 = hkdf_derive(ikm, 32)
        derived64 = hkdf_derive(ikm, 64)
        
        assert len(derived16) == 16
        assert len(derived32) == 32
        assert len(derived64) == 64
    
    def test_hkdf_info_separation(self):
        """Test that different info values produce different keys"""
        ikm = b"shared secret"
        
        key1 = hkdf_derive(ikm, 32, info=b"key1")
        key2 = hkdf_derive(ikm, 32, info=b"key2")
        
        assert key1 != key2


class TestAEAD:
    """Test AEAD encryption/decryption"""
    
    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption"""
        key = generate_random_bytes(32)
        plaintext = b"Secret message"
        
        ciphertext, nonce = aead_encrypt(key, plaintext)
        decrypted = aead_decrypt(key, ciphertext, nonce)
        
        assert decrypted == plaintext
        assert ciphertext != plaintext
    
    def test_encrypt_with_associated_data(self):
        """Test encryption with associated data"""
        key = generate_random_bytes(32)
        plaintext = b"Secret message"
        ad = b"header info"
        
        ciphertext, nonce = aead_encrypt(key, plaintext, ad)
        decrypted = aead_decrypt(key, ciphertext, nonce, ad)
        
        assert decrypted == plaintext
    
    def test_wrong_key_fails(self):
        """Test that wrong key fails to decrypt"""
        key1 = generate_random_bytes(32)
        key2 = generate_random_bytes(32)
        plaintext = b"Secret message"
        
        ciphertext, nonce = aead_encrypt(key1, plaintext)
        
        with pytest.raises(ValueError):
            aead_decrypt(key2, ciphertext, nonce)
    
    def test_modified_ciphertext_fails(self):
        """Test that modified ciphertext is detected"""
        key = generate_random_bytes(32)
        plaintext = b"Secret message"
        
        ciphertext, nonce = aead_encrypt(key, plaintext)
        
        # Modify one byte
        modified = ciphertext[:5] + bytes([ciphertext[5] ^ 0xFF]) + ciphertext[6:]
        
        with pytest.raises(ValueError):
            aead_decrypt(key, modified, nonce)
    
    def test_wrong_nonce_fails(self):
        """Test that wrong nonce fails"""
        key = generate_random_bytes(32)
        plaintext = b"Secret message"
        
        ciphertext, nonce = aead_encrypt(key, plaintext)
        wrong_nonce = generate_random_bytes(len(nonce))
        
        with pytest.raises(ValueError):
            aead_decrypt(key, ciphertext, wrong_nonce)
    
    def test_invalid_key_size(self):
        """Test that invalid key size is rejected"""
        short_key = generate_random_bytes(16)
        plaintext = b"Secret message"
        
        with pytest.raises(ValueError):
            aead_encrypt(short_key, plaintext)


class TestPasswordDerivation:
    """Test password-based key derivation"""
    
    def test_derive_key_from_password(self):
        """Test basic password derivation"""
        password = "my secure password"
        salt = generate_random_bytes(16)
        
        key = derive_key_from_password(password, salt)
        
        assert len(key) == 32
    
    def test_same_password_same_key(self):
        """Test that same password produces same key with same salt"""
        password = "my secure password"
        salt = generate_random_bytes(16)
        
        key1 = derive_key_from_password(password, salt)
        key2 = derive_key_from_password(password, salt)
        
        assert key1 == key2
    
    def test_different_salt_different_key(self):
        """Test that different salts produce different keys"""
        password = "my secure password"
        salt1 = generate_random_bytes(16)
        salt2 = generate_random_bytes(16)
        
        key1 = derive_key_from_password(password, salt1)
        key2 = derive_key_from_password(password, salt2)
        
        assert key1 != key2
    
    def test_different_password_different_key(self):
        """Test that different passwords produce different keys"""
        salt = generate_random_bytes(16)
        
        key1 = derive_key_from_password("password1", salt)
        key2 = derive_key_from_password("password2", salt)
        
        assert key1 != key2
    
    def test_short_salt_rejected(self):
        """Test that short salt is rejected"""
        password = "my secure password"
        short_salt = generate_random_bytes(8)
        
        with pytest.raises(ValueError):
            derive_key_from_password(password, short_salt)


class TestUtilities:
    """Test utility functions"""
    
    def test_generate_random_bytes(self):
        """Test random byte generation"""
        random1 = generate_random_bytes(32)
        random2 = generate_random_bytes(32)
        
        assert len(random1) == 32
        assert len(random2) == 32
        assert random1 != random2  # Astronomically unlikely to be equal
    
    def test_constant_time_compare(self):
        """Test constant-time comparison"""
        a = b"secret value"
        b = b"secret value"
        c = b"other value!"
        
        assert constant_time_compare(a, b)
        assert not constant_time_compare(a, c)
    
    def test_ed25519_to_x25519_conversion(self):
        """Test Ed25519 to X25519 key conversion"""
        ed_private, ed_public = generate_ed25519_keypair()
        
        x_private = convert_ed25519_to_x25519_private(ed_private)
        x_public = convert_ed25519_to_x25519_public(ed_public)
        
        assert len(x_private) == 32
        assert len(x_public) == 32
        
        # Verify the converted keys work for DH
        other_private, other_public = generate_x25519_keypair()
        
        secret1 = x25519_dh(x_private, other_public)
        secret2 = x25519_dh(other_private, x_public)
        
        assert secret1 == secret2
