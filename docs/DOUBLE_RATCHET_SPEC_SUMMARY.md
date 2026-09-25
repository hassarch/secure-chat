# Double Ratchet Protocol Implementation Summary

## Overview

The Double Ratchet algorithm is used for encrypting messages in an ongoing conversation after the initial key agreement (X3DH). It provides forward secrecy and post-compromise security through two types of ratcheting:

1. **Symmetric-key ratchet** (KDF chains): Derives new message keys from chain keys
2. **DH ratchet**: Generates new root keys through Diffie-Hellman exchanges

## Key Hierarchy

```
X3DH Shared Secret (SK)
        ↓
    Root Key (RK)
        ↓
   ┌────┴────┐
   ↓         ↓
Send Chain  Receive Chain
Key (CK)    Key (CK)
   ↓           ↓
Message     Message
Keys (MK)   Keys (MK)
```

## State Variables

### Core State
- **Root Key (RK)**: 32 bytes - Rotated on each DH ratchet step
- **Send Chain Key (CK_s)**: 32 bytes - Derives sending message keys
- **Receive Chain Key (CK_r)**: 32 bytes - Derives receiving message keys
- **DH Ratchet Key Pair**: Current X25519 keypair for DH ratchet
- **DH Remote Public Key**: Remote party's current public key

### Counters
- **Send Message Number (N_s)**: Messages sent in current sending chain
- **Receive Message Number (N_r)**: Messages received in current receiving chain
- **Previous Send Chain Length (PN)**: For detecting DH ratchet steps

### Skipped Messages
- **Skipped Message Keys**: Map of (public_key, msg_num) → message_key
- Used to decrypt out-of-order messages

## Initialization

After X3DH completes with shared secret `SK`:

```python
# Alice is sender, Bob is receiver
def initialize_alice(SK: bytes, bob_public_dh: bytes):
    dh_private, dh_public = generate_x25519_keypair()
    
    # Perform initial DH ratchet
    dh_out = DH(dh_private, bob_public_dh)
    RK, CK_s = KDF_RK(SK, dh_out)
    
    state = RatchetState(
        root_key=RK,
        chain_key_send=CK_s,
        chain_key_recv=None,  # Will be set when receiving
        dh_private=dh_private,
        dh_public=dh_public,
        dh_remote=bob_public_dh,
        send_msg_num=0,
        recv_msg_num=0,
        prev_chain_length=0,
        skipped_keys={}
    )

def initialize_bob(SK: bytes):
    dh_private, dh_public = generate_x25519_keypair()
    
    state = RatchetState(
        root_key=SK,
        chain_key_send=None,  # Will be set on first send
        chain_key_recv=None,  # Will be set when receiving
        dh_private=dh_private,
        dh_public=dh_public,
        dh_remote=None,  # Will be set from Alice's first message
        send_msg_num=0,
        recv_msg_num=0,
        prev_chain_length=0,
        skipped_keys={}
    )
```

## KDF Functions

### KDF_RK (Root Key KDF)
Derives new root key and chain key from DH output:

```python
def KDF_RK(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """
    Input: 32-byte root key, 32-byte DH output
    Output: 32-byte root key, 32-byte chain key
    """
    output = HKDF(
        input_key_material=dh_out,
        salt=rk,
        info=b"DoubleRatchet-RootKey",
        length=64
    )
    return output[:32], output[32:64]
```

### KDF_CK (Chain Key KDF)
Derives new chain key and message key:

```python
def KDF_CK(ck: bytes) -> Tuple[bytes, bytes]:
    """
    Input: 32-byte chain key
    Output: 32-byte chain key, 32-byte message key
    """
    # Method 1: HMAC-based (recommended)
    new_ck = HMAC-SHA256(ck, 0x01)
    mk = HMAC-SHA256(ck, 0x02)
    return new_ck, mk
    
    # Method 2: HKDF-based (alternative)
    output = HKDF(
        input_key_material=ck,
        salt=b"",
        info=b"DoubleRatchet-ChainKey",
        length=64
    )
    return output[:32], output[32:64]
```

## Message Encryption

### Sending a Message

```python
def ratchet_encrypt(state: RatchetState, plaintext: bytes, ad: bytes) -> (Header, bytes):
    # 1. Derive message key from chain key
    state.chain_key_send, message_key = KDF_CK(state.chain_key_send)
    
    # 2. Create header
    header = Header(
        dh_public=state.dh_public,
        prev_chain_length=state.prev_chain_length,
        message_number=state.send_msg_num
    )
    
    # 3. Increment send counter
    state.send_msg_num += 1
    
    # 4. Encrypt with AEAD
    # AD includes header to authenticate it
    header_bytes = encode(header)
    ciphertext, nonce = AEAD_ENCRYPT(message_key, plaintext, header_bytes + ad)
    
    # 5. Delete message key (forward secrecy)
    del message_key
    
    return header, ciphertext, nonce
```

### Receiving a Message

```python
def ratchet_decrypt(state: RatchetState, header: Header, ciphertext: bytes, 
                    nonce: bytes, ad: bytes) -> bytes:
    # 1. Check if we need to perform DH ratchet step
    if header.dh_public != state.dh_remote:
        skip_message_keys(state, header.prev_chain_length)
        dh_ratchet(state, header)
    
    # 2. Skip message keys if needed (out-of-order messages)
    skip_message_keys(state, header.message_number)
    
    # 3. Derive message key
    state.chain_key_recv, message_key = KDF_CK(state.chain_key_recv)
    state.recv_msg_num += 1
    
    # 4. Decrypt with AEAD
    header_bytes = encode(header)
    plaintext = AEAD_DECRYPT(message_key, ciphertext, nonce, header_bytes + ad)
    
    # 5. Delete message key
    del message_key
    
    return plaintext
```

## DH Ratchet Step

Performed when receiving a message with a new DH public key:

```python
def dh_ratchet(state: RatchetState, header: Header):
    # 1. Save previous chain length for next send
    state.prev_chain_length = state.send_msg_num
    
    # 2. Perform DH with remote's new public key
    state.dh_remote = header.dh_public
    dh_recv = DH(state.dh_private, state.dh_remote)
    
    # 3. Derive new root key and receive chain key
    state.root_key, state.chain_key_recv = KDF_RK(state.root_key, dh_recv)
    state.recv_msg_num = 0
    
    # 4. Generate new DH keypair
    state.dh_private, state.dh_public = generate_x25519_keypair()
    
    # 5. Perform DH with our new keypair
    dh_send = DH(state.dh_private, state.dh_remote)
    
    # 6. Derive new root key and send chain key
    state.root_key, state.chain_key_send = KDF_RK(state.root_key, dh_send)
    state.send_msg_num = 0
```

## Skipped Message Keys

Handle out-of-order message delivery:

```python
def skip_message_keys(state: RatchetState, until: int):
    """
    Store message keys for skipped messages.
    
    Args:
        until: Message number to skip to
    """
    if state.recv_msg_num + MAX_SKIP < until:
        raise TooManySkippedMessages()
    
    if state.chain_key_recv is not None:
        while state.recv_msg_num < until:
            ck, mk = KDF_CK(state.chain_key_recv)
            state.chain_key_recv = ck
            
            # Store skipped message key
            key = (state.dh_remote, state.recv_msg_num)
            state.skipped_keys[key] = mk
            
            state.recv_msg_num += 1

def try_skipped_message_keys(state: RatchetState, header: Header, 
                              ciphertext: bytes, nonce: bytes, ad: bytes) -> Optional[bytes]:
    """
    Try to decrypt with a skipped message key.
    """
    key = (header.dh_public, header.message_number)
    
    if key in state.skipped_keys:
        mk = state.skipped_keys[key]
        del state.skipped_keys[key]  # Delete after use
        
        header_bytes = encode(header)
        plaintext = AEAD_DECRYPT(mk, ciphertext, nonce, header_bytes + ad)
        return plaintext
    
    return None
```

## Message Header Format

```python
class MessageHeader:
    dh_public: bytes          # 32 bytes - Current DH public key
    prev_chain_length: int    # Previous send chain length
    message_number: int       # Message number in current chain
    
    def encode(self) -> bytes:
        # Network byte order encoding
        return dh_public + pack('>I', prev_chain_length) + pack('>I', message_number)
```

## Security Properties

### Forward Secrecy
- ✅ **Message keys deleted after use**: Old messages cannot be decrypted
- ✅ **Chain keys ratcheted forward**: Cannot derive old message keys from current chain key
- ✅ **DH keys rotated**: Old DH keys deleted, cannot be recovered

### Post-Compromise Security (Future Secrecy)
- ✅ **DH ratchet introduces fresh randomness**: Each DH step uses new random private key
- ✅ **Attacker must maintain persistent access**: Compromise heals after DH ratchet step
- ✅ **Recovery within 1 round-trip**: After Bob receives compromised message and replies

### Replay Protection
- ✅ **Message numbers tracked**: Duplicate message numbers rejected
- ✅ **Skipped key window bounded**: Old messages beyond window rejected
- ❌ **No explicit anti-replay nonce**: Relies on message numbering

## Constants

```python
MAX_SKIP = 1000              # Maximum skipped message keys to store
SKIPPED_KEY_TTL = 7 * 24 * 3600  # 7 days expiry for skipped keys
MAX_MESSAGE_AGE = 30 * 24 * 3600  # 30 days maximum message age
```

## Implementation Notes

### Memory Management
- Delete message keys immediately after use
- Limit skipped keys cache (MAX_SKIP)
- Implement expiry for skipped keys
- Clear old chain keys when ratcheting

### Concurrency
- State must be protected with locks for thread safety
- Encrypt/decrypt operations must be serialized per contact
- Multiple contacts can operate concurrently

### Error Handling
- **Decryption failure**: Could be tampering, corruption, or wrong key
- **Too many skipped keys**: Potential DoS or desync attack
- **Message too old**: Replay attempt or severe desync

### State Persistence
- Serialize state after each message send/receive
- Encrypt state at rest
- Atomic updates to prevent corruption
- Include version field for future migrations

## Example Message Flow

```
Alice                                   Bob
  |                                      |
  | Initial X3DH                         |
  | SK established                       |
  |                                      |
  | Msg #0 (chain 0)                    |
  |------------------------------------->|
  |      [Alice DH pub = A0]            |
  |                                      |
  | Msg #1 (chain 0)                    |
  |------------------------------------->|
  |      [Alice DH pub = A0]            |
  |                                      |
  |                       Msg #0 (chain 1)|
  |<-------------------------------------|
  |      [Bob DH pub = B0]              |
  |      [Bob performs DH ratchet]      |
  |                                      |
  | [Alice performs DH ratchet]         |
  | Msg #0 (chain 2)                    |
  |------------------------------------->|
  |      [Alice DH pub = A1]            |
```

Each message with a new DH public key triggers a DH ratchet step, creating forward secrecy.

## Test Vectors

Test implementations should verify:
1. Alice and Bob can exchange messages
2. Messages decrypt to correct plaintext
3. Out-of-order messages handled correctly
4. DH ratchet steps occur correctly
5. Skipped keys cached and used properly
6. State serialization/deserialization works

## References

- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [The Double Ratchet Algorithm (WhatsApp Whitepaper)](https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf)
