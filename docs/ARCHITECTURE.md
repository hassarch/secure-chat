# SecureChat Architecture

## Overview

SecureChat implements the Signal Protocol for end-to-end encrypted messaging. The system consists of client applications that perform all cryptographic operations and a relay server that routes encrypted messages without access to plaintext.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Client A                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   UI Layer   │  │   Session    │  │   Crypto     │     │
│  │   (CLI/GUI)  │  │   Store      │  │  Primitives  │     │
│  └──────┬───────┘  └──────┬───────┘  └──────▲───────┘     │
│         │                  │                  │             │
│  ┌──────▼──────────────────▼──────────────────┴───────┐    │
│  │            Messaging Core                           │    │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐   │    │
│  │  │   X3DH     │  │   Double   │  │  Transport │   │    │
│  │  │  Handshake │  │   Ratchet  │  │    Layer   │   │    │
│  │  └────────────┘  └────────────┘  └──────┬─────┘   │    │
│  └────────────────────────────────────────────┬───────┘    │
└───────────────────────────────────────────────┼────────────┘
                                                │
                          TLS + WebSocket       │
                                                │
┌───────────────────────────────────────────────▼────────────┐
│                     Relay Server                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   WebSocket  │  │   Prekey     │  │   Message    │     │
│  │   Handler    │  │   Store      │  │   Queue      │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                                                │
                          TLS + WebSocket       │
                                                │
┌───────────────────────────────────────────────▼────────────┐
│                        Client B                              │
│                     (same structure)                         │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### Client Components

#### 1. Crypto Primitives (`src/crypto/`)

**Purpose:** Wrapper around libsodium (PyNaCl) providing cryptographic operations

**Key Operations:**
- X25519: Elliptic Curve Diffie-Hellman
- Ed25519: Digital signatures
- ChaCha20-Poly1305: AEAD encryption
- HKDF: Key derivation
- Argon2: Password-based key derivation

**Design Principles:**
- NO custom crypto implementations
- All primitives from vetted libraries
- Constant-time comparisons for secrets
- Clear API with type hints

#### 2. X3DH Module (`src/x3dh/`)

**Purpose:** Extended Triple Diffie-Hellman key agreement protocol

**Responsibilities:**
- Generate prekey bundles (identity key, signed prekey, one-time prekeys)
- Perform initial key agreement
- Verify signed prekeys
- Derive initial shared secret

**X3DH Protocol Flow:**
```
Alice (initiator)                 Server                Bob (receiver)
     │                              │                         │
     │                              │    ┌──────────────────┐ │
     │                              │    │ Publish prekeys: │ │
     │                              │ ◄──┤ - Identity Key   │ │
     │                              │    │ - Signed Prekey  │ │
     │                              │    │ - One-time keys  │ │
     │                              │    └──────────────────┘ │
     │  ┌───────────────────────┐  │                         │
     │  │ Fetch Bob's prekey    │  │                         │
     │  │ bundle                │──►│                         │
     │  └───────────────────────┘  │                         │
     │  ┌───────────────────────┐  │                         │
     │  │ Perform X3DH:         │  │                         │
     │  │ DH1: IKa ⚡ SPKb      │  │                         │
     │  │ DH2: EKa ⚡ IKb       │  │                         │
     │  │ DH3: EKa ⚡ SPKb      │  │                         │
     │  │ DH4: EKa ⚡ OPKb      │  │                         │
     │  │ SK = KDF(DH1..DH4)    │  │                         │
     │  └───────────────────────┘  │                         │
     │                              │                         │
     │  ┌───────────────────────┐  │  ┌───────────────────┐ │
     │  │ Send initial message  │  │  │ Receive message   │ │
     │  │ with EKa, IKa         │──►──►│ Perform X3DH with │ │
     │  └───────────────────────┘  │  │ received keys     │ │
     │                              │  │ Derive same SK    │ │
     │                              │  └───────────────────┘ │
```

**Key Points:**
- Asynchronous: Bob doesn't need to be online
- Deniable: No proof Alice initiated
- Forward secure: One-time prekey provides FS from first message

#### 3. Double Ratchet Module (`src/ratchet/`)

**Purpose:** Symmetric-key and DH ratcheting for ongoing message encryption

**Responsibilities:**
- Symmetric-key ratchet: KDF chains for message keys
- DH ratchet: Periodic key agreement for root key rotation
- Skipped message key handling for out-of-order delivery
- Message encryption/decryption

**Double Ratchet State:**
```python
{
    # DH Ratchet
    "dh_private": bytes,    # Current DH private key
    "dh_public": bytes,     # Current DH public key
    "dh_remote": bytes,     # Remote's current DH public key
    "root_key": bytes,      # Root key (32 bytes)
    
    # Symmetric Ratchet (Sending)
    "chain_key_send": bytes,     # Sending chain key
    "message_number_send": int,   # Messages sent in current chain
    
    # Symmetric Ratchet (Receiving)
    "chain_key_recv": bytes,     # Receiving chain key
    "message_number_recv": int,   # Messages received in current chain
    
    # Skipped Message Keys
    "skipped_keys": {
        (dh_public, msg_num): message_key
    }
}
```

**Ratchet Operations:**

1. **Symmetric Ratchet (KDF Chain):**
```
Chain Key N ──KDF──► Chain Key N+1
    │
    └──────KDF──► Message Key N
```

2. **DH Ratchet (Root Key Rotation):**
```
Root Key N + DH(own, remote) ──KDF──► Root Key N+1, Chain Key N+1
```

**Message Flow:**
```
Alice                                 Bob
  │                                    │
  │  Message #0 (Chain 0)              │
  ├────────────────────────────────────►│
  │                                    │
  │  Message #1 (Chain 0)              │
  ├────────────────────────────────────►│
  │                                    │
  │                                    │  ◄── DH Ratchet (Bob sends)
  │  Message #0 (Chain 1)              │
  │◄────────────────────────────────────┤
  │                                    │
  │  ◄── DH Ratchet (Alice sends)     │
  │  Message #0 (Chain 2)              │
  ├────────────────────────────────────►│
```

#### 4. Session Store (`src/session/`)

**Purpose:** Encrypted persistence of session state

**Storage:**
- SQLite database with SQLCipher encryption
- Per-user master key derived from password (Argon2)
- Each session encrypted separately

**Schema:**
```sql
CREATE TABLE sessions (
    contact_id TEXT PRIMARY KEY,
    identity_key_remote BLOB NOT NULL,
    ratchet_state BLOB NOT NULL,  -- Encrypted JSON
    created_at INTEGER NOT NULL,
    last_updated INTEGER NOT NULL
);

CREATE TABLE skipped_keys (
    contact_id TEXT NOT NULL,
    dh_public BLOB NOT NULL,
    message_number INTEGER NOT NULL,
    message_key BLOB NOT NULL,  -- Encrypted
    created_at INTEGER NOT NULL,
    PRIMARY KEY (contact_id, dh_public, message_number)
);

CREATE TABLE identity_keys (
    username TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL,
    verified BOOLEAN DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
```

#### 5. Transport Layer (`src/client/transport.py`)

**Purpose:** WebSocket communication with relay server

**Operations:**
- Connect/disconnect
- Send ciphertext messages
- Receive ciphertext messages
- Fetch prekey bundles
- Publish prekey bundles
- Handle reconnection

#### 6. UI Layer (`src/client/cli.py`)

**Purpose:** User interface (CLI for v1)

**Features:**
- Contact list
- Send/receive messages
- Display safety numbers
- Verify contacts
- Handle identity key changes

### Server Components

#### 1. WebSocket Handler (`src/server/websocket.py`)

**Purpose:** Handle client connections

**Responsibilities:**
- Accept WebSocket connections
- Authenticate users (lightweight)
- Route messages between clients
- Handle online/offline state

#### 2. Prekey Store (`src/server/prekey_store.py`)

**Purpose:** Store and serve prekey bundles

**Operations:**
- Store user prekey bundles
- Serve prekey bundles on request
- Deplete one-time prekeys
- Track low prekey inventory

**Storage:**
```sql
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL,
    registered_at INTEGER NOT NULL
);

CREATE TABLE signed_prekeys (
    username TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    uploaded_at INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username)
);

CREATE TABLE one_time_prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    public_key BLOB NOT NULL,
    uploaded_at INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username)
);
```

#### 3. Message Queue (`src/server/message_queue.py`)

**Purpose:** Queue messages for offline users

**Operations:**
- Store ciphertext for offline recipients
- Deliver on reconnection
- Delete after delivery + ack
- Expire old messages (30 days)

**Storage:**
```sql
CREATE TABLE message_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    metadata BLOB NOT NULL,  -- Header info
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (recipient) REFERENCES users(username)
);
```

## Protocol Flows

### First Message (X3DH Handshake)

```
1. Bob registers:
   - Generates identity key IKb
   - Generates signed prekey SPKb, signs with IKb
   - Generates 100 one-time prekeys OPKb
   - Uploads bundle to server

2. Alice wants to message Bob:
   - Fetches Bob's prekey bundle
   - Verifies SPKb signature
   - Generates ephemeral key EKa
   - Performs X3DH:
     * DH1 = DH(IKa, SPKb)
     * DH2 = DH(EKa, IKb)
     * DH3 = DH(EKa, SPKb)
     * DH4 = DH(EKa, OPKb)  [if OPK available]
     * SK = HKDF(DH1 || DH2 || DH3 || DH4)
   - Initializes Double Ratchet with SK
   - Encrypts message
   - Sends: {IKa, EKa, OPK_id, ciphertext}

3. Bob receives:
   - Extracts IKa, EKa, OPK_id
   - Performs same X3DH computation
   - Initializes Double Ratchet with SK
   - Decrypts message
```

### Ongoing Messages (Double Ratchet)

```
1. Sending a message:
   - Derive message key from chain key
   - Encrypt plaintext with message key
   - Advance chain key
   - If first message after receiving: perform DH ratchet
   - Send: {dh_public, prev_chain_length, message_number, ciphertext}

2. Receiving a message:
   - If new DH public key: perform DH ratchet
   - If skipped messages: store skipped message keys
   - Derive message key for this message number
   - Decrypt ciphertext
   - Advance chain key
```

## Security Properties

### Defense in Depth

1. **Transport Layer:** TLS (protects against casual network observers)
2. **Protocol Layer:** E2E encryption (protects against compromised server)
3. **Storage Layer:** Encrypted database (protects at-rest data)

### Key Hierarchy

```
Master Password
    │
    └──Argon2──► Storage Encryption Key
                     │
                     ├──► Session State (encrypted)
                     ├──► Skipped Keys (encrypted)
                     └──► Identity Keys (encrypted)

X3DH Shared Secret
    │
    └──HKDF──► Root Key (initial)
                 │
                 └──DH Ratchet──► Root Key (updates)
                                      │
                                      ├──► Send Chain Key
                                      │      └──► Message Keys
                                      │
                                      └──► Recv Chain Key
                                             └──► Message Keys
```

### State Management

**Ephemeral State (memory only):**
- Chain keys
- Derived message keys (deleted after use)
- DH private keys (rotated)

**Persistent State (encrypted on disk):**
- Identity keys (long-term)
- Current ratchet position
- Skipped message keys (bounded)

**Never Stored:**
- Used message keys
- Old chain keys after ratchet
- Master password (only key derived from it)

## Scalability Considerations

### Client
- Local database size grows with number of contacts
- Skipped key cache bounded per contact
- Memory usage O(contacts + skipped_keys)

### Server
- One-time prekey consumption: O(new conversations)
- Message queue: O(offline messages)
- No per-session state (stateless relay)

### Future Optimizations
- Prekey refill automation
- Message queue partitioning
- Horizontal server scaling (stateless design enables it)

## Testing Strategy

### Unit Tests
- Crypto primitives (test vectors)
- X3DH handshake (known values)
- Double Ratchet steps (spec conformance)

### Integration Tests
- Full client-to-client message flow
- Out-of-order message handling
- Offline delivery
- Session resumption

### Security Tests
- Replay protection
- Tampering detection
- Forward secrecy verification
- Post-compromise security verification

## Future Enhancements (v2+)

1. **Group Messaging:** Sender Keys protocol
2. **Multi-device:** Device linking and sync
3. **Voice/Video:** WebRTC with SRTP
4. **Metadata Protection:** Tor integration, sealed sender
5. **Rich Content:** File transfer with chunking
6. **Disappearing Messages:** Client-side auto-deletion
7. **Backup/Restore:** Encrypted cloud backup

## References

- [Signal X3DH Spec](https://signal.org/docs/specifications/x3dh/)
- [Signal Double Ratchet Spec](https://signal.org/docs/specifications/doubleratchet/)
- [libsignal Implementation](https://github.com/signalapp/libsignal)
