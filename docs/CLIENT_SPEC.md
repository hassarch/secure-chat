# SecureChat Client Specification

## Overview

The SecureChat client is a CLI application that provides end-to-end encrypted messaging using the Signal Protocol. It manages user identity, establishes encrypted sessions via X3DH, maintains Double Ratchet sessions, and communicates with the relay server over WebSocket.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Interface                        │
│  (register, login, send, receive, list, verify, etc.)   │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Session Manager                         │
│  • Coordinate X3DH handshakes                           │
│  • Manage Double Ratchet sessions                       │
│  • Handle message encryption/decryption                 │
│  • Session lifecycle management                         │
└────────┬───────────────────────────────┬────────────────┘
         │                               │
┌────────▼──────────┐         ┌─────────▼────────────────┐
│  Storage Layer    │         │   Transport Layer        │
│  • Identity keys  │         │   • WebSocket client     │
│  • Sessions       │         │   • Message send/receive │
│  • Contacts       │         │   • Reconnection logic   │
│  • Encrypted DB   │         │   • Server communication │
└───────────────────┘         └──────────────────────────┘
```

## Components

### 1. Storage Layer (`src/client/storage.py`)

**Purpose**: Securely store identity keys, Double Ratchet sessions, and contact information using password-based encryption.

**Key Features**:
- Password-based encryption using Argon2id
- Store identity key pair (Ed25519)
- Store prekey bundles
- Store Double Ratchet sessions (per contact)
- Store contact list with identity keys
- SQLite database with encrypted blobs

**Schema**:
```sql
-- User's own identity
CREATE TABLE identity (
    user_id TEXT PRIMARY KEY,
    identity_private_key BLOB NOT NULL,  -- Encrypted
    identity_public_key BLOB NOT NULL,
    signed_prekey_private BLOB NOT NULL, -- Encrypted
    signed_prekey_public BLOB NOT NULL,
    signed_prekey_signature BLOB NOT NULL,
    prekey_id INTEGER NOT NULL,
    registration_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Contact identity keys and verification status
CREATE TABLE contacts (
    contact_id TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL,
    verified INTEGER DEFAULT 0,  -- 0=unverified, 1=verified
    safety_number TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Double Ratchet sessions
CREATE TABLE sessions (
    contact_id TEXT PRIMARY KEY,
    session_state BLOB NOT NULL,  -- Encrypted serialized RatchetState
    last_message_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (contact_id) REFERENCES contacts(contact_id)
);

-- Message queue for pending sends
CREATE TABLE pending_messages (
    message_id TEXT PRIMARY KEY,
    recipient_id TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (recipient_id) REFERENCES contacts(recipient_id)
);
```

**Encryption Strategy**:
- Master key derived from user password using Argon2id
- Each sensitive blob encrypted with AEAD (XChaCha20-Poly1305)
- Salt stored per-database (in metadata table)
- Key derivation: `Argon2id(password, salt, ops=3, mem=64MB)`

**API**:
```python
class SecureStorage:
    def __init__(self, db_path: str, password: str)
    def initialize_identity(self, user_id: str, identity: PreKeyBundle)
    def get_identity(self) -> Tuple[str, PreKeyBundle]
    def save_session(self, contact_id: str, state: RatchetState)
    def load_session(self, contact_id: str) -> Optional[RatchetState]
    def add_contact(self, contact_id: str, identity_key: bytes)
    def get_contact(self, contact_id: str) -> Optional[Contact]
    def list_contacts(self) -> List[Contact]
    def verify_contact(self, contact_id: str, safety_number: str)
    def delete_session(self, contact_id: str)
    def close()
```

### 2. Transport Layer (`src/client/transport.py`)

**Purpose**: Handle WebSocket communication with the relay server.

**Key Features**:
- WebSocket connection management
- Automatic reconnection with exponential backoff
- Message send/receive with acknowledgments
- Heartbeat/keepalive
- Queue messages during disconnection

**Message Flow**:
```
Client                          Server
  │                               │
  ├──── REGISTER ────────────────>│
  │<──── REGISTERED ──────────────┤
  │                               │
  ├──── UPLOAD_PREKEYS ──────────>│
  │<──── PREKEYS_UPLOADED ────────┤
  │                               │
  ├──── FETCH_PREKEY_BUNDLE ─────>│
  │<──── PREKEY_BUNDLE ───────────┤
  │                               │
  ├──── SEND_MESSAGE ────────────>│
  │<──── MESSAGE_SENT ────────────┤
  │                               │
  │<──── MESSAGE_RECEIVED ────────┤
  ├──── ACK ─────────────────────>│
```

**API**:
```python
class Transport:
    def __init__(self, server_url: str, user_id: str)
    async def connect()
    async def disconnect()
    async def register(identity_key: bytes, signed_prekey: SignedPreKey) -> bool
    async def upload_prekeys(prekeys: List[OneTimePreKey]) -> bool
    async def fetch_prekey_bundle(recipient_id: str) -> Optional[PreKeyBundle]
    async def send_message(recipient_id: str, ciphertext: bytes) -> bool
    async def receive_messages() -> AsyncIterator[Message]
    def set_message_handler(handler: Callable)
    def is_connected() -> bool
```

### 3. Session Manager (`src/client/session.py`)

**Purpose**: Coordinate X3DH handshakes and manage Double Ratchet sessions.

**Key Features**:
- Initiate new sessions using X3DH
- Accept incoming X3DH handshakes
- Encrypt/decrypt messages using Double Ratchet
- Handle session initialization and rotation
- Manage out-of-order messages

**Session Lifecycle**:

**New Conversation (Alice → Bob)**:
1. Alice fetches Bob's prekey bundle from server
2. Alice performs X3DH handshake (initiator side)
3. Alice initializes Double Ratchet with shared secret
4. Alice encrypts first message and sends to Bob
5. Bob receives message, performs X3DH (receiver side)
6. Bob initializes Double Ratchet with same shared secret
7. Both now have active Double Ratchet session

**Existing Conversation**:
1. Load session state from storage
2. Encrypt/decrypt with Double Ratchet
3. Save updated session state after each message
4. Handle out-of-order messages with skipped keys

**API**:
```python
class SessionManager:
    def __init__(self, storage: SecureStorage, transport: Transport)
    async def initialize_session(self, recipient_id: str) -> bool
    async def encrypt_message(self, recipient_id: str, plaintext: bytes) -> bytes
    async def decrypt_message(self, sender_id: str, ciphertext: bytes) -> bytes
    def get_session_info(self, contact_id: str) -> Optional[SessionInfo]
    async def delete_session(self, contact_id: str)
    def compute_safety_number(self, contact_id: str) -> str
```

### 4. CLI Interface (`src/client/cli.py`)

**Purpose**: User-facing command-line interface.

**Commands**:

```bash
# User Management
securechat register <username>
securechat login <username>
securechat logout

# Messaging
securechat send <recipient> <message>
securechat receive  # Poll for new messages
securechat listen   # Continuous listening mode

# Contacts
securechat contacts list
securechat contacts add <username>
securechat contacts verify <username> <safety-number>
securechat contacts info <username>

# Session Management
securechat session info <username>
securechat session delete <username>  # Delete and start fresh
securechat session list

# Utility
securechat status  # Connection status, identity fingerprint
securechat help
```

**Interactive Mode**:
```bash
securechat listen

SecureChat v1.0 - Listening for messages...
Connected as: alice@securechat
Identity: A1B2C3D4E5F6...

[12:34:56] bob: Hey Alice!
> Hi Bob, how are you?
[12:35:01] You → bob: Hi Bob, how are you?
[12:35:05] bob: Great! Want to grab coffee?
> Sure! When?
[12:35:10] You → bob: Sure! When?
```

## Security Considerations

### 1. Password Security
- Require strong passwords (min 12 chars, complexity check)
- Use Argon2id with secure parameters (ops=3, mem=64MB)
- Never store plaintext password
- Lock database after inactivity (configurable timeout)

### 2. Key Storage
- All private keys encrypted at rest
- Use operating system keychain if available (future enhancement)
- Secure deletion on logout (overwrite before delete)

### 3. Session Security
- Forward secrecy via Double Ratchet
- Out-of-order message handling
- Replay attack prevention (message counters)
- Session expiration (configurable, default 30 days)

### 4. Network Security
- TLS/WSS for transport encryption (server must use SSL)
- Certificate pinning (optional, for production)
- Verify server identity before sending identity keys

### 5. Identity Verification
- Safety numbers (fingerprint comparison)
- Trust on First Use (TOFU) model
- Warn on identity key changes
- QR code verification (future enhancement)

## Error Handling

### Connection Errors
- Auto-reconnect with exponential backoff (1s, 2s, 4s, 8s, 16s, max 60s)
- Queue messages during disconnection
- Notify user of connection status changes

### Crypto Errors
- Invalid signature: reject message, warn user
- Session corruption: offer to reset session
- Decryption failure: check for out-of-order, handle skipped keys

### Storage Errors
- Database corruption: backup and recovery mode
- Wrong password: lock after 3 attempts, require unlock timer
- Disk full: warn and pause

## Testing Strategy

### Unit Tests
- Storage encryption/decryption
- Session serialization
- Transport message handling
- CLI command parsing

### Integration Tests
- Full X3DH handshake between two clients
- Message encryption/decryption flow
- Out-of-order message handling
- Session persistence and recovery
- Offline message delivery

### Security Tests
- Password strength validation
- Key derivation correctness
- Session forward secrecy
- Replay attack prevention

## Configuration

**Config file**: `~/.securechat/config.yaml`

```yaml
# Server settings
server:
  url: "wss://securechat.example.com"
  reconnect_attempts: 5
  reconnect_delay: 1  # seconds

# Storage settings
storage:
  db_path: "~/.securechat/securechat.db"
  session_timeout: 2592000  # 30 days in seconds
  auto_lock: 900  # 15 minutes

# Security settings
security:
  password_min_length: 12
  argon2_ops: 3
  argon2_mem: 67108864  # 64MB
  verify_server_cert: true

# UI settings
ui:
  timestamp_format: "%H:%M:%S"
  message_history: 100
  color_enabled: true
```

## Performance Considerations

### Database
- Use WAL mode for concurrent reads
- Index on contact_id, message timestamps
- Vacuum on cleanup operations

### Memory
- Limit message cache size (default 1000 messages)
- Stream large attachments (future)
- Lazy load session states

### Network
- Batch message sends when possible
- Compress large payloads
- Implement backpressure for receive queue

## Future Enhancements

1. **Group Messaging**: Sender keys protocol
2. **File Attachments**: End-to-end encrypted file transfer
3. **Voice/Video**: WebRTC with E2E encryption
4. **Desktop Notifications**: System notifications for new messages
5. **Multi-Device**: Sesame protocol for device sync
6. **Backup/Restore**: Encrypted backup to cloud
7. **Disappearing Messages**: Auto-delete after time/read
8. **Typing Indicators**: Encrypted typing status
9. **Read Receipts**: Optional encrypted receipts
10. **Search**: Encrypted message search

## Development Workflow

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Run tests
pytest tests/unit/test_client*.py -v
pytest tests/integration/ -v

# Run client
securechat register alice
securechat listen

# In another terminal
securechat --user bob register bob
securechat --user bob send alice "Hello Alice!"
```

## Deployment

### Installation
```bash
pip install securechat
securechat register <username>
```

### Requirements
- Python 3.8+
- PyNaCl 1.5.0+
- websockets 12.0+
- SQLite 3.35+

### Platform Support
- Linux: Full support
- macOS: Full support
- Windows: Full support (with Windows Terminal for colors)

---

**Status**: Ready for implementation
**Author**: SecureChat Development Team
**Last Updated**: 2026-09-25
