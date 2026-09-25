# SecureChat Relay Server API Specification

## Overview

The relay server is a **trusted-but-honest** component that routes encrypted messages and stores prekey bundles. The server **cannot** decrypt message content but **can** see metadata (who talks to whom, timing, message sizes).

## Design Principles

1. **Zero Knowledge of Plaintext:** Server never has access to message keys
2. **Minimal State:** Server is mostly stateless for horizontal scaling
3. **Simple Authentication:** Username-based (not the security boundary)
4. **Ephemeral Messages:** Delete after delivery + acknowledgment
5. **Automatic Cleanup:** Expire old messages and prekeys

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Relay Server                              │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  WebSocket   │  │   Prekey     │  │   Message    │     │
│  │   Handler    │  │   Store      │  │   Queue      │     │
│  │              │  │              │  │              │     │
│  │ - Routing    │  │ - Upload     │  │ - Persist    │     │
│  │ - Presence   │  │ - Fetch      │  │ - Deliver    │     │
│  │ - Auth       │  │ - Deplete    │  │ - Expire     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │            SQLite Database                         │    │
│  │  - users                                           │    │
│  │  - prekey_bundles                                  │    │
│  │  - one_time_prekeys                                │    │
│  │  - message_queue                                   │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## WebSocket Protocol

### Connection

```
URL: ws://localhost:8000/ws
Protocol: JSON over WebSocket
```

### Message Format

All messages are JSON objects with a `type` field:

```json
{
  "type": "message_type",
  "data": { ... }
}
```

## API Endpoints

### 1. User Registration

**Type:** `register`

**Request:**
```json
{
  "type": "register",
  "data": {
    "username": "alice",
    "identity_key": "hex-encoded-ed25519-public-key"
  }
}
```

**Response (Success):**
```json
{
  "type": "register_response",
  "success": true,
  "data": {
    "username": "alice",
    "registered_at": 1695648000
  }
}
```

**Response (Error):**
```json
{
  "type": "register_response",
  "success": false,
  "error": "Username already taken"
}
```

**Notes:**
- Username must be unique
- Username 3-32 characters, alphanumeric + underscore
- Identity key stored for verification

---

### 2. Upload Prekey Bundle

**Type:** `upload_prekeys`

**Request:**
```json
{
  "type": "upload_prekeys",
  "data": {
    "username": "alice",
    "signed_prekey": {
      "public_key": "hex-encoded-x25519-public",
      "signature": "hex-encoded-ed25519-signature",
      "key_id": 1
    },
    "one_time_prekeys": [
      {
        "public_key": "hex-encoded-x25519-public",
        "key_id": 1
      },
      ...
    ]
  }
}
```

**Response:**
```json
{
  "type": "upload_prekeys_response",
  "success": true,
  "data": {
    "signed_prekey_id": 1,
    "one_time_prekey_count": 100,
    "uploaded_at": 1695648000
  }
}
```

**Notes:**
- Replaces previous signed prekey
- Adds to pool of one-time prekeys
- Should upload when count < 20

---

### 3. Fetch Prekey Bundle

**Type:** `fetch_prekeys`

**Request:**
```json
{
  "type": "fetch_prekeys",
  "data": {
    "username": "bob"
  }
}
```

**Response (Success):**
```json
{
  "type": "fetch_prekeys_response",
  "success": true,
  "data": {
    "username": "bob",
    "identity_key": "hex-encoded-ed25519-public",
    "signed_prekey": {
      "public_key": "hex-encoded-x25519-public",
      "signature": "hex-encoded-signature",
      "key_id": 1
    },
    "one_time_prekey": {
      "public_key": "hex-encoded-x25519-public",
      "key_id": 42
    }
  }
}
```

**Response (No OPK Available):**
```json
{
  "type": "fetch_prekeys_response",
  "success": true,
  "data": {
    "username": "bob",
    "identity_key": "...",
    "signed_prekey": { ... },
    "one_time_prekey": null
  }
}
```

**Notes:**
- One-time prekey is consumed (deleted) on fetch
- Client should check if OPK is null
- Returns 404 if user doesn't exist

---

### 4. Send Message

**Type:** `send_message`

**Request:**
```json
{
  "type": "send_message",
  "data": {
    "from": "alice",
    "to": "bob",
    "message": {
      "header": {
        "dh_public": "hex-encoded",
        "prev_chain_length": 5,
        "message_number": 10
      },
      "ciphertext": "hex-encoded",
      "nonce": "hex-encoded"
    },
    "x3dh_initial": {
      "sender_identity_key": "hex-encoded-ed25519-public",
      "ephemeral_key": "hex-encoded-x25519-public",
      "one_time_prekey_id": 42
    }
  }
}
```

**Response:**
```json
{
  "type": "send_message_response",
  "success": true,
  "data": {
    "message_id": "uuid-v4",
    "delivered": false,
    "queued": true
  }
}
```

**Notes:**
- `x3dh_initial` only present for first message
- Server routes to recipient if online
- Queues if recipient offline
- Returns unique message ID

---

### 5. Receive Message (Push)

**Type:** `incoming_message`

**Server → Client:**
```json
{
  "type": "incoming_message",
  "data": {
    "message_id": "uuid-v4",
    "from": "alice",
    "to": "bob",
    "timestamp": 1695648000,
    "message": {
      "header": { ... },
      "ciphertext": "...",
      "nonce": "..."
    },
    "x3dh_initial": { ... }
  }
}
```

**Client Response (ACK):**
```json
{
  "type": "message_ack",
  "data": {
    "message_id": "uuid-v4"
  }
}
```

**Notes:**
- Pushed to client immediately if online
- Client must ACK within 60 seconds
- Message deleted after ACK

---

### 6. Fetch Queued Messages

**Type:** `fetch_messages`

**Request:**
```json
{
  "type": "fetch_messages",
  "data": {
    "username": "bob"
  }
}
```

**Response:**
```json
{
  "type": "fetch_messages_response",
  "success": true,
  "data": {
    "messages": [
      {
        "message_id": "uuid-1",
        "from": "alice",
        "timestamp": 1695648000,
        "message": { ... }
      },
      ...
    ]
  }
}
```

**Notes:**
- Returns all queued messages for user
- Client should ACK each message
- Messages expire after 30 days

---

### 7. Presence/Status

**Type:** `presence`

**Request:**
```json
{
  "type": "presence",
  "data": {
    "username": "alice",
    "status": "online"
  }
}
```

**Response:**
```json
{
  "type": "presence_response",
  "success": true,
  "data": {
    "status": "online",
    "last_seen": 1695648000
  }
}
```

**Notes:**
- Status: "online", "away", "offline"
- Automatically set to "offline" on disconnect

---

### 8. Prekey Count

**Type:** `prekey_count`

**Request:**
```json
{
  "type": "prekey_count",
  "data": {
    "username": "alice"
  }
}
```

**Response:**
```json
{
  "type": "prekey_count_response",
  "success": true,
  "data": {
    "count": 15,
    "needs_replenishment": true
  }
}
```

**Notes:**
- Alerts client when OPK count < 20
- Client should upload more prekeys

---

## Database Schema

### users Table
```sql
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL,
    registered_at INTEGER NOT NULL,
    last_seen INTEGER,
    status TEXT DEFAULT 'offline'
);

CREATE INDEX idx_users_status ON users(status);
```

### signed_prekeys Table
```sql
CREATE TABLE signed_prekeys (
    username TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    key_id INTEGER NOT NULL,
    uploaded_at INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
```

### one_time_prekeys Table
```sql
CREATE TABLE one_time_prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    public_key BLOB NOT NULL,
    key_id INTEGER NOT NULL,
    uploaded_at INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX idx_opk_username ON one_time_prekeys(username);
CREATE UNIQUE INDEX idx_opk_user_keyid ON one_time_prekeys(username, key_id);
```

### message_queue Table
```sql
CREATE TABLE message_queue (
    message_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    delivered BOOLEAN DEFAULT 0,
    FOREIGN KEY (recipient) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX idx_mq_recipient ON message_queue(recipient, delivered);
CREATE INDEX idx_mq_expires ON message_queue(expires_at);
```

---

## Error Codes

```json
{
  "type": "error",
  "error_code": "ERROR_CODE",
  "message": "Human readable message"
}
```

### Error Codes
- `USER_NOT_FOUND` - Recipient doesn't exist
- `USER_EXISTS` - Username already registered
- `INVALID_USERNAME` - Username format invalid
- `INVALID_REQUEST` - Malformed request
- `AUTHENTICATION_FAILED` - Auth check failed
- `PREKEYS_NOT_FOUND` - No prekeys available
- `MESSAGE_TOO_LARGE` - Message exceeds size limit
- `RATE_LIMIT_EXCEEDED` - Too many requests
- `INTERNAL_ERROR` - Server error

---

## Rate Limiting

Per connection:
- **Registration:** 1 per IP per hour
- **Messages:** 100 per minute
- **Prekey fetch:** 50 per minute
- **Prekey upload:** 10 per hour

---

## Security Considerations

### What Server Can Do
- ✅ See who talks to whom (metadata)
- ✅ See message timing and sizes
- ✅ Drop/delay messages (availability attack)
- ✅ Refuse to deliver messages

### What Server Cannot Do
- ❌ Read message content (E2E encrypted)
- ❌ Impersonate users (without identity key)
- ❌ Forge messages (AEAD authentication)
- ❌ Modify messages undetected (authentication)

### Defense in Depth
- TLS for transport (separate from E2E)
- Message size limits (prevent DoS)
- Rate limiting (prevent abuse)
- Automatic cleanup (limit exposure)

---

## Future Enhancements

### v2 Features
- [ ] Push notifications
- [ ] Multi-device support
- [ ] Group message routing
- [ ] Server-side contact discovery
- [ ] Sealed sender (metadata protection)
- [ ] Distributed server architecture

---

## Testing

### Unit Tests
- Database operations
- Message routing logic
- Prekey management
- Rate limiting

### Integration Tests
- Full message flow (Alice → Server → Bob)
- Offline message queueing
- Concurrent connections
- Error handling

---

## Configuration

### Environment Variables
```bash
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
DATABASE_PATH=./securechat.db

# Security
MAX_MESSAGE_SIZE=1048576  # 1MB
MESSAGE_RETENTION_DAYS=30
MAX_CONNECTIONS=1000

# Rate Limiting
RATE_LIMIT_MESSAGES=100
RATE_LIMIT_WINDOW=60
```

---

## Monitoring

### Metrics to Track
- Active connections
- Messages per second
- Average message size
- Queue depth
- Prekey inventory per user
- Error rates

### Alerts
- Queue depth > 1000
- Prekey count < 10 for any user
- Error rate > 5%
- Database size > 10GB

---

## Deployment

### Development
```bash
python -m src.server.main
```

### Production
```bash
# Use gunicorn with uvicorn workers
gunicorn src.server.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

### Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/
CMD ["python", "-m", "src.server.main"]
```

---

## References

- [WebSocket Protocol RFC 6455](https://tools.ietf.org/html/rfc6455)
- [Signal Server Architecture](https://github.com/signalapp/Signal-Server)
