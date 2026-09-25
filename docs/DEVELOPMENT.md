# SecureChat Development Guide

## Getting Started

### Prerequisites

- Python 3.9 or higher
- pip and virtualenv
- libsodium (installed automatically with PyNaCl)
- SQLCipher (for encrypted database)

### Initial Setup

```bash
# Clone the repository
cd /path/to/securechat

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
make install-dev

# Run tests to verify setup
make test
```

## Project Structure

```
securechat/
├── src/
│   ├── crypto/          # Cryptographic primitives (Phase 1)
│   │   ├── __init__.py
│   │   └── primitives.py
│   ├── x3dh/            # X3DH key agreement (Phase 2)
│   │   ├── __init__.py
│   │   ├── prekeys.py
│   │   └── handshake.py
│   ├── ratchet/         # Double Ratchet (Phase 3)
│   │   ├── __init__.py
│   │   ├── state.py
│   │   └── ratchet.py
│   ├── session/         # Session storage (Phase 5)
│   │   ├── __init__.py
│   │   └── store.py
│   ├── server/          # Relay server (Phase 4)
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── websocket.py
│   │   ├── prekey_store.py
│   │   └── message_queue.py
│   ├── client/          # Client implementation (Phase 5)
│   │   ├── __init__.py
│   │   ├── cli.py
│   │   └── transport.py
│   └── protocol/        # Protocol buffers definitions
│       └── messages.proto
├── tests/
│   ├── unit/           # Unit tests
│   └── integration/    # Integration tests
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   └── DEVELOPMENT.md
├── requirements.txt
├── setup.py
├── pytest.ini
└── README.md
```

## Development Workflow

### Phase 1: Crypto Primitives (✅ CURRENT)

**Goal:** Implement and test wrapper around libsodium

**Files:**
- `src/crypto/primitives.py` - ✅ Complete
- `tests/unit/test_primitives.py` - ✅ Complete

**Tasks:**
- [x] X25519 key generation and DH
- [x] Ed25519 signing and verification
- [x] HKDF key derivation
- [x] ChaCha20-Poly1305 AEAD
- [x] Argon2 password hashing
- [x] Constant-time comparison
- [x] Ed25519 to X25519 conversion
- [x] Comprehensive unit tests

**Testing:**
```bash
make test-unit
```

### Phase 2: X3DH Key Agreement

**Goal:** Implement asynchronous initial key exchange

**Files to Create:**
- `src/x3dh/prekeys.py` - Prekey bundle generation
- `src/x3dh/handshake.py` - X3DH protocol implementation
- `tests/unit/test_x3dh.py` - Unit tests

**Key Components:**
1. `PrekeyBundle` class
2. `generate_prekey_bundle()` - Generate identity, signed, one-time keys
3. `x3dh_sender()` - Alice's side of handshake
4. `x3dh_receiver()` - Bob's side of handshake

**Reference:** [Signal X3DH Spec](https://signal.org/docs/specifications/x3dh/)

**Testing Requirements:**
- Verify shared secret matches on both sides
- Test with and without one-time prekey
- Verify signature validation
- Test invalid signature rejection

### Phase 3: Double Ratchet

**Goal:** Implement symmetric and DH ratcheting for message encryption

**Files to Create:**
- `src/ratchet/state.py` - Ratchet state management
- `src/ratchet/ratchet.py` - Ratchet algorithm
- `tests/unit/test_ratchet.py` - Unit tests

**Key Components:**
1. `RatchetState` class
2. `initialize_ratchet()` - Set up from X3DH shared secret
3. `ratchet_encrypt()` - Encrypt a message
4. `ratchet_decrypt()` - Decrypt a message
5. `dh_ratchet_step()` - Perform DH ratchet
6. `symmetric_ratchet()` - KDF chain step
7. `handle_skipped_keys()` - Cache keys for out-of-order messages

**Reference:** [Signal Double Ratchet Spec](https://signal.org/docs/specifications/doubleratchet/)

**Testing Requirements:**
- Test sending/receiving messages in order
- Test out-of-order message delivery
- Test skipped message handling
- Verify forward secrecy (old keys deleted)
- Test DH ratchet rotation

### Phase 4: Relay Server

**Goal:** WebSocket server for message relay

**Files to Create:**
- `src/server/main.py` - Server entry point
- `src/server/websocket.py` - WebSocket handler
- `src/server/prekey_store.py` - Prekey storage
- `src/server/message_queue.py` - Offline message queue
- `tests/integration/test_server.py` - Integration tests

**Key Components:**
1. User registration endpoint
2. Prekey upload/fetch endpoints
3. Message send/receive endpoints
4. Online presence tracking
5. Offline message queuing

**API Endpoints:**
```
POST   /register        - Register new user
POST   /prekeys/upload  - Upload prekey bundle
GET    /prekeys/:user   - Fetch user's prekey bundle
POST   /send            - Send encrypted message
WS     /connect         - WebSocket for real-time messages
```

### Phase 5: Client Implementation

**Goal:** CLI client with encrypted storage

**Files to Create:**
- `src/session/store.py` - Encrypted session storage
- `src/client/transport.py` - WebSocket client
- `src/client/cli.py` - CLI interface
- `tests/integration/test_client.py` - Integration tests

**Key Components:**
1. Session store with SQLCipher
2. Contact management
3. Message send/receive
4. Safety number display
5. Identity verification

**CLI Commands:**
```bash
securechat register <username>
securechat login <username>
securechat send <recipient> <message>
securechat verify <contact>
securechat list-contacts
```

### Phase 6: Security Hardening

**Goal:** Add security features and documentation

**Tasks:**
- Implement safety numbers (identity key fingerprints)
- Add identity key change detection
- Implement replay protection
- Add constant-time operations where needed
- Security code review
- Update threat model documentation

## Testing Guidelines

### Unit Tests

**Location:** `tests/unit/`

**Scope:** Test individual functions and classes in isolation

**Run:**
```bash
make test-unit
```

**Requirements:**
- Test normal operation
- Test edge cases
- Test error conditions
- Test with known test vectors (where available)

### Integration Tests

**Location:** `tests/integration/`

**Scope:** Test components working together

**Run:**
```bash
make test-integration
```

**Scenarios:**
- Full message flow (Alice → Server → Bob)
- Offline message delivery
- Out-of-order message handling
- Session resumption after disconnect
- Multiple concurrent clients

### Test Coverage

**Goal:** >90% coverage for crypto and protocol code

**Run:**
```bash
make coverage
```

View HTML report: `open htmlcov/index.html`

## Code Style

### Formatting

Use Black for consistent formatting:

```bash
make format
```

### Type Hints

All functions should have type hints:

```python
def x25519_dh(private_key: PrivateKey, public_key: PublicKey) -> SharedSecret:
    ...
```

Run type checking:

```bash
make type-check
```

### Documentation

All modules, classes, and functions need docstrings:

```python
def hkdf_derive(input_key_material: bytes, length: int, ...) -> bytes:
    """
    Derive key material using HKDF-SHA256.
    
    Args:
        input_key_material: Source key material
        length: Number of bytes to derive
        
    Returns:
        Derived key material
        
    Reference:
        Signal spec section X.Y
    """
```

## Security Guidelines

### DO ✅

- Use primitives from PyNaCl/cryptography only
- Follow Signal Protocol specs exactly
- Include spec section references in comments
- Use constant-time comparisons for secrets
- Delete sensitive data immediately after use
- Validate all inputs from untrusted sources
- Write comprehensive tests
- Document security assumptions

### DON'T ❌

- Implement custom crypto algorithms
- Roll your own random number generator
- Store keys in plaintext
- Log sensitive data
- Skip input validation
- Make assumptions about timing
- Copy-paste crypto code without understanding
- Commit private keys to git

## Debugging

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Inspect Ratchet State

```python
from src.ratchet import RatchetState

state = RatchetState.load(contact_id)
print(f"Send chain length: {state.message_number_send}")
print(f"Recv chain length: {state.message_number_recv}")
print(f"Skipped keys: {len(state.skipped_keys)}")
```

### Verify Keys Match

```python
# On both clients, print identity key
print(identity_key.hex())

# Should match what the other party sees
```

## Common Issues

### Issue: Tests fail with "ModuleNotFoundError"

**Solution:** Install in development mode
```bash
pip install -e .
```

### Issue: Crypto operations fail

**Solution:** Ensure libsodium is installed
```bash
# macOS
brew install libsodium

# Ubuntu
sudo apt-get install libsodium-dev

# Then reinstall PyNaCl
pip install --force-reinstall PyNaCl
```

### Issue: Database locked error

**Solution:** Ensure only one client instance per database
```bash
rm ~/.securechat/sessions.db
```

### Issue: Skipped key cache grows unbounded

**Solution:** Implement cache eviction (Phase 6)
```python
MAX_SKIPPED_KEYS = 1000
if len(skipped_keys) > MAX_SKIPPED_KEYS:
    # Evict oldest keys
```

## Performance Optimization

### Benchmarking

```bash
pytest tests/unit/test_primitives.py --benchmark
```

### Expected Performance

- X25519 DH: <1ms
- Ed25519 sign: <1ms
- ChaCha20-Poly1305 encrypt: <1ms per KB
- HKDF derive: <1ms
- Full message encrypt/decrypt: <5ms

## Contributing

### Before Committing

```bash
make format      # Format code
make lint        # Check formatting
make type-check  # Type checking
make test        # All tests pass
```

### Commit Messages

Follow conventional commits:

```
feat(crypto): add HKDF key derivation
fix(ratchet): handle skipped message keys correctly
docs(architecture): update Double Ratchet diagram
test(x3dh): add test vectors from spec
```

### Pull Request Checklist

- [ ] Tests pass
- [ ] Code formatted with Black
- [ ] Type hints added
- [ ] Docstrings updated
- [ ] No sensitive data in commits
- [ ] Architecture docs updated if needed

## Release Process

### Version Numbering

- v0.x.x - Development (pre-release)
- v1.0.0 - First stable release (after security audit)

### Before v1.0.0

- [ ] Complete all phases 1-6
- [ ] 100% pass on known test vectors
- [ ] Code review by cryptography expert
- [ ] External security audit
- [ ] Threat model reviewed
- [ ] Documentation complete

## Resources

### Specifications
- [Signal X3DH](https://signal.org/docs/specifications/x3dh/)
- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)

### Reference Implementations
- [libsignal](https://github.com/signalapp/libsignal) - Official Signal implementation

### Cryptography Resources
- [PyNaCl Documentation](https://pynacl.readthedocs.io/)
- [Cryptography.io](https://cryptography.io/)
- [libsodium Documentation](https://doc.libsodium.org/)

### Papers
- "The Double Ratchet Algorithm" - Signal
- "The X3DH Key Agreement Protocol" - Signal
- "Security Analysis of the Signal Protocol" - Various academics

## Support

For questions or issues:
1. Check this development guide
2. Review the architecture documentation
3. Read the Signal Protocol specifications
4. Open an issue on GitHub

## License

MIT License - See LICENSE file for details.

**⚠️ Educational Implementation Warning:**
This is an educational project. Do not use for protecting sensitive communications without a professional security audit.
