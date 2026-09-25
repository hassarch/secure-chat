# SecureChat Testing Guide

This document describes how to test SecureChat at various levels.

## Quick Start

```bash
# Install in development mode
pip install -e .

# Run all unit tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Unit Tests

### Phase 1: Cryptographic Primitives (27 tests)
```bash
pytest tests/unit/test_primitives.py -v
```

Tests all crypto wrappers: X25519, Ed25519, HKDF, AEAD, Argon2.

### Phase 2: X3DH Key Agreement (24 tests)
```bash
pytest tests/unit/test_x3dh.py -v
```

Tests prekey generation, signatures, and handshake protocol.

### Phase 3: Double Ratchet (26 tests)
```bash
pytest tests/unit/test_ratchet.py -v
```

Tests symmetric ratchet, DH ratchet, out-of-order messages.

### Phase 4: Server Database (19 tests)
```bash
pytest tests/unit/test_server_database.py -v
```

Tests user registration, prekey storage, message queue.

### Phase 5: Client Storage (27 tests)
```bash
pytest tests/unit/test_client_storage.py -v
```

Tests encrypted storage, session persistence, contact management.

**Note:** Storage tests are slow (~2 minutes) due to Argon2id password derivation. This is expected and ensures security.

## Integration Testing

### Manual End-to-End Test

**Terminal 1: Start Server**
```bash
python -m src.server.main
```

**Terminal 2: Register and Run Bob**
```bash
# Register Bob
securechat --user bob register bob --password bob_password_123

# Bob listens for messages
securechat --user bob listen --password bob_password_123
```

**Terminal 3: Register and Send from Alice**
```bash
# Register Alice
securechat --user alice register alice --password alice_password_123

# Send message to Bob
securechat --user alice send bob "Hello Bob!" --password alice_password_123
```

You should see:
- Server logs the connection and message relay
- Bob receives and displays: `[alice]: Hello Bob!`
- Alice confirms: `✓ Message sent to bob`

### Verify Safety Numbers

**Terminal 1 (Bob):**
```bash
securechat --user bob contacts list --password bob_password_123
# Copy safety number shown for Alice
```

**Terminal 2 (Alice):**
```bash
securechat --user alice contacts list --password alice_password_123
# Verify both show the same safety number
```

**Verify Identity:**
```bash
securechat --user alice contacts verify bob "12345 67890 12345" --password alice_password_123
```

## Test Coverage Analysis

### Current Coverage (by Phase)

| Phase | Module | Tests | Coverage |
|-------|--------|-------|----------|
| 1 | Crypto Primitives | 27 | 99% |
| 2 | X3DH | 24 | 99% |
| 3 | Double Ratchet | 26 | 95% |
| 4 | Server Database | 19 | 100% |
| 5 | Client Storage | 27 | ~90% |

**Total: 123+ tests**

### Running Coverage Reports

```bash
# Generate coverage for specific module
pytest tests/unit/test_primitives.py --cov=src.crypto.primitives --cov-report=term-missing

# Full coverage
pytest tests/unit/ --cov=src --cov-report=html --cov-report=term

# Coverage with branch analysis
pytest tests/unit/ --cov=src --cov-branch --cov-report=html
```

## Performance Testing

### Cryptographic Operations
```bash
# Time primitive operations
python -m pytest tests/unit/test_primitives.py -v --durations=10
```

Expected timings:
- X25519 DH: <1ms
- Ed25519 sign: <1ms
- AEAD encrypt: <1ms
- Argon2id (moderate): 50-100ms per operation

### Storage Operations
```bash
# Time storage tests (slow due to Argon2)
python -m pytest tests/unit/test_client_storage.py -v --durations=10
```

Expected timings:
- Database init: 50-100ms (Argon2 derivation)
- Save/load session: <10ms
- Contact operations: <5ms

### Message Throughput

Manual test for message rate:
```bash
# Send 100 messages
for i in {1..100}; do
  securechat --user alice send bob "Message $i" --password alice_password_123
done
```

Expected: 10-50 messages/second depending on network

## Security Testing

### Test Threat Scenarios

**1. Wrong Password**
```bash
# Try to login with wrong password (should fail)
securechat --user alice login alice --password wrong_password
```

**2. Identity Verification**
```bash
# Try to verify with wrong safety number
securechat --user alice contacts verify bob "00000 00000 00000" --password alice_password_123
# Should show: "Safety number mismatch! WARNING: MITM attack"
```

**3. Session Deletion**
```bash
# Delete and reinitialize session
securechat --user alice session delete bob --password alice_password_123
securechat --user alice send bob "New session" --password alice_password_123
```

### Encryption Verification

Check that private keys are encrypted at rest:
```bash
# Dump database (should see encrypted blobs, not plaintext keys)
sqlite3 ~/.securechat/alice.db "SELECT hex(identity_private_key) FROM identity LIMIT 1;"
```

Output should be long hex string (encrypted), not a 64-char Ed25519 private key.

## Debugging Tests

### Verbose Output
```bash
pytest tests/unit/test_x3dh.py -v -s
```

### Stop on First Failure
```bash
pytest tests/unit/ -x
```

### Run Specific Test
```bash
pytest tests/unit/test_primitives.py::TestX25519::test_key_exchange -v
```

### Enable Debug Logging
```bash
pytest tests/unit/test_ratchet.py -v -s --log-cli-level=DEBUG
```

## Continuous Integration

### Pre-commit Checks
```bash
# Run before committing
pytest tests/unit/ --cov=src --cov-report=term --cov-fail-under=90
```

### Full Test Suite
```bash
# Run everything with coverage
pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing
```

## Known Testing Limitations

1. **No Server Integration Tests**: Server handler and WebSocket logic not fully tested
2. **No Transport Tests**: Transport layer needs unit tests
3. **Manual End-to-End**: Full E2E flow requires manual testing
4. **No Concurrency Tests**: Multi-user scenarios not automated
5. **No Fuzzing**: Crypto inputs not fuzz-tested

## Future Testing Improvements

- [ ] Automated integration tests with mock server
- [ ] Property-based testing for crypto (Hypothesis)
- [ ] Fuzzing for message parsing
- [ ] Load testing for server
- [ ] Security audit test suite
- [ ] Performance benchmarks
- [ ] Memory leak detection

## Test Data

Test databases and keys are stored in:
- Unit tests: `tempfile.gettempdir()` (auto-cleaned)
- Manual testing: `~/.securechat/` (user must clean)

Clean test data:
```bash
rm -rf ~/.securechat/
```

## Troubleshooting

### Argon2 Tests Timeout
If storage tests timeout:
- This is expected (Argon2 is intentionally slow)
- Use `pytest tests/unit/test_client_storage.py::TestIdentityManagement -v` to run subset
- Or skip storage tests: `pytest tests/unit/ --ignore=tests/unit/test_client_storage.py`

### Server Connection Failed
If integration tests fail with connection error:
- Ensure server is running: `python -m src.server.main`
- Check server URL: `ws://localhost:8000` (default)
- Verify no firewall blocking WebSocket connections

### Import Errors
If tests fail with import errors:
- Install in development mode: `pip install -e .`
- Check virtual environment: `which python`
- Install test dependencies: `pip install pytest pytest-cov pytest-asyncio`

---

**For security-critical testing, consult docs/THREAT_MODEL.md and engage professional security auditors.**
