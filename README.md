# SecureChat

End-to-End Encrypted Messaging Application implementing the Signal Protocol (X3DH + Double Ratchet).

## Overview

SecureChat is an educational and functional implementation of the Signal Protocol for secure messaging. It provides:

- **End-to-End Encryption**: The server cannot read message content
- **Forward Secrecy**: Compromise of long-term keys doesn't expose past conversations
- **Post-Compromise Security**: Sessions can self-heal after key compromise
- **Authenticity Verification**: Cryptographic safety numbers to verify contacts

## Architecture

### Components

1. **Crypto Primitives Layer** (`src/crypto/`)
   - Wrappers around libsodium (via PyNaCl)
   - X25519 (ECDH), Ed25519 (signatures), HKDF, ChaCha20-Poly1305 (AEAD), Argon2

2. **X3DH Module** (`src/x3dh/`)
   - Asynchronous key agreement protocol
   - Prekey bundle generation and verification

3. **Double Ratchet Module** (`src/ratchet/`)
   - Symmetric-key ratchet (KDF chains)
   - DH ratchet (root key rotation)
   - Skipped message key handling

4. **Session Store** (`src/session/`)
   - Encrypted local persistence of ratchet state
   - SQLite with per-user encryption

5. **Server** (`src/server/`)
   - WebSocket relay for ciphertext
   - Prekey bundle storage
   - Message queue for offline delivery

6. **Client** (`src/client/`)
   - CLI chat interface
   - WebSocket transport
   - Contact management and verification

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Start the relay server
```bash
python -m src.server.main
```

### Run a client
```bash
python -m src.client.cli --username alice
```

## Security Model

### Protected Against
- Passive network eavesdropping
- Malicious/compromised server operators
- Key compromise (forward and future secrecy)
- Message tampering
- Basic replay attacks

### Out of Scope (v1)
- Metadata privacy (traffic analysis)
- Endpoint compromise (device malware)
- Group messaging (deferred to v2)
- Multi-device support (deferred to v2)

## Development Phases

- [x] Phase 1: Crypto primitives wrapper
- [ ] Phase 2: X3DH implementation
- [ ] Phase 3: Double Ratchet implementation
- [ ] Phase 4: Relay server
- [ ] Phase 5: Client implementation
- [ ] Phase 6: Security hardening

## References

- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [libsignal Reference Implementation](https://github.com/signalapp/libsignal)

## License

MIT License - Educational purposes. Not audited for production use.

## Warning

⚠️ **This is an educational implementation.** While it follows the Signal Protocol specifications carefully, it has not undergone professional security audit. Do not use for protecting sensitive communications without proper review.
