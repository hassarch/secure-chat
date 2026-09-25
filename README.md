# SecureChat

**End-to-End Encrypted Messaging with the Signal Protocol**

[![Status](https://img.shields.io/badge/Status-Complete-brightgreen)]()
[![Tests](https://img.shields.io/badge/Tests-123%2B%20Passing-success)]()
[![Coverage](https://img.shields.io/badge/Coverage-95%25-brightgreen)]()
[![Phase](https://img.shields.io/badge/Phase-6%2F6%20Complete-blue)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 📋 Overview

SecureChat is a **complete, educational implementation** of the Signal Protocol (X3DH + Double Ratchet) for end-to-end encrypted messaging. All 6 development phases are complete, with comprehensive testing and production-ready documentation.

### Key Features

✅ **End-to-End Encryption** - Server cannot read message content  
✅ **Forward Secrecy** - Past messages stay secure even if keys are compromised  
✅ **Post-Compromise Security** - Sessions self-heal after key compromise  
✅ **Safety Numbers** - Verify contact identities to detect MITM attacks  
✅ **Offline Messaging** - Messages delivered when recipient comes online  
✅ **No Custom Crypto** - All primitives from libsodium (vetted library)

### Project Statistics

- **📦 20 source files** (~4,500 lines of implementation)
- **✅ 123+ tests** with 95% coverage
- **📚 13+ documentation files** (~20,000 words)
- **🔒 150+ item security audit checklist**
- **✨ Production deployment guide included**

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- Virtual environment (recommended)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/securechat.git
cd securechat

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install -e .
```

### Running SecureChat

**Terminal 1: Start Server**
```bash
python -m src.server.main
# Server starts on ws://localhost:8000
```

**Terminal 2: Register and Run Bob**
```bash
securechat --user bob register bob --password bob_password
securechat --user bob listen --password bob_password
```

**Terminal 3: Register and Send from Alice**
```bash
securechat --user alice register alice --password alice_password
securechat --user alice send bob "Hello Bob!" --password alice_password
```

Bob will see: `[alice]: Hello Bob!`

### CLI Commands

```bash
# User management
securechat register <username> --password <pass>
securechat login <username> --password <pass>

# Messaging
securechat send <recipient> <message> --password <pass>
securechat receive --password <pass>
securechat listen --password <pass>  # Continuous mode

# Contacts
securechat contacts list --password <pass>
securechat contacts verify <contact> <safety-number> --password <pass>

# Session management
securechat session delete <contact> --password <pass>
securechat status --password <pass>
```

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Interface                        │
│           (register, send, receive, verify)              │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Session Manager                         │
│        (X3DH handshake + Double Ratchet)                │
└────────┬───────────────────────────────┬────────────────┘
         │                               │
┌────────▼──────────┐         ┌─────────▼────────────────┐
│  Storage Layer    │         │   Transport Layer        │
│  (Encrypted DB)   │         │   (WebSocket Client)     │
└───────────────────┘         └──────────┬───────────────┘
                                          │
                              ┌───────────▼───────────────┐
                              │    Relay Server           │
                              │  (WebSocket + Queue)      │
                              └───────────────────────────┘
```

### Phase Breakdown

**Phase 1: Crypto Primitives** ✅ (27 tests, 99% coverage)
- X25519, Ed25519, HKDF, ChaCha20-Poly1305, Argon2id
- File: `src/crypto/primitives.py`

**Phase 2: X3DH Key Agreement** ✅ (24 tests, 99% coverage)
- Prekey generation, signatures, handshake protocol
- Files: `src/x3dh/prekeys.py`, `src/x3dh/handshake.py`

**Phase 3: Double Ratchet** ✅ (26 tests, 95% coverage)
- KDF chains, DH ratchet, out-of-order messages
- Files: `src/ratchet/state.py`, `src/ratchet/ratchet.py`

**Phase 4: Relay Server** ✅ (19 tests, 100% DB coverage)
- WebSocket server, message queue, prekey storage
- Files: `src/server/database.py`, `src/server/handler.py`, `src/server/main.py`

**Phase 5: CLI Client** ✅ (27 tests, 90% coverage)
- Encrypted storage, WebSocket transport, session manager, CLI
- Files: `src/client/storage.py`, `src/client/transport.py`, `src/client/session.py`, `src/client/cli.py`

**Phase 6: Security & Audit** ✅ (Documentation complete)
- Security audit checklist, user guide, deployment guide
- Files: `docs/SECURITY_AUDIT_CHECKLIST.md`, `docs/SECURITY_GUIDE.md`, `docs/PRODUCTION_DEPLOYMENT.md`

## 🧪 Testing

### Run All Tests

```bash
# All unit tests
pytest tests/unit/ -v

# With coverage report
pytest tests/unit/ --cov=src --cov-report=html

# View coverage
open htmlcov/index.html
```

### Test Results

| Phase | Module | Tests | Coverage |
|-------|--------|-------|----------|
| 1 | Crypto Primitives | 27 | 99% |
| 2 | X3DH | 24 | 99% |
| 3 | Double Ratchet | 26 | 95% |
| 4 | Server Database | 19 | 100% |
| 5 | Client Storage | 27 | 90% |
| **Total** | **All Modules** | **123+** | **95%+** |

### Manual Integration Test

See `TESTING.md` for complete end-to-end testing procedures.

## 🔐 Security

### Security Properties

✅ **End-to-End Encryption** - Only sender and recipient can read messages  
✅ **Forward Secrecy** - Past messages secure even if keys compromised  
✅ **Post-Compromise Security** - DH ratchet provides healing  
✅ **Authentication** - AEAD prevents message tampering  
✅ **Deniability** - No unforgeable signatures  
✅ **Replay Protection** - Message numbering prevents replays

### What's Protected

✅ Message content (encrypted end-to-end)  
✅ Message integrity (authenticated encryption)  
✅ Identity verification (safety numbers)  
✅ Keys at rest (Argon2id + AEAD)

### What's NOT Protected

⚠️ **Metadata** - Server sees who talks to whom  
⚠️ **Device security** - Malware can read messages  
⚠️ **Screen captures** - Physical observation  
⚠️ **Contact betrayal** - Recipient can share messages

### Known Limitations

1. **No server rate limiting** (HIGH priority - documented)
2. **No server authentication** (MEDIUM priority - documented)
3. **Python memory safety** (fundamental language limitation)
4. **One-time prekeys not consumed** (TODO in session manager)

See `docs/SECURITY_GUIDE.md` for complete security documentation.

### Production Readiness: 85%

**Ready for:**
- ✅ Security audit
- ✅ Educational use
- ✅ Internal testing

**Needs before production:**
- ⚠️ Professional security audit (CRITICAL)
- ⚠️ Rate limiting implementation
- ⚠️ Server authentication
- ⚠️ Load testing

## 📚 Documentation

### User Documentation
- **README.md** - This file (quick start)
- **TESTING.md** - How to run tests
- **docs/SECURITY_GUIDE.md** - User security guide

### Technical Documentation
- **docs/ARCHITECTURE.md** - System architecture
- **docs/THREAT_MODEL.md** - Security analysis
- **docs/X3DH_SPEC_SUMMARY.md** - X3DH protocol summary
- **docs/DOUBLE_RATCHET_SPEC_SUMMARY.md** - Double Ratchet summary
- **docs/SERVER_API_SPEC.md** - Server API documentation
- **docs/CLIENT_SPEC.md** - Client architecture

### Security & Operations
- **docs/SECURITY_AUDIT_CHECKLIST.md** - 150+ audit items
- **docs/PRODUCTION_DEPLOYMENT.md** - Production deployment guide
- **docs/DEVELOPMENT.md** - Development guide

### Phase Summaries
- **PHASE_5_SUMMARY.md** - Client implementation summary
- **PHASE_6_SUMMARY.md** - Security & audit summary
- **PROJECT_STATUS.md** - Complete project status

## 🛠️ Development

### Project Structure

```
securechat/
├── src/
│   ├── crypto/         # Cryptographic primitives (Phase 1)
│   ├── x3dh/          # X3DH key agreement (Phase 2)
│   ├── ratchet/       # Double Ratchet (Phase 3)
│   ├── server/        # WebSocket server (Phase 4)
│   └── client/        # CLI client (Phase 5)
│       ├── storage.py    # Encrypted storage
│       ├── transport.py  # WebSocket client
│       ├── session.py    # Session manager
│       └── cli.py        # CLI interface
├── tests/
│   ├── unit/          # Unit tests (123+ tests)
│   └── integration/   # Integration tests
├── docs/              # Documentation (13+ files)
└── [config files]
```

### Dependencies

**Core:**
- PyNaCl 1.5.0 (libsodium bindings)
- cryptography 41.0.7 (additional crypto)
- websockets 12.0 (WebSocket support)

**Development:**
- pytest 7.4.3 (testing)
- pytest-cov 7.1.0 (coverage)

See `requirements.txt` for complete list.


## 🤝 Contributing

This is an educational project. Contributions welcome for:
- Bug fixes
- Test improvements
- Documentation enhancements
- Security reviews

**Please note:** Any cryptographic changes require extensive review.

## 📖 References

### Signal Protocol Specifications
- [X3DH Specification](https://signal.org/docs/specifications/x3dh/) - Extended Triple Diffie-Hellman
- [Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/) - Message encryption

### Implementations
- [libsignal](https://github.com/signalapp/libsignal) - Official Signal Protocol library
- [PyNaCl](https://pynacl.readthedocs.io/) - Python bindings to libsodium

### Cryptographic Standards
- **NIST SP 800-56A Rev. 3** - X25519 DH
- **FIPS 186-4** - Ed25519 signatures
- **RFC 8439** - ChaCha20-Poly1305
- **RFC 9106** - Argon2

## 📋 Roadmap

### Completed ✅
- Core cryptographic protocol (Phases 1-3)
- Relay server with offline messages (Phase 4)
- CLI client with encrypted storage (Phase 5)
- Security documentation and audit prep (Phase 6)

### Future Enhancements 📋
- Multi-device support (Sesame protocol)
- Group messaging (Sender Keys)
- File attachments
- GUI client (Electron or native)
- Mobile apps (iOS/Android)
- QR code verification
- Disappearing messages

### Before Production ⚠️
1. Professional security audit ($15k-50k, 4-6 weeks)
2. Implement rate limiting (HIGH priority)
3. Add server authentication (HIGH priority)
4. Load testing (1000+ concurrent users)
5. Penetration testing
6. Legal review (ToS, Privacy Policy)

**Timeline to Production:** 2-3 months after audit

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

**Educational Implementation** - Not audited for production use.

## ⚠️ Important Disclaimer

**THIS IS AN EDUCATIONAL IMPLEMENTATION**

While SecureChat follows Signal Protocol specifications carefully and uses well-tested cryptographic libraries (libsodium), it has **NOT** undergone professional security audit.

### DO NOT USE FOR:
- ❌ Protecting lives of at-risk individuals
- ❌ Evading surveillance in hostile jurisdictions
- ❌ Life-or-death situations
- ❌ Any scenario where failure causes serious harm

### For Production Security, Use:
- ✅ [Signal](https://signal.org) - Audited, mature
- ✅ [WhatsApp](https://whatsapp.com) - Signal Protocol
- ✅ Other professionally audited implementations

### SecureChat is Suitable For:
- ✅ Learning cryptographic protocols
- ✅ Understanding Signal Protocol
- ✅ Security course projects
- ✅ Internal testing (low-risk)
- ✅ Code review and study

---

**Made with ❤️ for educational purposes**

**Questions?** See documentation in `docs/` or open an issue.

**Security Concerns?** Email: security@securechat.example.com (see `docs/SECURITY_GUIDE.md`)
