# SecureChat Threat Model

## 1. Assets to Protect

### 1.1 Message Content
- Plaintext of messages exchanged between users
- The most critical asset

### 1.2 Long-term Keys
- Identity keys (Ed25519 keypairs)
- Compromise allows impersonation

### 1.3 Session State
- Current ratchet state (chain keys, root keys)
- Compromise affects ongoing conversation security

### 1.4 Metadata
- Who communicates with whom
- When messages are sent
- Message sizes and frequency

## 2. Threat Actors

### 2.1 Passive Network Attacker
**Capabilities:**
- Observe all network traffic
- Cannot modify or inject packets

**Motivation:**
- Mass surveillance
- Targeted monitoring

### 2.2 Active Network Attacker (MITM)
**Capabilities:**
- Intercept, modify, and inject network traffic
- Cannot compromise endpoints

**Motivation:**
- Intercept and modify communications
- Impersonate parties

### 2.3 Malicious Server Operator
**Capabilities:**
- Full control over relay server
- Access to all stored data
- Cannot compromise endpoints

**Motivation:**
- Read user messages
- Impersonate users

### 2.4 Opportunistic Endpoint Attacker
**Capabilities:**
- Temporary access to device (stolen, borrowed)
- Cannot extract keys from secure storage
- Can read unlocked sessions

**Motivation:**
- Read recent messages
- Impersonate user briefly

### 2.5 Advanced Endpoint Attacker
**Capabilities:**
- Malware on user's device
- Extract keys from memory
- Read all decrypted content

**Motivation:**
- Complete compromise of communications

## 3. Security Properties & Guarantees

### 3.1 End-to-End Encryption ✓
**Property:** Only intended recipients can read message content

**Threat Mitigation:**
- ✓ Passive network attacker cannot read messages
- ✓ Malicious server cannot read messages

**Mechanism:**
- X3DH establishes shared secret unknown to server
- Double Ratchet encrypts each message with unique key
- AEAD (ChaCha20-Poly1305) provides confidentiality

### 3.2 Forward Secrecy ✓
**Property:** Compromise of current keys doesn't expose past messages

**Threat Mitigation:**
- ✓ Opportunistic endpoint attacker gains limited access
- ✓ Advanced endpoint attacker (if detected/removed) doesn't expose full history

**Mechanism:**
- Message keys are deleted immediately after use
- Old chain keys are deleted after ratchet steps
- DH ratchet creates new shared secrets regularly

### 3.3 Post-Compromise Security / Future Secrecy ✓
**Property:** Session can recover from key compromise

**Threat Mitigation:**
- ✓ Opportunistic endpoint attacker's access doesn't permanently compromise session
- ✓ Advanced endpoint attacker (if removed) doesn't compromise future messages

**Mechanism:**
- DH ratchet introduces fresh randomness from both parties
- After each ratchet step, attacker without current device access loses ability to decrypt

### 3.4 Authentication ✓
**Property:** Verify you're talking to the intended party

**Threat Mitigation:**
- ✓ Active network attacker (MITM) can be detected
- ✓ Malicious server attempting impersonation can be detected

**Mechanism:**
- Long-term identity keys
- Signed prekeys prevent key substitution
- Safety numbers allow out-of-band verification

### 3.5 Message Integrity ✓
**Property:** Detect tampered messages

**Threat Mitigation:**
- ✓ Active network attacker cannot modify messages undetected
- ✓ Malicious server cannot modify messages undetected

**Mechanism:**
- AEAD authentication tag on every message
- Tampered messages fail to decrypt

### 3.6 Replay Protection ✓
**Property:** Old messages cannot be replayed

**Threat Mitigation:**
- ✓ Active network attacker cannot replay captured messages
- ✓ Malicious server cannot replay stored messages

**Mechanism:**
- Message keys are never reused
- Skipped message key cache has bounds
- Out-of-order messages beyond window are rejected

## 4. What is NOT Protected (v1)

### 4.1 Metadata (Out of Scope) ⚠️
**Not Protected:**
- Who talks to whom (sender/recipient)
- When messages are sent (timing)
- Message sizes
- Online/offline status
- IP addresses

**Implication:**
- Server and network observers can build social graph
- Traffic analysis possible

**Future Mitigation:**
- Mix networks (Tor integration)
- Cover traffic
- Message padding

### 4.2 Endpoint Compromise (Out of Scope) ⚠️
**Not Protected:**
- Malware on device can read plaintext after decryption
- Screen recorders, keyloggers
- Memory dumps

**Implication:**
- E2E encryption doesn't help against compromised devices

**Mitigation Strategy:**
- Device security is user's responsibility
- Secure enclave for keys (future)
- Remote attestation (future)

### 4.3 Denial of Service (Out of Scope) ⚠️
**Not Protected:**
- Server/network can block messages
- Spam/flooding attacks
- Resource exhaustion

**Implication:**
- Availability is not guaranteed

### 4.4 Multi-device (Deferred to v2) ⚠️
**Not Protected:**
- Synchronizing session state across devices
- Secure device linking

**Implication:**
- Each device has independent sessions

### 4.5 Group Messaging (Deferred to v2) ⚠️
**Not Protected:**
- Efficient group encryption
- Group member changes

**Implication:**
- v1 supports 1:1 only

## 5. Attack Scenarios & Analysis

### 5.1 Passive Eavesdropping
**Attack:** Network attacker captures all traffic

**Analysis:**
- ✅ Message content is encrypted
- ✅ Key agreement happens end-to-end
- ❌ Metadata visible (who, when, sizes)

**Conclusion:** Messages protected, metadata exposed

### 5.2 Malicious Relay Server
**Attack:** Server operator tries to read messages

**Analysis:**
- ✅ Server only sees ciphertext
- ✅ Server doesn't have decryption keys
- ❌ Server can see full metadata
- ❌ Server can selectively drop messages

**Conclusion:** Content protected, availability/metadata not protected

### 5.3 Man-in-the-Middle (MITM)
**Attack:** Active network attacker intercepts initial key exchange

**Analysis:**
- ⚠️ Without out-of-band verification, MITM can substitute keys
- ✅ Safety number comparison detects MITM
- ✅ Signed prekeys prevent silent key substitution
- ⚠️ Requires user diligence to compare safety numbers

**Conclusion:** Protection requires user verification

### 5.4 Compromised Prekey Bundle
**Attack:** Attacker compromises server, modifies prekey bundles

**Analysis:**
- ✅ Signed prekeys are verified against published identity key
- ✅ Attacker cannot forge signature without identity private key
- ⚠️ If attacker also compromises identity key, they can MITM

**Conclusion:** Signature verification critical, trust anchor is identity key

### 5.5 Stolen Device (Unlocked)
**Attack:** Attacker steals unlocked device

**Analysis:**
- ❌ Attacker can read message history in UI
- ❌ Attacker can send messages as victim
- ✅ Forward secrecy protects future messages (after user regains device)
- ⚠️ Depends on user locking device

**Conclusion:** Physical security critical

### 5.6 Key Compromise with Passive Eavesdropping
**Attack:** Attacker records all traffic, later compromises keys

**Analysis:**
- ✅ Past messages protected by forward secrecy
- ❌ Current and future messages compromised until next DH ratchet
- ✅ Post-compromise security restores security after ratchet steps

**Conclusion:** Limited exposure window

### 5.7 Replay Attack
**Attack:** Attacker replays captured ciphertext

**Analysis:**
- ✅ Message keys are single-use
- ✅ Skipped key cache has bounds
- ✅ Out-of-window messages rejected

**Conclusion:** Replay protected within protocol

## 6. Trust Assumptions

### 6.1 Cryptographic Primitives
**Assumption:** libsodium implementations are correct and secure

**Justification:** Industry-vetted, widely audited

**Risk:** Crypto vulnerabilities (low probability)

### 6.2 Server Honest-but-Curious
**Assumption:** Server correctly relays messages but may try to read them

**Justification:** Realistic threat model for many deployments

**Risk:** Malicious server can drop messages, expose metadata

### 6.3 Endpoint Security
**Assumption:** User's device is not compromised during key generation/use

**Justification:** Out of scope for E2E protocol

**Risk:** Endpoint malware renders E2E encryption ineffective

### 6.4 User Verification Discipline
**Assumption:** Users verify safety numbers for high-security conversations

**Justification:** Optional security upgrade

**Risk:** MITM possible if users don't verify

## 7. Security Boundaries

### Protected by Protocol
1. Message confidentiality (E2E)
2. Message authenticity (signatures + AEAD)
3. Forward secrecy (key deletion + DH ratchet)
4. Post-compromise security (DH ratchet)
5. Replay protection (message key tracking)

### Not Protected by Protocol
1. Metadata privacy
2. Endpoint security
3. Availability
4. User behavior (verification discipline)

## 8. Recommendations

### For Users
1. ✅ Always verify safety numbers with new contacts
2. ✅ Monitor for identity key changes
3. ✅ Lock device when not in use
4. ✅ Keep software updated
5. ⚠️ Be aware metadata is not protected

### For Operators
1. ✅ Use TLS for defense-in-depth
2. ✅ Minimize server logs
3. ✅ Implement rate limiting
4. ⚠️ Consider metadata minimization strategies
5. ⚠️ Be transparent about what data is collected

### For Developers
1. ✅ Never implement custom crypto
2. ✅ Follow spec exactly
3. ✅ Write comprehensive tests
4. ✅ Code review all crypto code
5. ✅ Consider professional security audit before production use

## 9. Version History

- v1.0 (2026-09-25): Initial threat model for SecureChat v1
