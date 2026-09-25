# SecureChat Security Guide

**Version:** 1.0  
**Last Updated:** September 25, 2026  
**Audience:** End Users

## Introduction

SecureChat uses the Signal Protocol to provide end-to-end encryption for your messages. This guide explains how SecureChat protects your privacy and what you need to do to stay secure.

---

## What SecureChat Protects

### ✅ Messages Are Encrypted End-to-End

**What this means:**
- Only you and your intended recipient can read messages
- Not even the SecureChat server can decrypt your messages
- Messages are encrypted before leaving your device
- They stay encrypted until they reach your recipient

**Technical details:**
- Uses X3DH for initial key agreement
- Uses Double Ratchet for message encryption
- Each message has a unique encryption key
- Keys are automatically rotated

### ✅ Forward Secrecy

**What this means:**
- If someone steals your keys today, they cannot decrypt past messages
- Message keys are deleted immediately after use
- Each message is independent

**Why it matters:**
- Even if your device is compromised, past conversations remain secure
- No single key can decrypt all your messages

### ✅ Post-Compromise Security

**What this means:**
- If your keys are stolen, future messages become secure again after a few exchanges
- The protocol "heals" itself through key rotation

**Why it matters:**
- Temporary compromises don't permanently break security
- Continues providing protection after recovery

### ✅ Deniability

**What this means:**
- You can plausibly deny sending a message
- Messages don't have unforgeable signatures
- Similar to a face-to-face conversation

**Why it matters:**
- No one can cryptographically prove you sent a specific message
- Protects against coercion

---

## What SecureChat Does NOT Protect

### ⚠️ Who You Talk To (Metadata)

**What this means:**
- The server knows which users are communicating
- Connection times and message frequency are visible
- IP addresses may be logged

**Mitigation:**
- Use a VPN or Tor for additional privacy
- Be aware that "who talks to whom" is not hidden

### ⚠️ Your Device Security

**What this means:**
- If someone has access to your unlocked device, they can read messages
- Malware on your device can capture messages
- Physical security is your responsibility

**Mitigation:**
- Use strong device passwords/PINs
- Keep your device updated
- Don't install untrusted apps
- Lock your device when not in use

### ⚠️ Screen Captures or Photos

**What this means:**
- Anyone can screenshot or photograph your screen
- Encryption doesn't prevent visual capture

**Mitigation:**
- Be aware of your surroundings when using SecureChat
- Consider who might see your screen

### ⚠️ The Other Person

**What this means:**
- Your recipient can save, screenshot, or forward messages
- There's no technical way to prevent this

**Mitigation:**
- Only share sensitive information with people you trust
- Assume anything you send could be shared

---

## How to Stay Secure

### 1. Choose a Strong Password

Your password protects all your keys on this device.

**Requirements:**
- At least 12 characters (longer is better)
- Mix uppercase, lowercase, numbers, symbols
- Don't reuse passwords from other services
- Don't use personal information (birthdays, names)

**Good password:**
```
Correct-Horse-Battery-Staple-9!
```

**Bad password:**
```
password123
yourname1990
```

**Why it matters:**
- Your password is the only thing protecting your stored keys
- A weak password can be cracked in seconds
- A strong password takes millions of years to crack

### 2. Verify Safety Numbers

Safety numbers let you verify you're talking to the right person and detect man-in-the-middle attacks.

**What is a safety number?**
- A 15-digit number derived from both users' identity keys
- Both users see the same number for each other
- Changes if identity keys change

**How to verify:**

1. **In person (most secure):**
   ```bash
   # Alice runs:
   securechat --user alice contacts list --password pass
   # Shows: Safety number: 12345 67890 12345

   # Bob runs:
   securechat --user bob contacts list --password pass
   # Shows: Safety number: 12345 67890 12345

   # Compare out loud - they should match!
   ```

2. **Over a trusted channel (secure):**
   - Read numbers to each other over a phone call
   - Compare via video chat where you can see each other

3. **Mark as verified:**
   ```bash
   securechat --user alice contacts verify bob "12345 67890 12345" --password pass
   ```

**When to verify:**
- When starting a conversation with someone important
- Periodically for high-security contacts
- If you see a "key changed" warning (future feature)

**Why it matters:**
- Detects man-in-the-middle attacks
- Confirms you're really talking to who you think
- Should be done for all sensitive conversations

### 3. Protect Your Device

**Physical security:**
- Lock your device with a PIN/password
- Don't leave it unattended while unlocked
- Enable full-disk encryption if available

**Software security:**
- Keep your operating system updated
- Only install software from trusted sources
- Use antivirus/anti-malware (especially on Windows)
- Don't root/jailbreak your device (weakens security)

**Network security:**
- Use a VPN when on public WiFi
- Don't use untrusted computers for SecureChat
- Be careful on shared/work networks

### 4. Manage Your Sessions

**Delete old sessions:**
If you think a session might be compromised:
```bash
securechat --user alice session delete bob --password pass
```

Then send a new message to establish a fresh session.

**Why it matters:**
- Forces new key agreement
- Removes potentially compromised keys
- Fresh start with post-compromise security

**When to delete:**
- If you suspect your device was compromised
- If you lost your device temporarily
- If you want extra assurance

### 5. Handle Identity Key Changes

**Future feature:** SecureChat will warn you if a contact's identity key changes.

**What this means:**
- They might have gotten a new device
- They might have reinstalled SecureChat
- **Or:** Someone might be intercepting your messages

**What to do:**
1. Contact them through another channel (phone, in person)
2. Ask if they got a new device or reinstalled
3. Verify safety numbers again
4. If something seems suspicious, stop communicating until resolved

### 6. Backup Your Identity

⚠️ **Important:** If you forget your password or lose your database file, you lose your identity keys forever.

**What to backup:**
- Your username
- Your password (stored securely!)
- Your database file: `~/.securechat/<username>.db`

**How to backup safely:**
- Use encrypted backup (e.g., encrypted USB drive)
- Store password separately (password manager or paper)
- Keep backup in a secure location

**What NOT to do:**
- Don't email your database or password
- Don't store unencrypted on cloud storage
- Don't write password on sticky notes

---

## Common Security Questions

### Q: Can the server read my messages?
**A:** No. Messages are encrypted on your device before being sent. The server only sees encrypted data.

### Q: Can SecureChat employees read my messages?
**A:** No. Even if they wanted to, they cannot decrypt your messages. Only you and your recipient have the keys.

### Q: What if the server gets hacked?
**A:** Attackers would see encrypted messages and identity keys (public keys). They cannot decrypt messages or impersonate users (unless they also compromised user devices).

### Q: What if my device gets hacked?
**A:** If malware is on your device, it could read messages before encryption or after decryption. This is why device security is critical.

### Q: Can my internet provider see my messages?
**A:** They can see you're using SecureChat but cannot see message content. They can see connection times and message sizes (metadata).

### Q: Is SecureChat legal to use?
**A:** Using encryption is legal in most countries, but check your local laws. Some countries restrict or ban encryption.

### Q: Can SecureChat be subpoenaed?
**A:** The server could be subpoenaed, but it only stores encrypted messages and metadata (who talked to whom). No plaintext messages exist on the server.

### Q: What if I'm forced to give up my password?
**A:** This is called "rubber-hose cryptography" and no technical solution exists. Consider the legal and personal risks in your jurisdiction.

### Q: Does SecureChat hide my IP address?
**A:** No. Use a VPN or Tor if IP privacy is important.

---

## Threat Scenarios

### Scenario 1: Passive Eavesdropper

**Threat:** Someone monitoring network traffic (ISP, government, hacker on public WiFi)

**Protection:**
- ✅ **Fully protected:** Messages are encrypted end-to-end
- ✅ **Transport encryption:** Use wss:// (WebSocket Secure)
- ⚠️ **Metadata visible:** They can see who you talk to

**Your action:**
- Use SecureChat normally
- Consider VPN for metadata protection

### Scenario 2: Active Man-in-the-Middle

**Threat:** Someone intercepting and potentially modifying messages

**Protection:**
- ✅ **Detection:** Safety numbers will differ
- ✅ **Prevention:** Verify safety numbers
- ⚠️ **Risk:** Vulnerable if you don't verify

**Your action:**
- Always verify safety numbers for important contacts
- Use a trusted channel for verification (in person, phone call)

### Scenario 3: Compromised Server

**Threat:** Server is hacked or operated by adversary

**Protection:**
- ✅ **Messages safe:** Server cannot decrypt
- ✅ **Identity keys safe:** Only public keys stored
- ⚠️ **Metadata exposed:** Who talks to whom visible
- ⚠️ **MITM possible:** Server could inject fake keys (detected by safety numbers)

**Your action:**
- Verify safety numbers
- Be aware metadata is not protected

### Scenario 4: Stolen Device (Locked)

**Threat:** Physical device theft while locked

**Protection:**
- ✅ **Keys protected:** Encrypted database
- ✅ **Strong password:** Makes brute-force difficult
- ⚠️ **Not bulletproof:** Given enough time, could be cracked

**Your action:**
- Use strong password (12+ characters)
- Enable full-disk encryption
- Remote wipe if possible (future feature)

### Scenario 5: Stolen Device (Unlocked)

**Threat:** Device stolen while SecureChat is running

**Protection:**
- ❌ **Not protected:** Attacker has full access
- ❌ **Messages readable:** Database is decrypted

**Your action:**
- Lock device when not in use
- Enable auto-lock timeout
- Contact server admin to revoke identity (future feature)

### Scenario 6: Malware on Device

**Threat:** Malware/spyware installed on your device

**Protection:**
- ❌ **Not protected:** Malware can read everything
- ❌ **Keylogging:** Can capture password
- ❌ **Screen capture:** Can record messages

**Your action:**
- Use antivirus software
- Only install trusted applications
- Keep OS updated
- Consider separate device for sensitive communications

### Scenario 7: Compromised Contact

**Threat:** The person you're talking to is compromised or malicious

**Protection:**
- ❌ **Not protected:** They have the keys
- ❌ **Can share:** They can forward messages
- ❌ **Can screenshot:** Technical protection impossible

**Your action:**
- Only share sensitive information with trusted contacts
- Assume anything you send could become public
- Use disappearing messages (future feature)

---

## Best Practices Summary

### Essential (Do These)
1. ✅ Use a strong, unique password (12+ characters)
2. ✅ Verify safety numbers for important contacts
3. ✅ Lock your device with a PIN/password
4. ✅ Keep your software updated
5. ✅ Backup your identity safely

### Recommended (Should Do)
1. ✅ Use VPN on public WiFi
2. ✅ Verify safety numbers periodically
3. ✅ Enable full-disk encryption
4. ✅ Use antivirus software
5. ✅ Be aware of your surroundings when using SecureChat

### Advanced (Extra Protection)
1. ✅ Use Tor for IP privacy
2. ✅ Use a dedicated device for sensitive communications
3. ✅ Verify safety numbers in person for critical contacts
4. ✅ Delete sessions periodically
5. ✅ Consider operational security (when/where you communicate)

### Never Do
1. ❌ Reuse passwords
2. ❌ Share your password
3. ❌ Leave device unlocked in public
4. ❌ Install untrusted software
5. ❌ Send sensitive info to unverified contacts

---

## Technical Security Details

### Cryptographic Algorithms

**Identity Keys:**
- Algorithm: Ed25519 (elliptic curve signatures)
- Key size: 256 bits
- Use: Sign prekeys, verify identities

**Message Encryption:**
- Algorithm: XChaCha20-Poly1305 (AEAD)
- Key size: 256 bits
- Nonce size: 192 bits (collision-resistant)
- Use: Encrypt each individual message

**Key Agreement:**
- Algorithm: X25519 (elliptic curve DH)
- Security level: ~128 bits
- Use: Establish shared secrets

**Key Derivation:**
- Algorithm: HKDF-SHA256
- Use: Derive message keys from chain keys

**Password Storage:**
- Algorithm: Argon2id
- Parameters: ops=3, mem=64MB (OWASP moderate)
- Salt: 16 bytes random per database
- Use: Protect stored keys with password

### Protocol Specifications

SecureChat implements:
- **X3DH:** Extended Triple Diffie-Hellman for initial key agreement
- **Double Ratchet:** Continuous key rotation for forward secrecy

These are the same protocols used by Signal, WhatsApp, and Facebook Messenger.

**References:**
- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)

---

## Getting Help

### Security Issue?
**DO NOT** report security issues publicly.

**Instead:**
- Email: security@securechat.example.com
- PGP Key: [Key ID]
- Response time: 48 hours

### General Questions?
- Documentation: `docs/` folder
- Issues: GitHub Issues
- Community: [Forum/Discord]

### Suspicious Activity?
If you suspect:
- Your account is compromised
- Someone is impersonating you
- A man-in-the-middle attack

**Do this:**
1. Stop using that account immediately
2. Verify safety numbers with all contacts
3. Report to security team
4. Create new identity if needed

---

## Security Checklist

Use this checklist to ensure you're following best practices:

### Initial Setup
- [ ] Generated identity with strong password (12+ chars)
- [ ] Backed up username and password safely
- [ ] Device has PIN/password lock
- [ ] Device has full-disk encryption

### Before First Message to Important Contact
- [ ] Verified safety number via trusted channel
- [ ] Marked contact as verified
- [ ] Confirmed they also verified your safety number

### Regular Maintenance
- [ ] Review contacts list monthly
- [ ] Delete unused sessions
- [ ] Check for software updates
- [ ] Verify backup is still accessible

### When Security Matters Most
- [ ] Meet in person to verify safety numbers
- [ ] Use VPN or Tor
- [ ] Use dedicated device
- [ ] Be aware of surroundings
- [ ] Consider operational security

---

## Frequently Asked Questions

### General

**Q: Is SecureChat as secure as Signal?**
A: SecureChat uses the same protocols, but Signal is more mature and has been audited more extensively. For maximum security, use Signal.

**Q: Is SecureChat open source?**
A: Yes, the code is available for review. This is important for security auditing.

**Q: Has SecureChat been audited?**
A: This is an educational implementation. Professional security audit is planned but not yet complete.

### Technical

**Q: What happens if I lose my password?**
A: You lose access to your identity forever. There is no password recovery. This is by design for security.

**Q: Can I use SecureChat on multiple devices?**
A: Not currently. Multi-device support is a future feature (requires additional protocol).

**Q: How are messages stored?**
A: Messages are stored encrypted on the server temporarily (for offline delivery) and then deleted. They are NOT stored on your device by default.

**Q: Can I export my message history?**
A: Not currently. Message persistence is a future feature.

### Privacy

**Q: What data does SecureChat collect?**
A: The server sees: your username, when you're online, who you message (but not the content), and your IP address.

**Q: Can I use SecureChat anonymously?**
A: Somewhat. Use a pseudonym and VPN/Tor. However, behavior patterns can still identify you.

**Q: Does SecureChat comply with GDPR/Privacy laws?**
A: This is an educational project. Production deployment would need legal review and compliance measures.

---

## Disclaimer

⚠️ **IMPORTANT**

SecureChat is an **educational implementation** of the Signal Protocol. While it follows the specifications carefully and uses well-tested cryptographic libraries, it has not yet undergone professional security audit.

**DO NOT use for:**
- Life-or-death situations
- Protecting lives of at-risk individuals
- Evading government surveillance in hostile jurisdictions
- Anything where failure could cause serious harm

**For production security needs, use:**
- Signal (signal.org)
- WhatsApp (with E2EE)
- Other audited, mature implementations

SecureChat is provided as-is for educational purposes. The developers make no warranties about security, correctness, or fitness for any purpose.

---

**Last Updated:** September 25, 2026  
**Version:** 1.0  
**For technical details, see:** `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md`
