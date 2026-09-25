# X3DH Protocol Implementation Summary

## Overview

X3DH (Extended Triple Diffie-Hellman) is an asynchronous key agreement protocol that allows two parties to establish a shared secret without requiring both to be online simultaneously.

## Protocol Roles

- **Alice**: The initiator who wants to send the first message
- **Bob**: The receiver who has published prekeys to the server
- **Server**: Stores and distributes prekey bundles (untrusted)

## Key Types

### Identity Key (IK)
- **Type**: Ed25519 keypair (can be converted to X25519 for DH)
- **Lifetime**: Long-term (months to years)
- **Purpose**: Provides authentication, forms user's cryptographic identity
- **Signed**: No (root of trust)

### Signed Prekey (SPK)
- **Type**: X25519 keypair
- **Lifetime**: Medium-term (rotated weekly/monthly)
- **Purpose**: Provides forward secrecy even if one-time prekeys exhausted
- **Signed**: Yes, by identity key

### One-Time Prekey (OPK)
- **Type**: X25519 keypair
- **Lifetime**: Single use
- **Purpose**: Provides forward secrecy from first message
- **Signed**: No (covered by SPK signature)

## Bob's Setup (Prekey Bundle Generation)

```
1. Generate identity key IK_b (Ed25519)
2. Generate signed prekey SPK_b (X25519)
3. Sign SPK_b with IK_b: Sig(IK_b, Encode(SPK_b))
4. Generate many one-time prekeys OPK_b1, OPK_b2, ... (X25519)
5. Upload to server: {IK_b, SPK_b, Sig(SPK_b), [OPK_b1, OPK_b2, ...]}
```

## Alice Initiates (X3DH Handshake)

```
1. Fetch Bob's prekey bundle from server
2. Verify signature: Verify(IK_b, SPK_b, Sig(SPK_b))
   - If verification fails: ABORT (potential MITM)
3. Generate ephemeral key EK_a (X25519)
4. Perform 4 DH operations:
   - DH1 = DH(IK_a, SPK_b)
   - DH2 = DH(EK_a, IK_b)
   - DH3 = DH(EK_a, SPK_b)
   - DH4 = DH(EK_a, OPK_b)  [if OPK available]
5. Derive shared secret:
   - SK = HKDF(DH1 || DH2 || DH3 || DH4, salt="SecureChat-X3DH")
6. Associate data: AD = Encode(IK_a) || Encode(IK_b)
7. Send initial message: {IK_a, EK_a, OPK_b_id, ciphertext}
```

## Bob Receives (Complete Handshake)

```
1. Receive: {IK_a, EK_a, OPK_b_id, ciphertext}
2. Lookup OPK_b from OPK_b_id (if present)
3. Perform same 4 DH operations:
   - DH1 = DH(SPK_b, IK_a)
   - DH2 = DH(IK_b, EK_a)
   - DH3 = DH(SPK_b, EK_a)
   - DH4 = DH(OPK_b, EK_a)  [if OPK was used]
4. Derive same shared secret:
   - SK = HKDF(DH1 || DH2 || DH3 || DH4, salt="SecureChat-X3DH")
5. Verify AD matches: AD = Encode(IK_a) || Encode(IK_b)
6. Delete used OPK_b
7. Decrypt initial message
```

## Security Properties

### Forward Secrecy
- ✅ **With OPK**: Full forward secrecy from first message
  - Compromise of long-term keys doesn't expose past sessions
  - OPK_b is deleted after use
- ⚠️ **Without OPK**: Forward secrecy after first response
  - First message vulnerable if IK + SPK compromised
  - Subsequent messages protected by Double Ratchet

### Authentication
- ✅ Alice verifies Bob's SPK signature
- ✅ Mutual authentication via DH with identity keys
- ⚠️ Requires out-of-band verification of IK_b to prevent MITM

### Deniability
- ✅ Alice can deny sending first message
  - No signature from Alice
  - Bob can't prove message origin to third party

## Implementation Notes

### DH Key Compatibility
- Identity keys are Ed25519 (signing)
- Need to convert to X25519 (DH) for key agreement
- Use `convert_ed25519_to_x25519_*()` functions

### DH Operation Order
The DH outputs must be combined in the correct order:
```
DH1 = DH(IK_sender, SPK_receiver)    # Identity ⇄ Signed
DH2 = DH(EK_sender, IK_receiver)     # Ephemeral ⇄ Identity  
DH3 = DH(EK_sender, SPK_receiver)    # Ephemeral ⇄ Signed
DH4 = DH(EK_sender, OPK_receiver)    # Ephemeral ⇄ OneTime (optional)
```

### HKDF Parameters
```python
salt = b"SecureChat-X3DH-v1"
info = b"SharedSecret"
output = 32 bytes (used as root key for Double Ratchet)
```

### Prekey Rotation
- **One-time prekeys**: Delete after use, replenish when low (<20)
- **Signed prekey**: Rotate weekly/monthly
- **Identity key**: Rarely rotated (major event)

## Error Handling

### Invalid Signature
```
If signature verification fails:
  - Log security event
  - Alert user of potential MITM
  - ABORT handshake
  - Do NOT proceed with invalid prekey
```

### Missing One-Time Prekey
```
If no OPK available (server ran out):
  - Perform X3DH with only 3 DH operations (no DH4)
  - Reduced forward secrecy for first message
  - Still secure, but warn user
```

### Identity Key Mismatch
```
If stored IK_b differs from fetched IK_b:
  - Potential MITM or device change
  - Warn user prominently
  - Require re-verification of safety number
```

## Test Vectors

### Test 1: Full X3DH (with OPK)
```python
# Alice's keys
IK_a = <32-byte Ed25519 private key>
IK_a_pub = <32-byte Ed25519 public key>
EK_a = <32-byte X25519 private key>
EK_a_pub = <32-byte X25519 public key>

# Bob's keys
IK_b = <32-byte Ed25519 private key>
IK_b_pub = <32-byte Ed25519 public key>
SPK_b = <32-byte X25519 private key>
SPK_b_pub = <32-byte X25519 public key>
OPK_b = <32-byte X25519 private key>
OPK_b_pub = <32-byte X25519 public key>

# Expected shared secret
SK = <32-byte shared secret>
```

### Test 2: X3DH without OPK
```python
# Same as Test 1 but omit OPK_b
# DH4 is skipped
# SK will be different
```

### Test 3: Signature Verification
```python
# Bob signs SPK_b
signature = Ed25519.sign(IK_b, SPK_b_pub)

# Alice verifies
assert Ed25519.verify(IK_b_pub, SPK_b_pub, signature) == True
```

## References

- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/x3dh.pdf)
- [Signal Protocol Documentation](https://signal.org/docs/)
