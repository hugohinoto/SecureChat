# SecureChat V2 automatic post-quantum key exchange

**Status: design proposal only — not implemented or enabled.**

This document records the target architecture for automatic first-contact key establishment, ongoing key refresh, and multi-device enrollment. It is deliberately not a claim that SecureChat currently provides post-quantum protection.

## Current implementation boundary

The current Crypto Protocol v2 client uses `@matrix-org/matrix-sdk-crypto-wasm` (Matrix Rust crypto) and Matrix Olm/Megolm flows. It provides device-scoped key management, Olm Double Ratchet key delivery, and one-message Megolm session rotation. This is classical public-key cryptography, not a post-quantum key exchange. The existing v2 protocol and stored conversations must remain available during any future migration.

The current library/API must not be described as implementing Signal PQXDH, SPQR, a post-quantum ratchet, ML-KEM, or ML-DSA unless a specific supported release and its audited API are verified. No custom implementation of these primitives is permitted.

## Target requirements

1. **First contact:** automatically establish an authenticated session without asking users to copy or exchange key material manually. The client must verify the peer's device identity and display a clear warning if trust cannot be established.
2. **Ongoing protection:** advance message keys continuously and periodically refresh post-quantum shared secret material. A timer alone is insufficient; refresh should also be driven by message counts, session age, and available one-time/prekey inventory.
3. **New device:** generate a unique identity and private state on each device. Existing trusted devices authorize enrollment. Create fresh peer sessions for the new device; never copy another device's live ratchet private state as a shortcut.
4. **Revocation and recovery:** revoke a device, reject its future key claims, notify other devices, and re-establish sessions with remaining trusted devices. Recovery must not silently weaken peer authentication.
5. **Fail closed:** no plaintext fallback and no silent downgrade to the legacy protocol. If the peer or device cannot negotiate the required protocol, block sending and explain how to resolve it.
6. **Compatibility:** preserve read-only decryption of existing V1 messages and maintain V2 sessions until a separately tested migration is approved.

## Cryptographic profile selection

The following are candidates, not an assertion that they are already integrated:

- **Initial asynchronous key establishment:** a maintained, independently reviewed PQXDH-compatible implementation using a NIST-standardized ML-KEM parameter set. The exact parameter set and wire format must follow the selected library/specification; do not invent a SecureChat-specific PQXDH variant.
- **Ongoing ratchet:** a reviewed post-quantum ratchet construction compatible with the selected initial handshake. Evaluate Signal's Double Ratchet plus SPQR/Triple Ratchet only through a supported, reviewed implementation. The current Matrix Olm Double Ratchet is not itself post-quantum.
- **Signatures and device identity:** retain the existing identity-verification chain while evaluating a standardized post-quantum signature such as ML-DSA. A hybrid signature must use a reviewed composite construction with unambiguous transcript binding; do not concatenate signatures or invent verification rules.
- **Message AEAD and KDF:** retain well-reviewed AEAD/KDF primitives and domain-separated transcript derivation as prescribed by the selected protocol. Do not substitute algorithms independently of the protocol specification.

A library decision is a release gate. Verify browser/WASM and Electron compatibility, deterministic test vectors, dependency provenance, key export/import semantics, memory clearing limitations, update cadence, and independent security review before enabling any PQ capability.

## Automatic lifecycle

### First contact

1. Each device creates its own identity and signed prekey material using the selected library.
2. The client uploads only public identity/prekey material and signatures. Private keys remain in the local encrypted device store.
3. The initiating device retrieves the recipient's device bundle and verifies account binding, device binding, signatures, expiry, algorithm identifiers, and trust state.
4. The library performs the authenticated PQ initial exchange and initializes the post-quantum ratchet.
5. The client commits the resulting state locally before marking the session ready. Duplicate requests must be idempotent.
6. The UI reports the negotiated protocol and verification state; it must not imply PQ protection when only classical V2 was negotiated.

### Continuous and scheduled refresh

- Advance the message ratchet for every message according to the selected protocol.
- Replenish signed and one-time prekeys before inventory becomes low.
- Consume one-time keys atomically and at most once.
- Trigger post-quantum ratchet refresh on protocol-defined message-count and age thresholds, and after a peer device change.
- Persist ratchet state atomically; prevent concurrent tabs/processes from advancing the same device state.
- Retain only the skipped-message key window required by the protocol and expire it according to the protocol rules.
- On partial failure, resume from an authenticated, idempotent state transition; never reuse a consumed one-time key or roll back to an older ratchet state.

### Device enrollment

- New device creates independent identity keys and an independent local vault.
- An existing trusted device approves the enrollment through an authenticated device-to-device flow.
- Bind the approval to account ID, new device ID, public-key fingerprints, protocol version, expiry, and a one-time nonce.
- Establish independent sessions between the new device and each peer device. Do not upload private keys or server-side plaintext backups.
- Provide explicit device revocation and rekey notifications.

## Server and storage boundaries

Cloudflare Workers/D1 may relay and persist public identity keys, signed public prekeys, one-time public prekeys, key identifiers, expiry/claim metadata, device trust/revocation metadata, and opaque encrypted to-device events. One-time prekey claiming must be an atomic conditional update with replay protection and an idempotency key.

The server must never receive device private identity keys, KEM decapsulation keys, ratchet chain/message keys, or plaintext. Do not add database columns for private key material. Any new public-key schema/API must be introduced only after the selected protocol library and exact wire format are fixed.

**No D1 migration is included in this design-only change.** Existing `crypto_devices`, `crypto_one_time_keys`, `crypto_to_device_inbox`, and `conversation_crypto_modes` remain the current V2 transport. A future PQ migration must use a new explicit protocol version and must not reinterpret existing V2 rows.

## Rollout and downgrade policy

1. Select and pin a reviewed PQ-capable library; publish the threat model and dependency review.
2. Implement isolated crypto adapters and pass upstream test vectors before adding server APIs.
3. Add versioned public-key/prekey transport and atomic one-time-key claims.
4. Add automatic handshake, refresh, device enrollment, revocation, and recovery behind a server/client capability gate.
5. Test mixed-version peers, multi-device fan-out, offline/reconnect, concurrent tabs, replay, rollback, key exhaustion, and interrupted state commits.
6. Enable only for newly negotiated sessions after explicit compatibility and security review. Keep existing V1/V2 decryption compatibility.
7. Remove fallback only after the migration window and recovery plan are verified.

A peer that lacks the required PQ profile must not be silently downgraded. The user must be told that a secure session could not be established.

## Required security tests before release

- Official known-answer and interoperability test vectors for every selected primitive/protocol.
- Transcript tampering, identity substitution, replay, prekey reuse, duplicate delivery, and downgrade tests.
- Ratchet rollback and crash-between-state-commit tests.
- Two or more devices per account, simultaneous enrollment, revocation, and offline catch-up.
- Browser and Electron/WASM parity, including supported CSP and offline behavior.
- Negative tests proving private material never appears in Worker requests, D1 rows, logs, analytics, or crash reports.
- Independent cryptographic review and documented recovery/backup behavior.

## Release status checklist

- [ ] Select and pin a maintained PQXDH-capable implementation.
- [ ] Select and pin a compatible post-quantum ratchet implementation.
- [ ] Review hybrid device authentication and identity migration.
- [ ] Implement public PQ prekey transport and atomic claim/replenishment.
- [ ] Implement automatic initial exchange and ratchet refresh.
- [ ] Implement trusted multi-device enrollment and revocation.
- [ ] Add cross-client interoperability and adversarial tests.
- [ ] Complete independent security review.

Until every applicable item is complete, SecureChat must continue to label the current protocol as classical Crypto Protocol v2 and must not advertise post-quantum protection.
