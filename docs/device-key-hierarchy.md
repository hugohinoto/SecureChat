# Device-bound key hierarchy

## Design

SecureChat does not derive secrets from User-Agent, screen dimensions, CPU count, memory size, timezone, IP address, or other browser/device fingerprint attributes. Those values are mutable, observable, spoofable, and are not cryptographic entropy.

Each browser profile creates a random 256-bit device-vault root using the Web Crypto CSPRNG. The raw random bytes are imported as a non-extractable HKDF-SHA-256 CryptoKey and immediately cleared from the JavaScript byte buffer. HKDF derives an AES-256-GCM wrapping key with domain-separated context containing the authenticated SecureChat user ID and random device ID. The passphrase used by the Matrix Rust/WASM crypto store is encrypted with AES-GCM using additional authenticated data bound to the same user/device pair.

The HKDF root CryptoKey is persisted in IndexedDB via structured cloning. It is marked non-extractable; this prevents direct export through Web Crypto, but does not prove hardware-backed storage or protect against active same-origin XSS that can invoke cryptographic operations. The browser may store key material according to its own implementation. This is a browser-profile/origin-scoped software key, not a TPM/Secure Enclave guarantee.

## Key separation

- Device vault root: random, local to one browser profile and account.
- Vault wrapping key: HKDF-SHA-256 derived, AES-256-GCM, scoped to user ID and device ID.
- Olm device identity and ratchet keys: generated and managed by Matrix Rust/WASM per device; private state stays in the local encrypted crypto store.
- Account signing identity: signs/authorizes device public keys and remains separately protected by the existing encrypted account-identity backup.
- Message/session keys: remain under Olm Double Ratchet and Megolm session rotation. The device-vault key is not substituted for ratchet keys and does not replace forward secrecy.

## Existing device migration

The original vault format stored a non-extractable AES-GCM wrapping key directly. On the next successful unlock, SecureChat decrypts the existing store passphrase, creates a random HKDF root and a v2 authenticated envelope, and saves the upgraded record while preserving the existing device ID and store passphrase. Therefore the existing Olm database name and ratchet state are not intentionally rotated or discarded. If migration fails, the app must report the error and must not delete the old record or crypto database.

No D1 schema migration is required. This change is entirely client-side.

## Hardware-backed enhancement

WebAuthn PRF can be evaluated as an optional additional unlock factor on authenticators that support it. It requires a WebAuthn ceremony and cannot be assumed available on every browser/device. It should be introduced as an opt-in recovery-aware enhancement, not as the only way to decrypt existing user data.
