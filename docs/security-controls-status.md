# SecureChat security follow-up

## Current state

- Application data encryption supports versioned keys. The diagnostic checks encrypted-row usage by generation and does not treat a staged second key as a completed rotation.
- Automatic Cloudflare Invocation Logs are disabled in Wrangler configuration. Application logging remains available only through fixed, non-sensitive labels.
- The production chat default remains protocol v1. A device-scoped Matrix Olm / Megolm v2 implementation, authenticated device registration, one-time-prekey transport, opaque to-device inbox, versioned message storage, and bilateral migration controls have been added behind `SECURECHAT_CRYPTO_V2_ENABLED=false`.
- The production security diagnostic deliberately keeps `forward-secrecy` at **critical**. Code being present or a feature flag being switched on is not proof that the complete protocol and deployment meet the security gate.
- Administrator passkey / WebAuthn authentication is not implemented. Administrator authentication remains password-based with the existing recent-login and password-age controls.

## Forward-secrecy implementation and production gate

The v2 implementation uses the Matrix Rust/WASM crypto state machine. Each browser profile/device receives its own device ID and local encrypted Olm state; the existing account identity backup does not clone live ratchet state. The server stores device public-key records, one-time keys, opaque encrypted to-device events, and versioned opaque Megolm messages. New conversations must be approved by both account owners before the protocol mode can become v2. Once v2 is selected, the legacy v1 message POST is rejected for that conversation; retained v1 messages remain on the v1 decryption path.

The feature flag is intentionally **false** in the checked-in production Wrangler configuration. Do not enable it for real users or claim production forward secrecy until all of the following pass:

1. Build and pin the exact WASM artifacts/dependencies reproducibly and verify the license and supply chain.
2. Review the exact vodozemac / SDK / WASM source path for X25519 low-order and all-zero DH rejection and add a negative test for the initial Olm handshake.
3. Run end-to-end browser tests with two users and at least two independent browser profiles/devices per user. Cover first-contact prekey establishment, bidirectional DH ratchets, one-time-prekey single-consumption under concurrency, group-key distribution, out-of-order and duplicate delivery, skipped-key limits, concurrent sends, reload/restart and IndexedDB persistence.
4. Verify device revocation end to end. The Worker now queues per-conversation revocation events to surviving registered devices; on their next crypto sync, clients invalidate the affected Megolm outbound session and dirty tracked device lists before the next key share. This is asynchronous, not instantaneous, until all devices receive and acknowledge the event. Test concurrent sends, devices offline during revocation, eventual event delivery/acknowledgement, and proof that the next message uses a fresh Megolm session which excludes the revoked device.
5. Test device loss, device replacement, recovery, prekey replenishment, fingerprint changes, and account root-key changes.
6. Verify that old v1 ciphertext remains readable after migration, that v2 never silently downgrades, and that a protocol-mode transition cannot race a concurrent v1 write.
7. Obtain an independent review of the current SDK versions, compiled WASM artifacts, Worker adapter, D1 schema, local persistence, and transport/recovery logic. The public 2022 vodozemac audit does not cover all of these components.

The production `forward-secrecy` diagnostic remains critical until these gates are met. Do not set `SECURECHAT_CRYPTO_V2_ENABLED=true` merely to clear the diagnostic.

## Administrator passkey release gate

Passkey support must use WebAuthn challenges bound to the admin account, origin, RP ID, and purpose; persist credential public keys and counters; prevent replay; require user verification; provide a second recovery authenticator or carefully designed recovery; enforce the passkey step before issuing an administrator session; and require recent password reauthentication for enrollment/removal with audit events. Do not mark it complete until browser tests cover login and recovery.
