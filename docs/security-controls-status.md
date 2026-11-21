# SecureChat security follow-up

## Current state

- Application data encryption supports versioned keys. The diagnostic checks encrypted-row usage by generation and does not treat a staged second key as a completed rotation.
- Automatic Cloudflare Invocation Logs are disabled in Wrangler configuration. Application logging remains available only through fixed, non-sensitive labels.
- Chat forward secrecy is not implemented in production. The current account-level ECDH identity scheme is not a Double Ratchet.
- Administrator passkey / WebAuthn authentication is not implemented. The current administrator authentication remains password-based with the existing recent-login and password-age controls.

## Forward secrecy release gate

Do not replace the v1 messaging path until a separately versioned v2 protocol can pass end-to-end tests across two browser profiles and multiple devices. Required work includes persistent device-local ratchet state, authenticated prekey/session establishment, one-time prekey replenishment, out-of-order and replay handling, device addition/removal, account recovery, safety-number changes, and a relay that stores opaque envelopes only. Existing v1 messages must remain on the v1 decrypt path. Obtain an independent protocol review before calling the feature production-ready.

The isolated `security-lab` SDK demo uses temporary in-memory identities and an external Sandbox relay. It is not a production integration, has no durable session store, and is not evidence that SecureChat has forward secrecy.

## Administrator passkey release gate

Passkey support must use WebAuthn challenges bound to the admin account, origin, RP ID, and purpose; persist credential public keys and counters; prevent replay; require user verification; provide a second recovery authenticator or a carefully designed recovery path; and enforce the passkey step before issuing an administrator session. Enrollment and removal must require recent password reauthentication and produce audit events. Do not mark the diagnostic passed until login and account-recovery flows are covered by browser-based tests.
