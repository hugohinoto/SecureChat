# E2EE v2 migration plan (Cloudflare self-hosted)

## Decision

Evaluate and integrate `@open-e2ee/signal-protocol-sdk` as a locally bundled browser dependency. Keep all application delivery infrastructure on the existing Cloudflare account:

- Cloudflare Worker remains the authenticated API and relay.
- Cloudflare D1 stores public device/prekey material, opaque encrypted envelopes, and routing metadata only.
- Browser-local SDK storage owns private identity material, prekeys, sessions, and ratchet state.
- No OpenE2EE hosted Relay, Sandbox, Console, or other third-party message relay is used.

The SDK is dual-licensed `MIT OR Apache-2.0`. Pin an exact reviewed version; do not use `latest` in production builds.

## Important constraints

1. The SDK package contains a client-side relay contract, not a server implementation. SecureChat must implement the authenticated relay endpoints and a browser transport adapter.
2. The relay must atomically consume one-time prekeys. A race that returns the same one-time prekey to two initiators is a release blocker.
3. The current application is a plain static browser app served from `public/`. Bare npm imports cannot be added to `public/app.js` without a reproducible bundling step. Build output must be deterministic and CI-checked.
4. The SDK protocol is not wire-compatible with the current ECDH-P256/HKDF/AES-GCM prototype or with Signal Messenger. Existing conversations must remain on the legacy decrypt path and must never be silently reinterpreted as v2.
5. The SDK's browser documentation explicitly warns that same-origin JavaScript, XSS, browser extensions, and compromised dependencies can invoke keys while the app is open. A restrictive CSP and supply-chain controls are required; browser E2EE does not protect against a compromised app origin.
6. The SDK documentation says there has been no independent third-party audit. Treat it as a candidate implementation, not as an audited security guarantee.

## Migration phases

### Phase 0 — repository and dependency assessment

- Pin the exact SDK release and its transitive dependencies.
- Confirm browser storage adapter behavior on Chromium, Firefox, and WebKit.
- Add a reproducible browser bundling pipeline and CI checks without changing the production entry point.
- Record license notices and dependency provenance.

### Phase 1 — isolated protocol proof

- Build a non-production test page with two independent browser profiles.
- Verify device identity creation, PQXDH session establishment, message encryption/decryption, Double Ratchet progression, restart persistence, and prekey replenishment.
- Confirm private key and plaintext fields never appear in Worker/D1 requests or logs.
- Verify identity-key change warnings and explicit safety-number comparison.

### Phase 2 — Cloudflare relay implementation

- Add versioned D1 tables for devices, public prekeys, one-time-prekey consumption, and encrypted envelopes.
- Add authenticated Worker endpoints implementing the SDK relay contract.
- Use D1 atomic operations / serialized Durable Object coordination for one-time-prekey consumption, idempotent envelope IDs, and delivery acknowledgement.
- Add strict ownership checks, per-user/device limits, payload limits, retention, rate limits, and cleanup.
- Do not store private keys, session state, ratchet state, or plaintext.

### Phase 3 — application integration

- Keep legacy conversations and their decryptor intact.
- Create new v2 conversations only after both devices have registered v2 keys and verified contact identity.
- Store an explicit crypto version per conversation/message; reject unknown versions.
- Add local encrypted message-history storage or clearly document server-side history limitations.
- Handle browser storage loss as identity loss; do not silently generate a replacement identity under the same trusted device record.

### Phase 4 — release gates

- Unit, integration, concurrency, replay, malformed-input, and multi-tab tests pass.
- Test two real browser profiles end-to-end against a local Worker/D1 environment.
- Review CSP, dependency tree, source maps, logs, and all network payloads.
- Obtain an independent security review before claiming production-grade E2EE.
- Deploy only after explicit approval; GitHub commits alone do not prove Cloudflare production deployment.

## Current status

This branch contains the migration decision and gates only. No production Worker, D1 schema, account, or existing conversation has been changed. No production E2EE claim is made.
