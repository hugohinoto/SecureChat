# Post-quantum implementation readiness review

**Status: investigation in progress — runtime cryptography is unchanged.**
**Reviewed:** 2026-11-26

This review records the blockers that must be resolved before SecureChat can safely replace or extend its current Matrix Olm/Megolm Crypto Protocol v2 implementation.

## Executive decision

Do not add an unreviewed PQXDH/WASM wrapper and do not claim post-quantum protection yet.

The target protocol remains a versioned, reviewed implementation of:
- asynchronous post-quantum initial key establishment (PQXDH-compatible);
- a continuous post-quantum ratchet (SPQR/Triple Ratchet-compatible);
- authenticated per-device enrollment and revocation;
- fail-closed negotiation with no plaintext or silent classical fallback.

The existing V1/V2 decrypt path must remain intact during migration.

## Findings

### Existing SecureChat integration

The web client currently imports `@matrix-org/matrix-sdk-crypto-wasm` 19.0.1 and uses Matrix Olm/Megolm APIs. The desktop renderer contains the same crypto-v2 client source and the desktop package also pins the Matrix WASM SDK. This gives the two clients a shared current implementation, but it does not provide PQXDH or SPQR.

The main repository and desktop repository currently use separate package manifests. Any future PQ adapter must therefore have one pinned, reproducible dependency and identical protocol behavior in both builds. Prefer a dedicated shared package/workspace or a single canonical adapter source copied/bundled by the existing build pipeline; do not maintain two independent protocol implementations.

### Signal libsignal candidate

The official `signalapp/libsignal` repository contains Rust implementations of PQXDH and Signal's post-quantum ratchet work. The upstream repository currently declares **AGPL-3.0-only**. SecureChat's project license is Apache-2.0.

This is a material distribution and licensing decision, not a routine dependency update. Before adopting libsignal, obtain a documented license review covering the intended distribution model, whether the integration creates a combined/derivative work, and whether the project can accept the resulting obligations. Do not change SecureChat's top-level license implicitly.

The upstream project describes the library as the Signal Protocol implementation for Signal. Its supported integration surface, browser/WASM build, stable public API, and external-project support guarantees must be confirmed against the exact pinned release. The presence of Rust source code alone is not proof that a browser/Electron integration is production-ready.

References:
- https://github.com/signalapp/libsignal
- https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/pqxdh.rs
- https://signal.org/docs/specifications/pqxdh/
- https://signal.org/docs/

### Authentication boundary

PQXDH revision 3 provides post-quantum forward secrecy for key establishment but its mutual authentication still relies on classical discrete-log assumptions. SecureChat must not label the entire identity/authentication system quantum-safe solely because PQXDH or ML-KEM is enabled.

A post-quantum or hybrid device-authentication migration requires a separately reviewed construction and transcript binding. Do not concatenate Ed25519 and ML-DSA signatures or invent a composite signature format.

## Required gates before runtime integration

1. **License gate:** document the legal decision for libsignal or select a permissively licensed, independently reviewed alternative with equivalent protocol coverage.
2. **Platform gate:** demonstrate a supported browser/WASM build and Electron portable build from the same pinned source, including offline startup and CSP compatibility.
3. **API gate:** identify stable public APIs for PQXDH, SPQR/Triple Ratchet, session persistence, serialization, and device/session lifecycle. No direct use of private Rust internals.
4. **Security gate:** verify upstream test vectors and interoperability tests; obtain independent cryptographic review of the exact integration and protocol version.
5. **Identity gate:** define account/device binding, device approval, revocation, identity-change handling, and the limits of classical authentication.
6. **Migration gate:** define versioned wire envelopes, peer capability negotiation, existing V1/V2 decryption, session transition, rollback prevention, and recovery.
7. **Server gate:** only after the selected protocol and wire format are fixed, implement public prekey publication, atomic one-time-key claims, replay protection, and opaque to-device transport. Private keys and ratchet secrets must never reach Workers, D1, logs, or analytics.
8. **Test gate:** add cross-client vectors and negative tests for downgrade, replay, key reuse, state rollback, concurrent tabs/processes, interrupted commits, device enrollment/revocation, offline recovery, and malformed messages.

## Immediate implementation plan

### Phase 0 — selection and feasibility (current)

- [x] Inspect both current package manifests and crypto-v2 entry points.
- [x] Confirm both clients currently depend on Matrix Rust/WASM crypto.
- [x] Record the official libsignal candidate and its AGPL-3.0-only license.
- [ ] Complete license review.
- [ ] Verify supported browser/WASM and Electron integration for a pinned release.
- [ ] Compare viable alternatives against protocol coverage, maintenance, audit, licensing, and interoperability.

### Phase 1 — isolated adapter and vectors

Only after Phase 0 passes:
- create one shared crypto adapter with an explicit protocol identifier/version;
- keep private keys and ratchet state in the encrypted local device vault;
- import official test vectors and add Web/Desktop byte-for-byte parity tests;
- keep PQ capability disabled until all tests pass.

### Phase 2 — transport and lifecycle

- add versioned public identity/prekey APIs and atomic one-time-prekey claims;
- implement automatic initial exchange, replenishment, ratchet refresh, device enrollment, and revocation;
- reject downgrade and fail closed when the required profile cannot be negotiated.

### Phase 3 — staged rollout

- enable only for newly established sessions behind a capability gate;
- preserve existing V1/V2 decryption and an explicit migration path;
- publish accurate per-conversation security status;
- remove legacy session creation only after interoperability, recovery, and independent review.

## Non-goals

- No custom PQXDH or SPQR implementation.
- No unreviewed third-party WASM wrapper.
- No private-key or ratchet-state storage on the server.
- No change to the Apache-2.0 project license without an explicit project decision.
- No runtime behavior change, database migration, merge, or deployment as part of this readiness review.

## Release claim

Until every required gate passes and the implementation is enabled for the relevant session, SecureChat must describe its current V2 encryption as classical Matrix Olm/Megolm—not post-quantum encryption.
