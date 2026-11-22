# Forward-secrecy integration review

**Review date:** 2026-11-23  
**Production decision:** No-go for enabling a new messaging protocol until an independently reviewed browser-compatible implementation and the release tests in [Issue #30](https://github.com/hugohinoto/SecureChat/issues/30) are satisfied.

## Existing production path

The current browser client derives one AES-GCM conversation key from the long-lived account ECDH identity key and the conversation ID. That same account identity can be restored on another device through the encrypted account backup. Message encryption does not advance a per-message sending or receiving chain. This is not forward secrecy.

The existing v1 path must remain available to decrypt retained ciphertext. New protocol messages must use explicit versioned envelopes, and the application must not silently downgrade a v2 session to v1.

## Candidate review

| Candidate | Browser deployment | Maintenance / trust notes | Decision |
| --- | --- | --- | --- |
| `signalapp/libsignal` | The project publishes TypeScript APIs over Rust implementations, but the project explicitly says use outside Signal is unsupported. The documented client bindings do not establish a supported Cloudflare Worker or browser deployment for this application. | Official Signal implementation, but external integration support and browser runtime requirements are unresolved. | Do not integrate into production without an explicitly supported browser/WASM target and a reviewed compatibility boundary. |
| `signalapp/libsignal-protocol-javascript` | Browser-oriented historical JavaScript library. | The repository says it is no longer maintained and directs new applications to libsignal-client. | Reject. |
| `open-e2ee/signal-protocol-js` | Its documentation describes browser support and device-local state adapters, including IndexedDB / OPFS. | The SDK's own assurance document states it has no independent audit engagement. It is also a separately versioned profile, not wire-compatible with Signal Messenger. | Candidate for an isolated integration spike only; not production-approved. |

## Why the protocol is not switched on yet

A browser-capable package by itself is not sufficient. This application also needs a correct device identity model, authenticated signed and one-time prekey distribution, independent sessions for each device pair, device-local durable ratchet state, per-device recipient fan-out, atomic state transitions, bounded skipped-message handling, replay rejection, out-of-order delivery, recovery and revocation, and a non-downgradable versioned envelope.

The browser store must be evaluated against same-origin script compromise and XSS. Encrypting an IndexedDB record with a key stored in the same origin does not protect against malicious JavaScript executing in that origin. A live ratchet state must not be copied by the existing account identity backup.

## Required release gates

1. Choose a protocol library with an explicitly supported browser/WASM deployment and a license compatible with this repository.
2. Obtain an independent security review of the exact library version, adapter, envelope format, storage boundary, and integration code.
3. Add multi-device end-to-end tests with two users and at least two browser profiles/devices per user.
4. Verify first-message establishment, both DH ratchet directions, concurrent sends, out-of-order delivery, bounded skipped keys, duplicate/replay rejection, restart/restore, device add/remove/revocation, and prekey replenishment.
5. Demonstrate that captured old ciphertext cannot be decrypted from later ratchet state, and that a later message cannot be derived from a compromised old chain state after a successful uncompromised DH ratchet.
6. Verify retained v1 ciphertext still decrypts and no legacy ciphertext is rewritten.
7. Keep the production `forward-secrecy` diagnostic critical until all gates pass. Do not claim forward secrecy based only on a candidate SDK or local demo.

## Primary references

- [Signal Protocol: Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal libsignal repository and support notice](https://github.com/signalapp/libsignal)
- [Deprecated browser JavaScript implementation notice](https://github.com/signalapp/libsignal-protocol-javascript)
- [OpenE2EE Signal Protocol SDK](https://github.com/open-e2ee/signal-protocol-js)
- [OpenE2EE assurance statement](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ASSURANCE.md)
