# Forward-secrecy integration review

## Implementation status in branch `security/olm-device-ratchet-v2` (2026-11-23)

The repository now contains a first integrated v2 implementation behind a server-side feature flag:

- Pinned `@matrix-org/matrix-sdk-crypto-wasm@19.0.1` and an esbuild bundle pipeline for a self-hosted browser WASM asset.
- Device-scoped OlmMachine initialization and encrypted IndexedDB-backed SDK state, with a unique device ID per browser profile. Device ID creation is atomic across tabs. Web Locks grants one active v2 owner per account/browser profile; unsupported browsers and concurrent tabs fail closed rather than opening the same persistent ratchet store twice. Stateful SDK operations are serialized per device.
- Account-root-signed device authorization, server-side device registry, signed/one-time key upload and claim, and opaque to-device inbox/ack transport.
- Room-key sharing via the SDK with `OnlyTrustedDevices`, one-hour / 100-message session rotation configuration, and a Megolm-encrypted message envelope.
- Explicit `protocol_version` on stored messages, a bilateral account approval gate for conversation cutover, and a Worker-side prohibition on sending v1 messages once a conversation is v2.
- Existing v1 decryption path retained for stored v1 messages.
- On first use, the client pins an account-root signing key only for a authenticated contact whose invitation was explicitly approved by the recipient, removing the separate fingerprint-entry step for normal onboarding. Key changes still stop the connection and require out-of-band fingerprint verification. This relies on the server's contact assertion and does not protect against a malicious server forging that assertion or substituting the initial key.
- Device listing and revocation endpoints, with rate-limited crypto writes.

**Activation state:** the checked-in `wrangler.jsonc` currently has `SECURECHAT_CRYPTO_V2_ENABLED="true"`. This does not prove that the production Worker has this configuration or that the security gates have passed. Confirm deployed configuration separately. Keep the `forward-secrecy` diagnostic Critical until independent review and multi-user/multi-device E2E gates pass.

**Known gap before any real-user activation:** device revocation now queues a per-conversation control event to each surviving registered device. On its next successful crypto sync, the client invalidates the affected Megolm outbound session and marks tracked device lists dirty so the next send can distribute a fresh key without the revoked device. This is asynchronous and still needs browser E2E proof for every surviving device, reliable event delivery/acknowledgement, concurrent send races, and recovery. Until that test passes, do not call device revocation immediate or complete. The integration also still needs independent protocol review, including the exact low-order/all-zero X25519 rejection path in the pinned vodozemac source.

This is an implementation candidate, not an announcement that SecureChat is production-approved for forward secrecy. Do not treat the checked-in feature flag as approval to claim production security; complete every release gate below first.


**Review date:** 2026-11-23  
**Production decision:** Keep the `forward-secrecy` diagnostic critical until release gates pass. The checked-in flag is enabled, but the 2022 audit is not sufficient assurance for the current version, bindings, or SecureChat integration.

## Existing production path

The current browser client derives one AES-GCM conversation key from the long-lived account ECDH identity key and the conversation ID. That same account identity can be restored on another device through the encrypted account backup. Message encryption does not advance a per-message sending or receiving chain. This is not forward secrecy.

The existing v1 path must remain available to decrypt retained ciphertext. New protocol messages must use explicit versioned envelopes, and the application must not silently downgrade a v2 session to v1.

## Strongest candidate for an isolated integration spike: Matrix Rust crypto SDK

### vodozemac

The Matrix `vodozemac` project is a maintained Rust implementation of Olm (a Double Ratchet-based asynchronous 1:1 session protocol) and Megolm. The current docs.rs release is v0.11.2. Its session API supports outbound/inbound pre-key session establishment, ratcheted encrypt/decrypt, and serializable session state.

### Browser binding

`@matrix-org/matrix-sdk-crypto-wasm` supplies WebAssembly + JavaScript bindings for `matrix-sdk-crypto`, the no-network-I/O Matrix E2EE state machine (`OlmMachine`). Its documented browser initialization uses `initAsync`; `OlmMachine.initialize(userId, deviceId, storeName, storePassphrase)` supports an IndexedDB-backed encrypted store. The device ID is an explicit part of the crypto machine. The Rust SDK describes its crypto crate as production-ready and the project is Apache-2.0 licensed.

This is a materially better browser integration lead than a deprecated JavaScript port or a browser SDK whose own assurance statement says it has not been independently audited. It is not, however, a drop-in replacement for SecureChat's current custom message API.

### Adaptation work required

The WASM binding is a Matrix-client crypto state machine, not a generic SecureChat chat SDK. Its outgoing requests are Matrix-shaped (device key upload/query/claim, to-device messages, room messages, and related requests) and must be processed by the host. To adopt it, SecureChat would need a protocol adapter that maps those requests/responses to authenticated Worker endpoints and D1 relay storage. The application would also need a defined room/device model, participant-device fan-out, encrypted room-key distribution, event framing, replay handling, and lifecycle handling for device registration/revocation and prekey replenishment. The adapter and storage model are part of the security-critical trusted code and require independent review.

The package's IndexedDB store and local state need an explicit threat model. A same-origin XSS or malicious script can act as the logged-in user and may access state while the page is running; a passphrase-encrypted database does not make a compromised active origin safe. The existing account identity backup must not clone mutable live ratchet state across devices.

## Audit scope and limitations

Least Authority's final vodozemac audit is dated **30 March 2022**. It examined vodozemac revisions `7c11a501bc316a0bf92a5fe06fee8582aad24897` and verification revision `57d8d87a747653d6d7b7a53acb9a8d8f8de48285`.

Crucially, the report says:
- high-level application interactions (including Matrix) were out of scope;
- the cryptographic design of Olm and Megolm was out of scope and presumed to work as intended;
- Android/Java, Python, and JavaScript bindings were out of scope unless specifically included;
- the report listed unresolved items at the time, including memory swap/side-channel exposure (Issue I), MAC tag length (Issue J), and configurable skipped/message-key limits (Suggestion 8).

The current vodozemac changelog records additional post-audit changes; for example, v0.11.2 (2026-11-05) fixed malformed Ed25519 base64 decoding panics and enabled zeroization features in dependent RustCrypto crates. The v0.10.0 changelog (2026-04-13) also changes `Curve25519SecretKey.diffie_hellman()` to return an `Option`, making outbound session creation and session encryption fallible. These are useful maintenance signals, but they do not extend the 2022 audit scope to the current commit, the WASM wrapper, or SecureChat's custom adapter.

There is an additional protocol-specific review item: in a 2026-02-18 response to a public report, the Matrix security team confirmed that the then-current Olm 3DH path did not reject all-zero X25519 outputs. Matrix disputed the alleged confidentiality impact under its signed-device-key distribution model, but said it would add a defence-in-depth check. Since the v0.10.0 fallible-DH change followed that response, the spike must trace the fix to the exact release commit and add a negative test that rejects low-order/all-zero DH inputs; the changelog alone is not proof that every relevant 3DH code path rejects them.

Therefore, treat vodozemac / matrix-sdk-crypto-wasm as the preferred **candidate for a controlled integration spike**, not as independently cleared production crypto for this use. Obtain a current independent review of the exact pinned Rust crate, WASM bindings, configuration, storage adapter, and SecureChat transport integration before enabling it for users.

## Other candidates reviewed

| Candidate | Browser deployment | Maintenance / trust notes | Decision |
| --- | --- | --- | --- |
| `signalapp/libsignal` | TypeScript APIs over Rust implementations; a supported browser deployment for this application is not established by the public integration guidance. | Official Signal implementation, but the project explicitly says use outside Signal is unsupported. | Do not use without an explicitly supported browser/WASM target and integration support. |
| `signalapp/libsignal-protocol-javascript` | Browser-oriented historical JavaScript library. | The repository says it is no longer maintained and directs new applications to libsignal-client. | Reject. |
| `open-e2ee/signal-protocol-js` | Browser support and device-local state adapters are documented. | Its own assurance statement says it has no independent audit engagement. | Do not enable in production; not preferred over the Matrix Rust/WASM candidate. |

## Required release gates

1. Pin exact `vodozemac`, `matrix-sdk-crypto`, and `matrix-sdk-crypto-wasm` versions; audit transitive dependencies, licenses, build reproducibility, WASM memory handling, and supply-chain integrity.
2. Build a non-production browser spike proving device creation, encrypted IndexedDB persistence/restart, prekey upload/claim, Olm session establishment, Megolm room-key distribution, and custom Worker transport mapping. Confirm the state machine can be hosted without a Matrix homeserver and that all request/response semantics can be implemented correctly.
3. Obtain an independent security review of the exact crate versions, bindings, adapter, envelope format, storage boundary, and Worker/D1 changes. Explicitly address the scope gaps in the 2022 audit.
4. Add multi-device end-to-end tests with two users and at least two independent browser profiles/devices per user.
5. Verify first-message establishment, bidirectional DH ratchets, concurrent sends, out-of-order delivery, bounded skipped keys, duplicate/replay rejection, refresh/restart, device addition/removal/revocation, and prekey replenishment.
6. Demonstrate that captured old ciphertext cannot be decrypted from later ratchet state, and that a later message cannot be derived from a compromised old chain state after a successful uncompromised DH ratchet.
7. Verify retained v1 ciphertext still decrypts and no legacy ciphertext is rewritten. Use an explicit per-message protocol version and never silently downgrade.
8. Keep the production `forward-secrecy` diagnostic critical until all gates pass. Do not claim forward secrecy based only on an SDK demo or successful package initialization.

## Primary references

- [Signal Protocol: Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [vodozemac repository and current documentation](https://github.com/matrix-org/vodozemac)
- [vodozemac Rust session API](https://docs.rs/vodozemac/latest/vodozemac/olm/struct.Session.html)
- [Least Authority vodozemac audit report (30 March 2022)](https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf)
- [matrix-sdk-crypto-wasm browser bindings](https://github.com/matrix-org/matrix-sdk-crypto-wasm)
- [OlmMachine API documentation](https://matrix-org.github.io/matrix-sdk-crypto-wasm/classes/OlmMachine.html)
- [vodozemac 0.11.2 changelog](https://github.com/matrix-org/vodozemac/blob/main/CHANGELOG.md)
- [Signal libsignal repository and support notice](https://github.com/signalapp/libsignal)
- [Deprecated browser JavaScript implementation notice](https://github.com/signalapp/libsignal-protocol-javascript)
- [OpenE2EE Signal Protocol SDK](https://github.com/open-e2ee/signal-protocol-js)
- [OpenE2EE assurance statement](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ASSURANCE.md)
