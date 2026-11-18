# SecureChat forward-secrecy evaluation lab

This folder is deliberately isolated from the production Worker and existing chats. It evaluates the browser-capable OpenE2EE Signal Protocol SDK before any application integration.

## Candidate

- Package: `@open-e2ee/signal-protocol-sdk`
- Pinned version: `14.7.0` (do not use a floating `latest` dependency)
- Protocol features advertised by the project: PQXDH session establishment and Double Ratchet / post-quantum ratcheting.
- This is an independent implementation/profile. It is **not affiliated with Signal Messenger and is not wire-compatible with Signal/libsignal**.
- The project states that it has not been independently audited by an external security firm. This lab is evaluation only, not approval for production use.

## Run the isolated Sandbox round-trip

Requires Node.js 22.18 or later.

1. From this directory, run `npm install`.
2. Create a Sandbox project using the SDK provider's documented setup and obtain its Sandbox relay URL. Do not use a Production relay.
3. Create `.env.local` containing:

   ```dotenv
   OPEN_E2EE_SIGNAL_RELAY_URL=your-sandbox-relay-url
   ```

4. Run `npm test`.

The test creates two temporary in-memory identities, sends one encrypted message through the Sandbox relay, and verifies that the second identity decrypts the exact plaintext. The in-memory keys and ratchet state are discarded when the process exits; this is intentional for this first smoke test.

## Before integrating into SecureChat

- Verify first-contact PQXDH, message encryption/decryption, sequential ratchet advancement, out-of-order delivery, replay rejection, skipped-message-key limits, and restart persistence.
- Review identity binding: SecureChat account authentication must be cryptographically bound to each device identity. Do not trust a user ID supplied by the browser alone.
- Decide and implement a device-local persistent browser store. Review the SDK's browser CSP requirements and XSS boundary.
- Design a relay adapter that stores opaque envelopes only; never send plaintext or private keys to Worker/D1.
- Preserve legacy conversations using the existing v1 decrypt path. New conversations must be explicitly versioned and use the new protocol. Never silently reinterpret or migrate old ciphertext.
- Add migration, backup, device-loss, key-change, and contact safety-number UX before any production rollout.
- Require independent security review before describing the product as production-grade E2EE.

## Important browser limitation

A browser app's origin serves the JavaScript that performs encryption. A compromised same-origin script or XSS can access the protocol client while it is unlocked, even if keys are non-extractable or storage is encrypted. The SDK documentation explicitly describes this threat boundary. A restrictive CSP, dependency control, and security review remain necessary.

This lab does not change the root `package.json`, Worker routes, D1 schema, production deployment, or existing conversation data.
