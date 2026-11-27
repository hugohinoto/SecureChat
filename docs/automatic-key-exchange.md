# Automatic user-to-user key exchange

SecureChat now runs key-exchange maintenance without requiring the user to open every conversation.

## Automatic workflow

- At sign-in, the client initializes its local Olm device and publishes signed device keys and signed one-time prekeys.
- In the foreground, the client synchronizes its encrypted to-device inbox and one-time-key counts every 30 seconds, and again when the window regains focus.
- For existing conversations with mutual OTP-verified contacts, the client checks the peer account-signing key under the platform's existing trust policy, queries active peer devices, claims signed one-time keys, and establishes missing Olm sessions.
- Each participant's client automatically records its own V2 migration approval after its local identity-trust gate passes. When both participants have approved, the server reports V2 enabled and both clients continue session maintenance.
- On message send, the existing Olm/Megolm path distributes the new message's room key to trusted active devices. Megolm remains one session per message; Olm handles the device-to-device key transport and ratchet.

## Trust and recovery boundaries

- This automation does not accept unverified devices. New peer devices must have account-key authorization signatures that verify against the locally trusted account-signing key.
- Web first-use pinning continues to follow the web client's existing mutual-OTP TOFU behavior. Desktop continues to require out-of-band fingerprint verification before marking a peer account key as trusted.
- A changed peer account-signing key stops automatic exchange. A valid key transition signature alone does not silently replace the local trust pin; the new fingerprint must be verified separately.
- When a device is revoked, existing revocation events continue to invalidate the affected group sessions. A revoked device is excluded from future key queries and room-key distribution.
- Automation runs while the application is open and in the foreground. It resumes on focus/visibility changes; it is not a background service when the application is closed.
- This is classical Matrix Olm/Megolm cryptography, not post-quantum encryption. It does not add PQXDH, ML-KEM, or SPQR.

## Key rotation

The existing implementation configures one Megolm session per message and uses Olm for to-device key delivery. The automation maintains signed one-time-key inventory and missing Olm sessions; it does not invent a new ratchet or change the cryptographic protocol.
