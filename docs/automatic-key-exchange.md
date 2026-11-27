# Automatic user-to-user key exchange

SecureChat now uses authenticated contact invitations instead of manual out-of-band OTP typing for new contacts.

## Contact approval and automatic key exchange

- The inviter creates a contact invitation while signed in. The server binds the invitation to that authenticated account session.
- The invited user must explicitly approve the invitation while signed in to the invited account. This is a one-tap consent action; no OTP is displayed, copied, or typed.
- Approval creates the verified contact pair and enables the existing authenticated contact APIs. It does not prove a real-world identity or protect against a compromised account/session; users should approve only invitations they recognize.
- After approval, the client automatically checks signed account keys, pins a first-use key under the existing Web trust policy, registers its own device, exchanges device keys, and starts V2 migration when both sides are ready.
- Changed or invalid signing keys are never auto-trusted. The client stops the exchange and requires out-of-band fingerprint comparison.
- Existing pending invitations remain addressable; the authenticated recipient can approve them without entering an OTP. The legacy OTP endpoints remain temporarily for compatibility with older clients.

## Automatic workflow

- At sign-in, the client initializes its local Olm device and publishes signed device keys and signed one-time prekeys.
- In the foreground, the client synchronizes its encrypted to-device inbox and one-time-key counts every 60 seconds, and again when the window regains focus.
- For conversations with explicitly approved contacts, the client checks the peer account-signing key, queries active peer devices, claims signed one-time keys, and establishes missing Olm sessions.
- Each participant's client automatically records its own V2 migration approval after its local identity-trust gate passes. When both participants have approved, the server reports V2 enabled and both clients continue session maintenance.
- On message send, the existing Olm/Megolm path distributes the new message's room key to trusted active devices. Megolm remains one session per message; Olm handles the device-to-device key transport and ratchet.

## Device management

Device registration and key synchronization run automatically. Listing registered devices and revoking a lost device are available only from User Settings; the chat sidebar and conversation view contain no device-management controls.

## Trust and recovery boundaries

- This flow is account-authenticated mutual consent, not proof of a person's legal or offline identity. It is weaker than exchanging a code through an independently verified channel against a compromised account.
- New peer devices must have account-key authorization signatures that verify against the locally trusted account-signing key.
- A changed peer account-signing key stops automatic exchange. A valid key transition signature alone does not silently replace the local trust pin; the new fingerprint must be verified separately.
- When a device is revoked, existing revocation events continue to invalidate the affected group sessions. A revoked device is excluded from future key queries and room-key distribution.
- Automation runs while the application is open and in the foreground. It resumes on focus/visibility changes; it is not a background service when the application is closed.
- This is classical Matrix Olm/Megolm cryptography, not post-quantum encryption. It does not add PQXDH, ML-KEM, or SPQR.
