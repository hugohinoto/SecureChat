# Signed chat identity keys

SecureChat now uses a separate P-256 ECDSA signing key to prove possession of the account's ECDH identity key.

## Proof format

The browser signs the UTF-8 message:

`SecureChat identity-key-proof:v1\n<user_id>\n<base64 ECDH public key>`

The Worker verifies the signature against the authenticated session's user ID before saving the key. The public-key endpoint returns the signing public key and proof. Clients verify the proof before deriving a conversation key.

The signing private key is generated as a non-extractable WebCrypto key and stored locally in IndexedDB. Existing ECDH identity keys are retained when possible; a signing key is added on the next login. The server never receives private keys.

## First-contact and key-change checks

Clients pin each peer's signing public key locally on first contact only when the peer is already a authenticated contact whose invitation was explicitly approved by the recipient. This lets the client start device-key authorization and the v2 ratchet automatically without a separate fingerprint-entry step. A changed key is never auto-trusted; the client stops and requires an out-of-band fingerprint comparison. A self-signature proves possession of the signing key, but not a real-world identity. Automatic first-use trust relies on the server's mutual-contact status and does not protect against a malicious server that can forge that status or substitute the first key.

If browser storage is cleared or the user changes devices, the local pin set is lost. The first key can be pinned again for an authenticated, explicitly approved contact; compare fingerprints out of band when protection against a malicious server is required.

## Legacy accounts

Migration `0009_signed_identity_keys.sql` adds nullable proof columns. Existing public keys are not deleted. Each account must sign in using the updated client to publish a proof. Until that happens, the security diagnostic reports the legacy unsigned key count and clients refuse to start a conversation with a legacy key.

This account identity layer does not itself implement X3DH, one-time prekeys, or Double Ratchet. Crypto v2 uses the separate Matrix Olm/Megolm SDK integration for device ratchets; see [forward-secrecy-integration-review.md](./forward-secrecy-integration-review.md) for its scope and release caveats.
