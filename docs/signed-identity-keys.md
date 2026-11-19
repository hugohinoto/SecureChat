# Signed chat identity keys

SecureChat now uses a separate P-256 ECDSA signing key to prove possession of the account's ECDH identity key.

## Proof format

The browser signs the UTF-8 message:

`SecureChat identity-key-proof:v1\n<user_id>\n<base64 ECDH public key>`

The Worker verifies the signature against the authenticated session's user ID before saving the key. The public-key endpoint returns the signing public key and proof. Clients verify the proof before deriving a conversation key.

The signing private key is generated as a non-extractable WebCrypto key and stored locally in IndexedDB. Existing ECDH identity keys are retained when possible; a signing key is added on the next login. The server never receives private keys.

## First-contact and key-change checks

Clients pin each peer's signing public key locally on first contact and reject a changed key. Users must still compare the displayed SHA-256 signing-key fingerprints with the peer over an independent trusted channel on first contact and after any key change. A self-signature proves possession of the signing key; by itself it does not prove a real-world identity or protect a first contact from a malicious server.

If browser storage is cleared or the user changes devices, the local pin set is lost and fingerprints must be compared again.

## Legacy accounts

Migration `0009_signed_identity_keys.sql` adds nullable proof columns. Existing public keys are not deleted. Each account must sign in using the updated client to publish a proof. Until that happens, the security diagnostic reports the legacy unsigned key count and clients refuse to start a conversation with a legacy key.

This change does not implement X3DH, one-time prekeys, or Double Ratchet. Forward secrecy remains unavailable until a separately reviewed protocol implementation is deployed.
