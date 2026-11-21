const encoder = new TextEncoder();

function decodeBase64(value) {
  if (typeof value !== "string" || value.length > 512 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("IDENTITY_KEY_ENCODING_INVALID");
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

export function identityKeyProofMessage(userId, identityPublicKey) {
  if (typeof userId !== "string" || !/^[a-z0-9_]{3,32}$/.test(userId) || typeof identityPublicKey !== "string" || identityPublicKey.length > 256) throw new Error("IDENTITY_KEY_PROOF_INPUT_INVALID");
  return encoder.encode("SecureChat identity-key-proof:v1\n" + userId + "\n" + identityPublicKey);
}

export async function verifyIdentityKeyProof({ userId, identityPublicKey, identitySigningPublicKey, identityKeySignature }) {
  try {
    const identity = decodeBase64(identityPublicKey), signing = decodeBase64(identitySigningPublicKey), signature = decodeBase64(identityKeySignature);
    if (identity.length !== 65 || identity[0] !== 4 || signing.length !== 65 || signing[0] !== 4 || signature.length !== 64) return false;
    const publicKey = await crypto.subtle.importKey("raw", signing, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, identityKeyProofMessage(userId, identityPublicKey));
  } catch { return false; }
}


export function identityKeyTransitionMessage(userId, previousSigningPublicKey, identityPublicKey, identitySigningPublicKey) {
  if (typeof userId !== "string" || !/^[a-z0-9_]{3,32}$/.test(userId) ||
      typeof previousSigningPublicKey !== "string" || previousSigningPublicKey.length > 256 ||
      typeof identityPublicKey !== "string" || identityPublicKey.length > 256 ||
      typeof identitySigningPublicKey !== "string" || identitySigningPublicKey.length > 256) {
    throw new Error("IDENTITY_KEY_TRANSITION_INPUT_INVALID");
  }
  return encoder.encode(
    "SecureChat identity-key-transition:v1\n" + userId + "\n" +
    previousSigningPublicKey + "\n" + identityPublicKey + "\n" + identitySigningPublicKey
  );
}

export async function verifyIdentityKeyTransition({
  userId,
  previousSigningPublicKey,
  identityPublicKey,
  identitySigningPublicKey,
  identityTransitionSignature
}) {
  try {
    const previous = decodeBase64(previousSigningPublicKey);
    const identity = decodeBase64(identityPublicKey);
    const signing = decodeBase64(identitySigningPublicKey);
    const signature = decodeBase64(identityTransitionSignature);
    if (previous.length !== 65 || previous[0] !== 4 ||
        identity.length !== 65 || identity[0] !== 4 ||
        signing.length !== 65 || signing[0] !== 4 ||
        signature.length !== 64) return false;
    const publicKey = await crypto.subtle.importKey(
      "raw", previous, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      identityKeyTransitionMessage(userId, previousSigningPublicKey, identityPublicKey, identitySigningPublicKey)
    );
  } catch {
    return false;
  }
}
