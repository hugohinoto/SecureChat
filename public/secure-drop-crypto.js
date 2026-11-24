const FILE_KEY_LENGTH = 32;
const MAX_FILE_BYTES = 100_000_000;
const ENVELOPE_ALGORITHM = "ECDH-P256-HKDF-SHA256-AES-GCM-256";
const encoder = new TextEncoder();

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function fromBase64(value) {
  if (typeof value !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("SECURE_DROP_KEY_ENCODING_INVALID");
  }
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}
function toHex(bytes) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function publicKeyFingerprint(publicKeyBase64) {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(publicKeyBase64)));
}
function envelopeAad(fingerprint) {
  return encoder.encode("SecureChat SecureDrop key envelope v1\n" + fingerprint);
}
function fileAad(fingerprint) {
  return encoder.encode("SecureChat SecureDrop file payload v1\n" + fingerprint);
}
async function deriveWrappingKey(privateKey, publicKey, salt, fingerprint) {
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey }, privateKey, 256
  ));
  try {
    const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: envelopeAad(fingerprint)
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    sharedSecret.fill(0);
  }
}
async function wrapFileKey(fileKeyBytes, recipientPublicKeyBase64, fileIv) {
  const fingerprint = await publicKeyFingerprint(recipientPublicKeyBase64);
  const recipientPublicKey = await crypto.subtle.importKey(
    "raw", fromBase64(recipientPublicKeyBase64),
    { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(ephemeral.privateKey, recipientPublicKey, salt, fingerprint);
  const wrappedFileKey = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: wrapIv, additionalData: envelopeAad(fingerprint) },
    wrappingKey,
    fileKeyBytes
  );
  return {
    version: 1,
    algorithm: ENVELOPE_ALGORITHM,
    recipientKeyFingerprint: fingerprint,
    ephemeralPublicKey: toBase64(new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey))),
    salt: toBase64(salt),
    iv: toBase64(wrapIv),
    wrappedFileKey: toBase64(new Uint8Array(wrappedFileKey)),
    fileIv: toBase64(fileIv)
  };
}
async function unwrapFileKey(envelope, recipientPrivateKey, recipientPublicKeyBase64) {
  const fingerprint = await publicKeyFingerprint(recipientPublicKeyBase64);
  if (!envelope || envelope.version !== 1 ||
      envelope.algorithm !== ENVELOPE_ALGORITHM ||
      envelope.recipientKeyFingerprint !== fingerprint) {
    throw new Error("SECURE_DROP_RECIPIENT_KEY_MISMATCH");
  }
  const ephemeralPublicKey = await crypto.subtle.importKey(
    "raw", fromBase64(envelope.ephemeralPublicKey),
    { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const salt = fromBase64(envelope.salt);
  const wrapIv = fromBase64(envelope.iv);
  const wrappingKey = await deriveWrappingKey(recipientPrivateKey, ephemeralPublicKey, salt, fingerprint);
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: wrapIv, additionalData: envelopeAad(fingerprint) },
    wrappingKey,
    fromBase64(envelope.wrappedFileKey)
  );
  if (raw.byteLength !== FILE_KEY_LENGTH) throw new Error("SECURE_DROP_FILE_KEY_INVALID");
  return new Uint8Array(raw);
}

export function encodeSecureDropKeyEnvelope(envelope) {
  const bytes = encoder.encode(JSON.stringify(envelope));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function encryptSecureDropFile(file, recipientPublicKeyBase64) {
  if (!(file instanceof Blob) || file.size < 1 || file.size > MAX_FILE_BYTES) {
    throw new RangeError("SECURE_DROP_FILE_SIZE_INVALID");
  }
  if (typeof recipientPublicKeyBase64 !== "string") {
    throw new TypeError("SECURE_DROP_RECIPIENT_KEY_REQUIRED");
  }
  const plaintext = await file.arrayBuffer();
  const fileKeyBytes = crypto.getRandomValues(new Uint8Array(FILE_KEY_LENGTH));
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  try {
    const fingerprint = await publicKeyFingerprint(recipientPublicKeyBase64);
    const fileKey = await crypto.subtle.importKey(
      "raw", fileKeyBytes, { name: "AES-GCM" }, false, ["encrypt"]
    );
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: fileIv, additionalData: fileAad(fingerprint) },
      fileKey,
      plaintext
    );
    if (ciphertext.byteLength > MAX_FILE_BYTES) throw new RangeError("SECURE_DROP_ENCRYPTED_FILE_TOO_LARGE");
    const envelope = await wrapFileKey(fileKeyBytes, recipientPublicKeyBase64, fileIv);
    return {
      ciphertext: new Uint8Array(ciphertext),
      envelope,
      encodedEnvelope: encodeSecureDropKeyEnvelope(envelope),
      originalSizeBytes: file.size,
      storedSizeBytes: ciphertext.byteLength
    };
  } finally {
    fileKeyBytes.fill(0);
  }
}

export async function decryptSecureDropFile(ciphertext, envelope, recipientPrivateKey, recipientPublicKeyBase64) {
  const bytes = ciphertext instanceof ArrayBuffer
    ? ciphertext
    : ArrayBuffer.isView(ciphertext)
      ? ciphertext.buffer.slice(ciphertext.byteOffset, ciphertext.byteOffset + ciphertext.byteLength)
      : null;
  if (!bytes || bytes.byteLength < 17 || bytes.byteLength > MAX_FILE_BYTES) {
    throw new RangeError("SECURE_DROP_CIPHERTEXT_SIZE_INVALID");
  }
  const fileKeyBytes = await unwrapFileKey(envelope, recipientPrivateKey, recipientPublicKeyBase64);
  try {
    const fileKey = await crypto.subtle.importKey(
      "raw", fileKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]
    );
    const fingerprint = await publicKeyFingerprint(recipientPublicKeyBase64);
    const fileIv = fromBase64(envelope.fileIv);
    if (fileIv.byteLength !== 12) throw new Error("SECURE_DROP_FILE_IV_INVALID");
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fileIv, additionalData: fileAad(fingerprint) },
      fileKey,
      bytes
    ));
  } finally {
    fileKeyBytes.fill(0);
  }
}

export const SECURE_DROP_CRYPTO = Object.freeze({
  algorithm: ENVELOPE_ALGORITHM,
  maxFileBytes: MAX_FILE_BYTES,
  fileKeyBytes: FILE_KEY_LENGTH
});
