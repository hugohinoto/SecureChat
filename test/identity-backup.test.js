import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  IDENTITY_BACKUP_ITERATIONS,
  encryptIdentityBackup,
  decryptIdentityBackup
} from "../public/identity-backup.js";

const b64 = bytes => Buffer.from(bytes).toString("base64");
const PASSWORD = "correct horse battery staple 2026";

async function createPayload() {
  const ecdh = await webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const signing = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  return {
    version: 1,
    identityPublicKey: b64(await webcrypto.subtle.exportKey("raw", ecdh.publicKey)),
    identitySigningPublicKey: b64(await webcrypto.subtle.exportKey("raw", signing.publicKey)),
    ecdhPrivateJwk: await webcrypto.subtle.exportKey("jwk", ecdh.privateKey),
    signingPrivateJwk: await webcrypto.subtle.exportKey("jwk", signing.privateKey)
  };
}

test("identity backup uses PBKDF2-SHA256 and an authenticated AES-GCM envelope", async () => {
  assert.equal(IDENTITY_BACKUP_ITERATIONS, 250000);
  const payload = await createPayload();
  const backup = await encryptIdentityBackup(payload, PASSWORD, webcrypto);
  assert.equal(backup.version, 1);
  assert.equal(Buffer.from(backup.salt, "base64").length, 16);
  assert.equal(Buffer.from(backup.iv, "base64").length, 12);
  assert.ok(Buffer.from(backup.ciphertext, "base64").length > 64);
  assert.ok(!backup.ciphertext.includes(payload.ecdhPrivateJwk.d));

  const restored = await decryptIdentityBackup(backup, PASSWORD, webcrypto);
  assert.equal(restored.publicKey, payload.identityPublicKey);
  assert.equal(restored.signingPublicKey, payload.identitySigningPublicKey);
  assert.equal(restored.backupPayload.identityPublicKey, payload.identityPublicKey);
  assert.equal(restored.privateKey.extractable, false);
  assert.equal(restored.signingPrivateKey.extractable, false);

  const peer = await webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const originalPrivate = await webcrypto.subtle.importKey(
    "jwk", payload.ecdhPrivateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]
  );
  const peerSecret = await webcrypto.subtle.deriveBits(
    { name: "ECDH", public: peer.publicKey }, originalPrivate, 256
  );
  const restoredSecret = await webcrypto.subtle.deriveBits(
    { name: "ECDH", public: peer.publicKey }, restored.privateKey, 256
  );
  assert.deepEqual(Buffer.from(restoredSecret), Buffer.from(peerSecret));
});

test("identity backup rejects a wrong password and tampered ciphertext", async () => {
  const backup = await encryptIdentityBackup(await createPayload(), PASSWORD, webcrypto);
  await assert.rejects(
    () => decryptIdentityBackup(backup, "wrong password", webcrypto),
    error => error.code === "IDENTITY_BACKUP_PASSWORD_MISMATCH"
  );
  const tampered = { ...backup, ciphertext: b64(Buffer.alloc(Buffer.from(backup.ciphertext, "base64").length, 0)) };
  await assert.rejects(
    () => decryptIdentityBackup(tampered, PASSWORD, webcrypto),
    error => error.code === "IDENTITY_BACKUP_PASSWORD_MISMATCH"
  );
});

test("identity backup rejects malformed envelopes", async () => {
  await assert.rejects(
    () => decryptIdentityBackup({ version: 1, salt: "bad", iv: "bad", ciphertext: "bad" }, PASSWORD, webcrypto),
    error => error.code === "IDENTITY_BACKUP_PASSWORD_MISMATCH"
  );
});
