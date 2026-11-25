import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { createDeviceVaultRecord, unlockDeviceVaultRecord } from "../public/device-vault.js";

const USER = "alice_01";
const DEVICE = "SC_0123456789abcdef0123456789abcdef";
const PASSPHRASE = "securechat-test-store-passphrase-32-bytes";

test("device vault uses a non-extractable HKDF root and a user/device-bound AES-256-GCM key", async () => {
  const record = await createDeviceVaultRecord(USER, DEVICE, PASSPHRASE, webcrypto);
  assert.equal(record.version, 2);
  assert.equal(record.rootKey.algorithm.name, "HKDF");
  assert.equal(record.rootKey.extractable, false);
  assert.equal(record.salt.byteLength, 32);
  assert.equal(record.iv.byteLength, 12);
  const unlocked = await unlockDeviceVaultRecord(record, USER, webcrypto);
  assert.equal(unlocked.storePassphrase, PASSPHRASE);
  assert.equal(unlocked.upgradedRecord, null);
  await assert.rejects(
    () => unlockDeviceVaultRecord(record, "bob_02", webcrypto),
    error => error.code === "CRYPTO_VAULT_IDENTITY_MISMATCH"
  );
});

test("device vault rejects a record copied to another device identity", async () => {
  const record = await createDeviceVaultRecord(USER, DEVICE, PASSPHRASE, webcrypto);
  const copied = { ...record, deviceId: "SC_abcdef0123456789abcdef0123456789" };
  await assert.rejects(
    () => unlockDeviceVaultRecord(copied, USER, webcrypto),
    error => error.code === "CRYPTO_VAULT_DECRYPT_FAILED"
  );
});

test("legacy AES-GCM vault records upgrade without changing the Olm store passphrase or device ID", async () => {
  const wrappingKey = await webcrypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv }, wrappingKey, new TextEncoder().encode(PASSPHRASE)
  );
  const legacy = { userId: USER, deviceId: DEVICE, wrappingKey, iv, ciphertext, createdAt: 123456 };
  const result = await unlockDeviceVaultRecord(legacy, USER, webcrypto);
  assert.equal(result.storePassphrase, PASSPHRASE);
  assert.equal(result.upgradedRecord.version, 2);
  assert.equal(result.upgradedRecord.deviceId, DEVICE);
  assert.equal(result.upgradedRecord.createdAt, 123456);
  assert.equal(result.upgradedRecord.rootKey.extractable, false);
  const reopened = await unlockDeviceVaultRecord(result.upgradedRecord, USER, webcrypto);
  assert.equal(reopened.storePassphrase, PASSPHRASE);
  assert.equal(reopened.upgradedRecord, null);
});
