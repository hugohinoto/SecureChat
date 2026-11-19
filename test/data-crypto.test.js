import test from "node:test";
import assert from "node:assert/strict";
import { encryptStored, decryptStored } from "../worker/data-crypto.js";

const env = { APP_DATA_ENCRYPTION_KEY: "securechat-test-key-material-at-least-32-bytes-long" };

test("application data is encrypted and decrypts with its bound context", async () => {
  const value = "private report details";
  const encrypted = await encryptStored(env, "bug-report:abc", value);
  assert.match(encrypted, /^enc:v1:/);
  assert.ok(!encrypted.includes(value));
  assert.equal(await decryptStored(env, "bug-report:abc", encrypted), value);
});

test("encrypted data cannot be opened under a different record context", async () => {
  const encrypted = await encryptStored(env, "announcement:one:title", "private title");
  await assert.rejects(() => decryptStored(env, "announcement:two:title", encrypted));
});

test("tampered ciphertext is rejected by AES-GCM authentication", async () => {
  const encrypted = await encryptStored(env, "admin-audit:log-1", "{\"event\":\"login\"}");
  const parts = encrypted.split(":");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  await assert.rejects(() => decryptStored(env, "admin-audit:log-1", parts.join(":")));
});

test("encryption fails closed when the application key is missing", async () => {
  await assert.rejects(() => encryptStored({}, "test", "no plaintext fallback"), /APP_DATA_ENCRYPTION_KEY_NOT_CONFIGURED/);
});
