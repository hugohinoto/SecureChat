import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import {
  createMeteredBody,
  handleSecureDropApi,
  secureDropCreditsForBytes,
  secureDropMonthKey,
  secureDropNextMonthStart,
  validateSecureDropKeyEnvelope
} from "../worker/secure-drop.js";
import {
  decryptSecureDropFile,
  encodeSecureDropKeyEnvelope,
  encryptSecureDropFile
} from "../public/secure-drop-crypto.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function keyEnvelopeFixture(fingerprint = "a".repeat(64)) {
  const ephemeral = new Uint8Array(65);
  ephemeral[0] = 4;
  return {
    version: 1,
    algorithm: "ECDH-P256-HKDF-SHA256-AES-GCM-256",
    recipientKeyFingerprint: fingerprint,
    ephemeralPublicKey: base64(ephemeral),
    salt: base64(new Uint8Array(16)),
    iv: base64(new Uint8Array(12)),
    wrappedFileKey: base64(new Uint8Array(48)),
    fileIv: base64(new Uint8Array(12))
  };
}

test("SecureDrop month accounting changes at midnight Japan time", () => {
  const beforeReset = Date.parse("2026-11-30T14:59:59.999Z");
  const reset = Date.parse("2026-11-30T15:00:00.000Z");
  assert.equal(secureDropMonthKey(beforeReset), "2026-11");
  assert.equal(secureDropNextMonthStart(beforeReset), reset);
  assert.equal(secureDropMonthKey(reset), "2026-12");
  assert.equal(secureDropNextMonthStart(reset), Date.parse("2026-12-31T15:00:00.000Z"));
});

test("SecureDrop charges from measured stored bytes using decimal MB rounding", () => {
  assert.equal(secureDropCreditsForBytes(1), 1);
  assert.equal(secureDropCreditsForBytes(1_000_000), 1);
  assert.equal(secureDropCreditsForBytes(1_000_001), 2);
  assert.equal(secureDropCreditsForBytes(100_000_000), 100);
  assert.throws(() => secureDropCreditsForBytes(0), /INVALID_STORED_SIZE/);
  assert.throws(() => secureDropCreditsForBytes(100_000_001), /INVALID_STORED_SIZE/);
});

test("recipient key envelopes require a P-256 ephemeral key, wrapped key, payload IV and matching fingerprint", () => {
  const envelope = keyEnvelopeFixture();
  assert.equal(validateSecureDropKeyEnvelope(envelope, "a".repeat(64)), true);
  assert.equal(validateSecureDropKeyEnvelope(envelope, "b".repeat(64)), false);
  assert.equal(validateSecureDropKeyEnvelope({ ...envelope, fileIv: "" }, "a".repeat(64)), false);
  assert.equal(validateSecureDropKeyEnvelope({ ...envelope, algorithm: "AES-CBC" }, "a".repeat(64)), false);
});

test("metered upload streams count actual bytes and enforce the hard limit", async () => {
  const input = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2]));
      controller.enqueue(new Uint8Array([3, 4]));
      controller.close();
    }
  });
  const metered = createMeteredBody(input, 4);
  const stored = await new Response(metered.stream).arrayBuffer();
  assert.equal(stored.byteLength, 4);
  assert.equal(metered.state.bytes, 4);
  assert.equal(metered.state.finished, true);

  const oversized = createMeteredBody(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      controller.close();
    }
  }), 2);
  await assert.rejects(() => new Response(oversized.stream).arrayBuffer());
  assert.equal(oversized.state.bytes, 3);
});

test("a download bearer token alone cannot access SecureDrop", async () => {
  const transferId = "01234567-89ab-4cde-8fab-0123456789ab";
  const response = await handleSecureDropApi(
    new Request("https://securechat.invalid/api/secure-drop/download/" + transferId, {
      headers: { "X-Secure-Drop-Token": "A".repeat(43) }
    }),
    { SECURE_DROP_R2: {}, DB: { prepare() { throw new Error("DB must not be read"); } } },
    {
      path: "/api/secure-drop/download/" + transferId,
      method: "GET",
      readCookie: () => null,
      getSession: async () => null,
      sameOrigin: () => true,
      checkRateLimit: async () => true
    }
  );
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error, "UNAUTHENTICATED");
});

test("a logged-in user who is neither sender nor recipient cannot consume a download", async () => {
  const transferId = "01234567-89ab-4cde-8fab-0123456789ab";
  const currentMonth = secureDropMonthKey(Date.now());
  let r2Read = false;
  const transfer = {
    object_key: "secure-drop/" + currentMonth + "/" + transferId,
    stored_size_bytes: 32,
    expires_at: Date.now() + 60_000,
    month_key: currentMonth,
    download_count: 0,
    status: "ready",
    user_id: "sender-user",
    recipient_user_id: "recipient-user"
  };
  const db = {
    prepare(sql) {
      return {
        bind() { return this; },
        async first() {
          assert.match(sql, /FROM secure_drop_transfers WHERE id=\?/);
          return transfer;
        }
      };
    }
  };
  const response = await handleSecureDropApi(
    new Request("https://securechat.invalid/api/secure-drop/download/" + transferId),
    {
      SECURE_DROP_R2: { async get() { r2Read = true; return { size: 32, body: new Uint8Array(32) }; } },
      DB: db
    },
    {
      path: "/api/secure-drop/download/" + transferId,
      method: "GET",
      readCookie: () => "valid-session",
      getSession: async () => ({ id: "unrelated-user" }),
      sameOrigin: () => true,
      checkRateLimit: async () => true
    }
  );
  assert.equal(response.status, 404);
  assert.equal(r2Read, false);
});

test("SecureDrop downloads use a conditional atomic three-download update", async () => {
  const source = await readFile(new URL("../worker/secure-drop.js", import.meta.url), "utf8");
  assert.match(source, /download_count=download_count\+1[\s\S]*?status='ready'[\s\S]*?download_count<3/);
  assert.match(source, /recipient_user_id=\?/);
  assert.doesNotMatch(source, /downloadToken/);
});

test("browser file encryption wraps the AES-GCM key to the recipient identity and detects tampering", async () => {
  const recipient = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const recipientPublicKey = base64(new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey)));
  const file = new Blob([new TextEncoder().encode("SecureDrop confidential payload")], {
    type: "application/octet-stream"
  });
  const encrypted = await encryptSecureDropFile(file, recipientPublicKey);
  assert.equal(encrypted.storedSizeBytes, file.size + 16);
  assert.equal(encrypted.originalSizeBytes, file.size);
  const header = Buffer.from(encrypted.encodedEnvelope.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  assert.deepEqual(JSON.parse(header), encrypted.envelope);

  const plaintext = await decryptSecureDropFile(
    encrypted.ciphertext,
    encrypted.envelope,
    recipient.privateKey,
    recipientPublicKey
  );
  assert.equal(new TextDecoder().decode(plaintext), "SecureDrop confidential payload");

  const tampered = encrypted.ciphertext.slice();
  tampered[0] ^= 1;
  await assert.rejects(() => decryptSecureDropFile(
    tampered,
    encrypted.envelope,
    recipient.privateKey,
    recipientPublicKey
  ));

  const other = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const otherPublicKey = base64(new Uint8Array(await crypto.subtle.exportKey("raw", other.publicKey)));
  await assert.rejects(() => decryptSecureDropFile(
    encrypted.ciphertext,
    encrypted.envelope,
    other.privateKey,
    otherPublicKey
  ), /SECURE_DROP_RECIPIENT_KEY_MISMATCH/);
});
