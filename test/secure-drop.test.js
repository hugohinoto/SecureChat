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
  validateSecureDropKeyEnvelope,
  verifySecureDropKeyEnvelopeSignature,
  runSecureDropMaintenance
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
    fileIv: base64(new Uint8Array(12)),
    senderUserId: "sender_01",
    senderSigningPublicKey: base64(new Uint8Array([4,...new Uint8Array(64)])),
    senderSignature: base64(new Uint8Array(64)),
    ciphertextSha256: "b".repeat(64)
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

test("server verifies sender ECDSA signatures over the envelope and ciphertext digest", async () => {
  const signer = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const senderSigningPublicKey = base64(new Uint8Array(await crypto.subtle.exportKey("raw", signer.publicKey)));
  const envelope = keyEnvelopeFixture();
  envelope.senderSigningPublicKey = senderSigningPublicKey;
  const fields = {
    version: envelope.version,
    algorithm: envelope.algorithm,
    recipientKeyFingerprint: envelope.recipientKeyFingerprint,
    ephemeralPublicKey: envelope.ephemeralPublicKey,
    salt: envelope.salt,
    iv: envelope.iv,
    wrappedFileKey: envelope.wrappedFileKey,
    fileIv: envelope.fileIv,
    senderUserId: envelope.senderUserId,
    senderSigningPublicKey: envelope.senderSigningPublicKey,
    ciphertextSha256: envelope.ciphertextSha256
  };
  const message = new TextEncoder().encode(
    "SecureChat SecureDrop sender signature v1\n" +
    envelope.senderUserId + "\n" + JSON.stringify(fields)
  );
  envelope.senderSignature = base64(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, signer.privateKey, message
  )));
  assert.equal(validateSecureDropKeyEnvelope(
    envelope, "a".repeat(64), "sender_01", senderSigningPublicKey
  ), true);
  assert.equal(await verifySecureDropKeyEnvelopeSignature(envelope), true);
  envelope.ciphertextSha256 = "c".repeat(64);
  assert.equal(await verifySecureDropKeyEnvelopeSignature(envelope), false);
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
      const statement = {
        values: [],
        bind(...values) { this.values=values; return this; },
        async first() {
          assert.ok(sql.includes("FROM secure_drop_transfers WHERE id=?"));
          if(sql.includes("recipient_user_id=?") && statement.values[1]!==transfer.recipient_user_id) return null;
          return transfer;
        }
      };
      return statement;
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

test("an in-flight pending upload is not deleted merely because its month-end expiry arrived", async () => {
  const source = await readFile(new URL("../worker/secure-drop.js", import.meta.url), "utf8");
  assert.match(
    source,
    /status='pending' AND updated_at<=\?\) OR \(status='deleting' AND updated_at<=\?\) OR \(status='ready' AND expires_at<=\?/
  );
  assert.doesNotMatch(
    source,
    /WHERE expires_at<=\? OR \(status IN \('pending','deleting'\)/
  );
});

test("monthly maintenance paginates old-month R2 objects and removes old D1 state only after the last page", async () => {
  const now = Date.parse("2026-11-24T04:00:00.000Z");
  const month = secureDropMonthKey(now);
  const batches = [];
  const db = {
    prepare(sql) {
      return {
        sql,
        bind() { return this; },
        async all() { return { results: [] }; },
        async first() {
          if(sql.includes("FROM secure_drop_maintenance")) {
            return { current_month: month, cursor: null, completed_at: null };
          }
          return null;
        }
      };
    },
    async batch(statements) { batches.push(statements.map(statement => statement.sql)); }
  };
  let listedPrefix = null;
  let deleted = [];
  const bucket = {
    async list(options) {
      listedPrefix=options.prefix;
      return {
        objects:[
          { key:"secure-drop/2026-10/old-file" },
          { key:"secure-drop/2026-11/current-file" }
        ],
        truncated:false
      };
    },
    async delete(keys) { deleted.push(...keys); }
  };
  const result = await runSecureDropMaintenance({ DB:db, SECURE_DROP_R2:bucket }, now);
  assert.deepEqual(result, { month, status:"ok" });
  assert.equal(listedPrefix, "secure-drop/");
  assert.deepEqual(deleted, ["secure-drop/2026-10/old-file"]);
  assert.equal(batches.length, 1);
  assert.ok(batches[0].some(sql => sql.includes("DELETE FROM secure_drop_transfers WHERE month_key<>?")));
});

test("monthly maintenance retains its cursor when R2 deletion fails so the next cron can retry", async () => {
  const now = Date.parse("2026-11-24T04:00:00.000Z");
  const month = secureDropMonthKey(now);
  let cursorUpdates=0;
  const db = {
    prepare(sql) {
      return {
        bind() { return this; },
        async all() { return { results: [] }; },
        async first() {
          if(sql.includes("FROM secure_drop_maintenance")) {
            return { current_month:month, cursor:null, completed_at:null };
          }
          return null;
        },
        async run() { cursorUpdates++; }
      };
    },
    async batch() { throw new Error("D1 finalization should not run after R2 failure"); }
  };
  const bucket = {
    async list() {
      return { objects:[{key:"secure-drop/2026-10/old-file"}], truncated:false };
    },
    async delete() { throw new Error("simulated R2 deletion outage"); }
  };
  const result = await runSecureDropMaintenance({ DB:db, SECURE_DROP_R2:bucket }, now);
  assert.deepEqual(result, { month, status:"retry_pending" });
  assert.equal(cursorUpdates, 0);
});

test("the sender cannot consume a recipient download allowance", async () => {
  const transferId = "01234567-89ab-4cde-8fab-0123456789ab";
  let r2Read = false;
  const db = {
    prepare(sql) {
      return {
        bind() { return this; },
        async first() { return null; }
      };
    }
  };
  const response = await handleSecureDropApi(
    new Request("https://securechat.invalid/api/secure-drop/download/" + transferId),
    {
      SECURE_DROP_R2: { async get() { r2Read=true; return { size:32, body:new Uint8Array(32) }; } },
      DB: db
    },
    {
      path: "/api/secure-drop/download/" + transferId,
      method: "GET",
      readCookie: () => "sender-session",
      getSession: async () => ({ id: "sender-user" }),
      sameOrigin: () => true,
      checkRateLimit: async () => true
    }
  );
  assert.equal(response.status, 404);
  assert.equal(r2Read, false);
});

test("upload billing accepts a size hint only when the measured stream matches it", async () => {
  const source = await readFile(new URL("../worker/secure-drop.js", import.meta.url), "utf8");
  assert.match(source, /X-Secure-Drop-Stored-Size/);
  assert.match(source, /contentLengthHeader !== storedSizeHeader/);
  assert.match(source, /actualBytes !== declaredStoredBytes/);
  assert.match(source, /Number\(storedObject\?\.size\) !== actualBytes/);
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(app, /X-Secure-Drop-Stored-Size/);
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
  const senderSigning = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const senderSigningPublic = base64(new Uint8Array(await crypto.subtle.exportKey("raw", senderSigning.publicKey)));
  const encrypted = await encryptSecureDropFile(
    file, recipientPublicKey, "sender_01", senderSigning.privateKey, senderSigningPublic
  );
  assert.ok(encrypted.storedSizeBytes >= 17);
  assert.ok(encrypted.storedSizeBytes < file.size + 256);
  assert.equal(encrypted.originalSizeBytes, file.size);
  assert.equal(encrypted.compression, "gzip");
  const header = Buffer.from(encrypted.encodedEnvelope.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  assert.deepEqual(JSON.parse(header), encrypted.envelope);

  const plaintext = await decryptSecureDropFile(
    encrypted.ciphertext,
    encrypted.envelope,
    recipient.privateKey,
    recipientPublicKey,
    "sender_01",
    senderSigningPublic
  );
  assert.equal(new TextDecoder().decode(plaintext.bytes), "SecureDrop confidential payload");
  assert.equal(plaintext.name, "secure-drop-file");
  assert.equal(plaintext.type, "application/octet-stream");

  const tampered = encrypted.ciphertext.slice();
  tampered[0] ^= 1;
  await assert.rejects(() => decryptSecureDropFile(
    tampered,
    encrypted.envelope,
    recipient.privateKey,
    recipientPublicKey,
    "sender_01",
    senderSigningPublic
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
    otherPublicKey,
    "sender_01",
    senderSigningPublic
  ), /SECURE_DROP_RECIPIENT_KEY_MISMATCH/);
});
