import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  deviceAuthorizationMessage,
  handleCryptoApi,
  matrixUserId,
  parseMatrixUserId
} from "../worker/crypto-api.js";

test("device authorization domain separates user, device, and both public identity keys", () => {
  const message = new TextDecoder().decode(
    deviceAuthorizationMessage("alice_01", "SC_12345678", "curve-key", "sign-key")
  );
  assert.equal(
    message,
    "SecureChat device authorization:v2\n@alice_01:securechat.invalid\nSC_12345678\ncurve-key\nsign-key"
  );
});

test("Matrix user IDs are canonical and reject foreign server names", () => {
  assert.equal(matrixUserId("alice_01"), "@alice_01:securechat.invalid");
  assert.equal(parseMatrixUserId("@alice_01:securechat.invalid"), "alice_01");
  assert.equal(parseMatrixUserId("@alice:example.org"), null);
  assert.equal(parseMatrixUserId("alice_01"), null);
});

test("crypto v2 routes fail closed when the explicit Worker feature flag is absent", async () => {
  const response = await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/status"),
    { DB: {} },
    { id: "user-id", user_id: "alice_01" },
    { url: new URL("https://securechat.invalid/api/crypto/status"), now: 1000 }
  );
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "CRYPTO_V2_DISABLED", enabled: false });
});

test("crypto v2 routes fail closed unless the feature flag is exactly true", async () => {
  for (const flag of [undefined, "false", "True", "1"]) {
    const response = await handleCryptoApi(
      new Request("https://securechat.invalid/api/crypto/status"),
      { DB: {}, SECURECHAT_CRYPTO_V2_ENABLED: flag },
      { id: "user-id", user_id: "alice_01" },
      { url: new URL("https://securechat.invalid/api/crypto/status"), now: 1000 }
    );
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "CRYPTO_V2_DISABLED", enabled: false });
  }
});


class RevokeTestStatement {
  constructor(db, sql) { this.db=db; this.sql=sql; this.values=[]; }
  bind(...values) { this.values=values; return this; }
  async first() {
    if (this.sql.includes("SELECT revoked_at FROM crypto_devices")) return { revoked_at: null };
    if (this.sql.includes("SELECT device_id, device_keys_json FROM crypto_devices")) {
      return {
        device_id: this.values[1],
        device_keys_json: JSON.stringify({ keys: { ["curve25519:"+this.values[1]]: "curve-key" } })
      };
    }
    return null;
  }
  async all() {
    if (this.sql.includes("SELECT mine.conversation_id")) {
      return { results: [{ conversation_id: "11111111-1111-4111-8111-111111111111", peer_user_id: "peer_01" }] };
    }
    if (this.sql.includes("SELECT user_id, device_id FROM crypto_devices")) {
      return { results: [
        { user_id: "user-internal", device_id: "current-device-01" },
        { user_id: "peer-internal", device_id: "peer-device-0001" }
      ] };
    }
    return { results: [] };
  }
  async run() {
    this.db.statements.push({ sql: this.sql, values: this.values });
    return { meta: { changes: this.sql.includes("INSERT OR IGNORE INTO crypto_to_device_inbox") ? 2 : 1 } };
  }
}

class RevokeTestDB {
  constructor() { this.statements=[]; this.batches=[]; }
  prepare(sql) { return new RevokeTestStatement(this, sql); }
  async batch(statements) {
    this.batches.push(statements);
    return statements.map(() => ({ meta: { changes: 1 } }));
  }
}

test("device revocation rejects revoking the current device", async () => {
  const db = new RevokeTestDB();
  const response = await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/devices/current-device-01/revoke", {
      method: "POST",
      headers: { "X-SecureChat-Device": "current-device-01" }
    }),
    { DB: db, SECURECHAT_CRYPTO_V2_ENABLED: "true" },
    { id: "user-internal", user_id: "alice_01" },
    { url: new URL("https://securechat.invalid/api/crypto/devices/current-device-01/revoke"), now: 1000 }
  );
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "CRYPTO_CANNOT_REVOKE_CURRENT_DEVICE");
  assert.equal(db.batches.length, 0);
});

test("device revocation uses one set-based query to notify every surviving account device", async () => {
  const db = new RevokeTestDB();
  const response = await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/devices/revoked-device-0001/revoke", {
      method: "POST",
      headers: { "X-SecureChat-Device": "current-device-01" }
    }),
    { DB: db, SECURECHAT_CRYPTO_V2_ENABLED: "true" },
    { id: "user-internal", user_id: "alice_01" },
    { url: new URL("https://securechat.invalid/api/crypto/devices/revoked-device-0001/revoke"), now: 1000 }
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    revoked: true,
    deviceId: "revoked-device-0001",
    notifiedDevices: 2,
    notificationQueuedAt: 1000
  });
  assert.equal(db.batches.length, 1);
  const notification = db.statements.find(statement =>
    statement.sql.includes("INSERT OR IGNORE INTO crypto_to_device_inbox")
  );
  assert.ok(notification);
  assert.ok(notification.sql.includes("'org.securechat.device_revoked'"));
  assert.ok(notification.sql.includes("FROM crypto_devices recipient"));
  assert.ok(notification.sql.includes("UNION"));
  assert.equal(notification.values[0], "user-internal");
  assert.equal(notification.values[1], "current-device-01");
  assert.equal(notification.values[2], "@alice_01:securechat.invalid");
  assert.equal(notification.values[3], "revoked-device-0001");
});


test("clients cannot forge the server-only device revocation event", async () => {
  const db = new RevokeTestDB();
  const response = await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/to-device", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SecureChat-Device": "current-device-01"
      },
      body: JSON.stringify({
        event_type: "org.securechat.device_revoked",
        transaction_id: "attacker-generated-event-01",
        messages: { "@peer_01:securechat.invalid": { "peer-device-0001": { conversation_id: "11111111-1111-4111-8111-111111111111" } } }
      })
    }),
    { DB: db, SECURECHAT_CRYPTO_V2_ENABLED: "true" },
    { id: "user-internal", user_id: "alice_01" },
    { url: new URL("https://securechat.invalid/api/crypto/to-device"), now: 1000 }
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "CRYPTO_TO_DEVICE_INVALID");
  assert.equal(db.batches.length, 0);
});


class AckTestStatement {
  constructor(db, sql) { this.db=db; this.sql=sql; this.values=[]; }
  bind(...values) { this.values=values; return this; }
  async first() {
    if (this.sql.includes("SELECT device_id, device_keys_json FROM crypto_devices")) {
      return { device_id:this.values[1], device_keys_json:"{}" };
    }
    return null;
  }
  async run() {
    this.db.lastStatement={sql:this.sql,values:this.values};
    return {meta:{changes:this.sql.startsWith("DELETE FROM crypto_to_device_inbox")?1:0}};
  }
}
class AckTestDB {
  prepare(sql) { return new AckTestStatement(this,sql); }
}
test("inbox acknowledgement accepts compact 32-hex server-generated event IDs", async () => {
  const db=new AckTestDB();
  const response=await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/sync/ack",{
      method:"POST",
      headers:{"Content-Type":"application/json","X-SecureChat-Device":"device-00000001"},
      body:JSON.stringify({event_ids:["0123456789abcdef0123456789abcdef"]})
    }),
    {DB:db,SECURECHAT_CRYPTO_V2_ENABLED:"true"},
    {id:"user-internal",user_id:"alice_01"},
    {url:new URL("https://securechat.invalid/api/crypto/sync/ack"),now:1000}
  );
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{acknowledged:1});
  assert.ok(db.lastStatement.sql.startsWith("DELETE FROM crypto_to_device_inbox"));
});

test("Megolm envelopes accept standard base64 session identifiers", () => {
  const source = readFileSync(new URL("../worker/crypto-api.js", import.meta.url), "utf8");
  assert.ok(source.includes("A-Za-z0-9+/_-"));
});


test("keys-query adapter returns the full Matrix response envelope", () => {
  const source = readFileSync(new URL("../worker/crypto-api.js", import.meta.url), "utf8");
  assert.ok(source.includes("master_keys: {}, self_signing_keys: {}, user_signing_keys: {}"));
  assert.ok(source.includes("device_authorizations: deviceAuthorizations"));
});


class ForwardSecrecyTestStatement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.values = []; }
  bind(...values) { this.values = values; return this; }
  async first() {
    if (this.sql.includes("SELECT device_id, device_keys_json FROM crypto_devices")) {
      return {
        device_id: this.values[1],
        device_keys_json: JSON.stringify({
          keys: { ["curve25519:" + this.values[1]]: "A".repeat(43) }
        })
      };
    }
    if (this.sql.includes("SELECT 1 AS ok FROM verified_contact_pairs")) return { ok: 1 };
    if (this.sql.includes("SELECT protocol_version FROM conversation_crypto_modes")) return { protocol_version: 2 };
    if (this.sql.includes("SELECT 1 AS ready FROM crypto_used_megolm_sessions")) {
      if (!this.db.ledgerAvailable) throw new Error("no such table: crypto_used_megolm_sessions");
      return { ready: 1 };
    }
    if (this.sql.includes("SELECT COUNT(*) AS count FROM crypto_devices")) return { count: 1 };
    return null;
  }
  async all() {
    if (this.sql.includes("SELECT peer.user_id AS peer_id")) return { results: [{ peer_id: "peer-internal" }] };
    return { results: [] };
  }
  async run() {
    return { meta: { changes: 1 } };
  }
}

class ForwardSecrecyTestDB {
  constructor({ ledgerAvailable = true } = {}) {
    this.ledgerAvailable = ledgerAvailable;
    this.sessions = new Map();
    this.messages = [];
  }
  prepare(sql) { return new ForwardSecrecyTestStatement(this, sql); }
  async batch(statements) {
    const [ledger, message] = statements;
    const [conversationId, senderId, deviceId, sessionId, messageId] = ledger.values;
    const key = senderId + ":" + deviceId + ":" + sessionId;
    const inserted = !this.sessions.has(key);
    if (inserted) this.sessions.set(key, { conversationId, messageId });
    const [messageIdFromInsert, , , , , , , , , , sessionIdFromInsert, ledgerMessageId] = message.values;
    const ledgerEntry = this.sessions.get(key);
    const messageInserted = inserted && ledgerEntry?.messageId === ledgerMessageId &&
      sessionIdFromInsert === sessionId && messageIdFromInsert === messageId;
    if (messageInserted) this.messages.push(message.values);
    return [
      { meta: { changes: inserted ? 1 : 0 } },
      { meta: { changes: messageInserted ? 1 : 0 } }
    ];
  }
}

const fsConversationA = "11111111-1111-4111-8111-111111111111";
const fsConversationB = "22222222-2222-4222-8222-222222222222";
const fsDeviceId = "SC_1234567890abcdef1234567890123456";
const fsRequest = (conversationId, sessionId) => new Request(
  "https://securechat.invalid/api/crypto/conversations/" + conversationId + "/messages",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-SecureChat-Device": fsDeviceId
    },
    body: JSON.stringify({
      encrypted_event: {
        algorithm: "m.megolm.v1.aes-sha2",
        ciphertext: "A".repeat(96),
        session_id: sessionId,
        sender_key: "A".repeat(43),
        device_id: fsDeviceId
      }
    })
  }
);
const fsSession = { id: "alice-internal", user_id: "alice_01" };
const fsEnv = db => ({ DB: db, SECURECHAT_CRYPTO_V2_ENABLED: "true" });

test("server rejects a reused Megolm session ID and accepts the next one-time session", async () => {
  const db = new ForwardSecrecyTestDB();
  const send = (conversationId, sessionId) => handleCryptoApi(
    fsRequest(conversationId, sessionId),
    fsEnv(db),
    fsSession,
    { url: new URL("https://securechat.invalid/api/crypto/conversations/" + conversationId + "/messages"), now: 5000 }
  );
  const first = await send(fsConversationA, "megolm-session-0001");
  assert.equal(first.status, 201);
  const replay = await send(fsConversationA, "megolm-session-0001");
  assert.equal(replay.status, 409);
  assert.equal((await replay.json()).error, "CRYPTO_MEGOLM_SESSION_REUSED");
  const next = await send(fsConversationA, "megolm-session-0002");
  assert.equal(next.status, 201);
  assert.equal(db.sessions.size, 2);
  assert.equal(db.messages.length, 2);
});

test("Megolm session IDs cannot be reused across conversations by the same device", async () => {
  const db = new ForwardSecrecyTestDB();
  const send = (conversationId, sessionId) => handleCryptoApi(
    fsRequest(conversationId, sessionId),
    fsEnv(db),
    fsSession,
    { url: new URL("https://securechat.invalid/api/crypto/conversations/" + conversationId + "/messages"), now: 5000 }
  );
  assert.equal((await send(fsConversationA, "global-session-0001")).status, 201);
  const replay = await send(fsConversationB, "global-session-0001");
  assert.equal(replay.status, 409);
  assert.equal((await replay.json()).error, "CRYPTO_MEGOLM_SESSION_REUSED");
  assert.equal(db.messages.length, 1);
});

test("crypto status refuses to claim forward secrecy when the D1 session ledger is missing", async () => {
  const db = new ForwardSecrecyTestDB({ ledgerAvailable: false });
  const response = await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/status"),
    fsEnv(db),
    fsSession,
    { url: new URL("https://securechat.invalid/api/crypto/status"), now: 5000 }
  );
  assert.equal(response.status, 503);
  const result = await response.json();
  assert.equal(result.forwardSecrecyRequired, true);
  assert.equal(result.forwardSecrecyReady, false);
  assert.equal(result.error, "CRYPTO_FORWARD_SECRECY_STORAGE_UNAVAILABLE");
});

test("crypto status reports forward secrecy ready only after the ledger can be queried", async () => {
  const db = new ForwardSecrecyTestDB();
  const response = await handleCryptoApi(
    new Request("https://securechat.invalid/api/crypto/status"),
    fsEnv(db),
    fsSession,
    { url: new URL("https://securechat.invalid/api/crypto/status"), now: 5000 }
  );
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.forwardSecrecyRequired, true);
  assert.equal(result.forwardSecrecyReady, true);
  assert.equal(result.sessionRotationMessages, 1);
});
