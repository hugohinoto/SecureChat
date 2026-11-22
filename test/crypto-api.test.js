import test from "node:test";
import assert from "node:assert/strict";
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
    return { meta: { changes: 1 } };
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

test("device revocation queues per-conversation invalidation to all surviving devices", async () => {
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
    notifiedDevices: 2
  });
  assert.equal(db.batches.length, 2);
  const notificationSql = db.batches[1].map(statement => statement.sql);
  assert.equal(notificationSql.length, 2);
  assert.ok(notificationSql.every(sql => sql.includes("'org.securechat.device_revoked'")));
  const recipients = db.batches[1].map(statement => statement.values.slice(1, 3));
  assert.deepEqual(recipients, [
    ["user-internal", "current-device-01"],
    ["peer-internal", "peer-device-0001"]
  ]);
});
