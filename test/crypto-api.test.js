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
