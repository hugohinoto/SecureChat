import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const refreshCss = readFileSync(new URL("../public/ui-refresh.css", import.meta.url), "utf8");

test("refreshed UI stylesheet is loaded after the legacy stylesheet", () => {
  const legacy = html.indexOf('href="/styles.css"');
  const refreshed = html.indexOf('href="/ui-refresh.css"');
  assert.notEqual(legacy, -1);
  assert.notEqual(refreshed, -1);
  assert.ok(refreshed > legacy);
});

test("all static DOM IDs referenced by the application remain present", () => {
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
  const selectors = [...app.matchAll(/\$\("#([^"]+)"\)/g)].map(match => match[1]);
  assert.ok(selectors.length > 0, "expected to find application DOM selectors");
  const missing = [...new Set(selectors)].filter(id => !ids.has(id));
  assert.deepEqual(missing, []);
});

test("refreshed UI includes keyboard focus, reduced-motion, and mobile navigation styles", () => {
  assert.match(refreshCss, /:focus-visible/);
  assert.match(refreshCss, /prefers-reduced-motion/);
  assert.match(refreshCss, /body\.mobile-chat/);
  assert.match(refreshCss, /body\.mobile-list/);
});

test("UI clearly states that the current messaging prototype has no forward secrecy", () => {
  assert.match(html, /メッセージ単位の鍵更新（前方秘匿性）には未対応/);
  assert.match(html, /機密情報は送信しないでください/);
});

test("device-scoped crypto vault uses a single IndexedDB readwrite transaction", () => {
  const cryptoClient = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");
  const creation = cryptoClient.slice(
    cryptoClient.indexOf("async function createDeviceVault"),
    cryptoClient.indexOf("async function api(")
  );
  assert.ok(creation.includes('db.transaction(VAULT_STORE, "readwrite")'));
  assert.ok(creation.includes("store.get(userId)"));
  assert.ok(creation.includes("store.add(candidate)"));
  assert.equal(creation.includes("await readVault(userId)"), false);
});

test("device revocation controls are present and the current device cannot be revoked", () => {
  const cryptoClient = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");
  assert.match(html, /id="crypto-v2-devices-toggle"/);
  assert.match(html, /id="crypto-v2-device-list"/);
  assert.match(cryptoClient, /CRYPTO_CANNOT_REVOKE_CURRENT_DEVICE/);
  assert.ok(cryptoClient.includes("org.securechat.device_revoked"));
});

test("crypto v2 requires an exclusive Web Lock for each browser-profile device", () => {
  const cryptoClient = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");
  assert.ok(cryptoClient.includes("globalThis.navigator?.locks"));
  assert.ok(cryptoClient.includes('mode: "exclusive", ifAvailable: true'));
  assert.ok(cryptoClient.includes("CRYPTO_DEVICE_ALREADY_OPEN_IN_ANOTHER_TAB"));
  assert.ok(cryptoClient.includes("CRYPTO_CROSS_TAB_LOCK_UNAVAILABLE"));
});

test("v2 conversations cannot silently fall back to v1 in a tab without device ownership", () => {
  assert.ok(app.includes('/api/crypto/conversations/"+encodeURIComponent(activeConversation.id)+"/mode'));
  assert.ok(app.includes("このタブでは端末鍵を開けていないため送信・復号できません"));
  assert.ok(app.includes("await closeCryptoV2Session()"));
});
