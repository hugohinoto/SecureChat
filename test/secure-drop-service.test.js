import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("SecureDrop is registered as a separate service and not in the chat composer", async () => {
  const home = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const service = await readFile(new URL("../public/secure-drop.html", import.meta.url), "utf8");
  assert.match(home, /href="\/secure-drop\.html"/);
  assert.match(home, /SecureDrop/);
  assert.doesNotMatch(home, /id="secure-drop-panel"/);
  assert.match(service, /INDEPENDENT SERVICE/);
  assert.match(service, /id="service-recipient"/);
  assert.match(service, /id="service-files"/);
});

test("standalone SecureDrop reuses the existing local key and pending upload stores", async () => {
  const app = await readFile(new URL("../public/secure-drop-app.js", import.meta.url), "utf8");
  assert.match(app, /securechat-local-keys/);
  assert.match(app, /securechat-securedrop-pending/);
  assert.match(app, /storeName === PENDING_STORE \? "id" : "userId"/);
  assert.match(app, /verifiedPeerPins/);
  assert.match(app, /preemptions\/ack/);
  assert.match(app, /encryptSecureDropFile/);
  assert.match(app, /decryptSecureDropFile/);
});

test("chat page no longer mounts SecureDrop controls in the message composer", async () => {
  const home = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  assert.doesNotMatch(home, /secure-drop-select/);
  assert.doesNotMatch(home, /secure-drop-priority/);
});
