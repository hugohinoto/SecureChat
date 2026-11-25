import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("SecureDrop is a workspace destination, not a separate SERVICES section", async () => {
  const home = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const service = await readFile(new URL("../public/secure-drop.html", import.meta.url), "utf8");
  assert.match(home, /class="workspace-navigation"/);
  assert.match(home, /href="\/secure-drop\.html"/);
  assert.match(home, /SecureDrop/);
  assert.doesNotMatch(home, /SERVICES/);
  assert.doesNotMatch(home, /service-launch-card/);
  assert.match(service, /class="service-workspace-sidebar"/);
  assert.match(service, /class="service-workspace-nav-link active"/);
  assert.match(service, /WORKSPACE TOOL/);
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


test("standalone SecureDrop shows the 2.5 GB capacity and uses the same fallback", async () => {
  const page = await readFile(new URL("../public/secure-drop.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/secure-drop-app.js", import.meta.url), "utf8");
  assert.match(page, /専用容量 2\.5 GB/);
  assert.match(app, /storageCapacityBytes \|\| 2_500_000_000/);
});


test("SecureDrop download credits are charged after three free downloads", async () => {
  const worker = await readFile(new URL("../worker/secure-drop.js", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/secure-drop-app.js", import.meta.url), "utf8");
  assert.match(worker, /download_count>=3/);
  assert.match(worker, /balance=balance-\?/);
  assert.match(worker, /'download_debit'/);
  assert.match(worker, /download_count<3 OR changes\(\)=1/);
  assert.match(worker, /downloadCreditsRequired/);
  assert.match(app, /無料ダウンロード3回を使い切っています/);
  assert.match(app, /クレジットを消費します/);
  assert.match(app, /次回以降 .*クレジット\/回/);
});
