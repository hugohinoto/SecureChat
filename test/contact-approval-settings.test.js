import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const worker = readFileSync(new URL("../worker/index.js", import.meta.url), "utf8");
const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const settings = readFileSync(new URL("../public/settings.html", import.meta.url), "utf8");
const settingsJs = readFileSync(new URL("../public/settings.js", import.meta.url), "utf8");

test("new contact invitations are bound to the signed-in inviter and require recipient account approval", () => {
  const createStart = worker.indexOf('if (path === "/api/contact-invitations" && method === "POST")');
  const acceptStart = worker.indexOf("const invitationAccept =", createStart);
  const acceptEnd = worker.indexOf("const responseCodeMatch =", acceptStart);
  assert.ok(createStart >= 0 && acceptStart > createStart && acceptEnd > acceptStart);
  const create = worker.slice(createStart, acceptStart);
  const accept = worker.slice(acceptStart, acceptEnd);
  assert.match(create, /INSERT INTO contact_invitations/);
  assert.match(create, /bind\(id, me, target\.id/);
  assert.doesNotMatch(create, /createOtp\(|otpDigest\(/);
  assert.match(accept, /invitee_user_id=\?/);
  assert.match(accept, /checkRateLimit\(env, request, "contact-approve"/);
  assert.match(accept, /INSERT OR REPLACE INTO verified_contact_pairs/);
  assert.match(accept, /DELETE FROM contact_invitations/);
});

test("new contact invitations do not expose manual OTP entry in the chat sidebar", () => {
  assert.match(app, /連絡先招待を送信/);
  assert.match(app, /連絡先として承認/);
  assert.match(app, /runAutomaticCryptoMaintenance\(\{force:true\}\)/);
  assert.doesNotMatch(app, /otpInputRow\(card/);
  assert.doesNotMatch(html, /ワンタイムコード招待/);
});

test("device management is only rendered and operated from user settings", () => {
  assert.doesNotMatch(html, /device-manage-sidebar-button|crypto-v2-device-list|端末管理/);
  assert.match(settings, /id="settings-devices"/);
  assert.match(settings, /id="crypto-v2-device-list"/);
  assert.match(settingsJs, /\/api\/crypto\/devices/);
  assert.match(settingsJs, /\/revoke/);
  assert.match(settingsJs, /X-SecureChat-Device/);
  assert.match(settingsJs, /onupgradeneeded=\(\)=>\{request\.transaction\.abort\(\);\}/);
});
