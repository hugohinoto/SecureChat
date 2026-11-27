import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = path => readFile(new URL(path, import.meta.url), "utf8");

test("Crypto v2 rotates Megolm sessions after every message", async () => {
  const crypto = await read("../public/crypto-v2.js");
  assert.match(crypto, /roomSettings\.sessionRotationPeriodMessages = 1/);
  assert.match(crypto, /settings\.rotationPeriodMessages = 1n/);
  assert.match(crypto, /One Megolm session per message/);
});

test("new messages require the forward-secrecy protocol when Crypto v2 is enabled", async () => {
  const worker = await read("../worker/index.js");
  const api = await read("../worker/crypto-api.js");
  const app = await read("../public/app.js");
  const route = worker.slice(worker.indexOf('if (sub === "messages" && method === "POST")'));
  assert.match(route, /SECURECHAT_CRYPTO_V2_ENABLED === "true"/);
  assert.match(route, /CRYPTO_FORWARD_SECRECY_REQUIRED/);
  assert.match(api, /forwardSecrecyRequired: true/);
  assert.match(api, /forwardSecrecyReady: true/);
  assert.match(api, /sessionRotationMessages: 1/);
  assert.match(app, /cryptoV2Required && activeProtocolVersion!==2/);
  assert.match(app, /相互OTP確認済み連絡先の初回鍵を自動で信頼/);
});

test("health diagnostics and documentation no longer claim forward secrecy is unimplemented", async () => {
  const worker = await read("../worker/index.js");
  const readme = await read("../README.md");
  assert.match(worker, /forwardSecrecy: forwardSecrecyReady/);
  assert.match(worker, /forwardSecrecyStorage: .*"migration-required"/);
  assert.doesNotMatch(worker, /public-key identity verification and forward secrecy are not implemented/);
  assert.match(readme, /Megolmセッションを1メッセージごとにローテーション/);
  assert.match(readme, /端末ストレージ全体が侵害された場合/);
  assert.doesNotMatch(readme, /公開鍵の本人確認、署名済みPreKey Bundleの検証、前方秘匿性/);
});

test("server enforces single-use Megolm session IDs even for stale clients", async () => {
  const worker = await read("../worker/crypto-api.js");
  const migration = await read("../database/d1-migrations/0018_forward_secrecy_sessions.sql");
  assert.match(worker, /INSERT OR IGNORE INTO crypto_used_megolm_sessions/);
  assert.match(worker, /CRYPTO_MEGOLM_SESSION_REUSED/);
  assert.match(worker, /results\?\.\[1\]\?\.meta\?\.changes/);
  assert.match(migration, /PRIMARY KEY \(sender_user_id, sender_device_id, session_id\)/);
  assert.match(migration, /REFERENCES conversations\(id\) ON DELETE CASCADE/);
});
