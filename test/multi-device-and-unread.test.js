import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const worker = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");
const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
const backupModule = await readFile(new URL("../public/identity-backup.js", import.meta.url), "utf8");
const migration = await readFile(
  new URL("../database/d1-migrations/0011_multi_device_identity_backup_and_reads.sql", import.meta.url),
  "utf8"
);
const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
const assetHeaders = await readFile(new URL("../public/_headers", import.meta.url), "utf8");

test("multi-device identity backup is password-encrypted and never stored as plaintext private keys", () => {
  assert.match(backupModule, /PBKDF2/);
  assert.match(backupModule, /AES-GCM/);
  assert.match(backupModule, /iterations:\s*IDENTITY_BACKUP_ITERATIONS/);
  assert.match(worker, /identity_backup_ciphertext/);
  assert.match(worker, /IDENTITY_KEY_CONFLICT/);
  assert.match(worker, /WHERE user_id=\? AND identity_signing_public_key=\?/);
  assert.match(migration, /identity_backup_ciphertext TEXT/);
  assert.doesNotMatch(worker, /ecdhPrivateJwk|signingPrivateJwk/);
});

test("identity transition proof is checked before a public identity key can be changed", () => {
  const conflict = worker.indexOf("!await verifyIdentityKeyTransition(");
  const update = worker.indexOf("UPDATE user_keys SET identity_public_key=");
  assert.ok(conflict >= 0);
  assert.ok(update > conflict);
  assert.match(worker, /identity_transition_from/);
  assert.match(worker, /identity_transition_signature/);
});

test("unread message counts are stored per user and conversation", () => {
  assert.match(migration, /CREATE TABLE IF NOT EXISTS conversation_reads/);
  assert.match(migration, /PRIMARY KEY \(conversation_id, user_id\)/);
  assert.match(worker, /AS unread_count FROM conversations/);
  assert.match(worker, /em\.sender_user_id<>\?/);
  assert.match(worker, /INSERT INTO conversation_reads/);
  assert.match(worker, /last_read_message_id/);
});

test("unread badges and browser notifications are wired in the client", () => {
  assert.match(app, /unread_count/);
  assert.match(app, /new Notification\(/);
  assert.match(app, /Notification\.requestPermission\(/);
  assert.match(app, /notification\.onclick/);
  assert.match(html, /id="unread-total"/);
  assert.match(html, /id="notification-enable-button"/);
});

test("the client explicitly scopes periodic message fetching to the focused visible tab", () => {
  assert.match(app, /document\.visibilityState==="visible" && document\.hasFocus\(\) && activeConversation/);
});


test("identity and authentication assets are never served from a stale browser cache", () => {
  assert.match(assetHeaders, /^\/\*[\s\S]*?Cache-Control:\s*no-store/m);
});

test("a legacy client may reuse only the exact existing identity without rewriting its backup", () => {
  assert.match(worker, /body\?\.identityBackup === undefined \|\| body\?\.identityBackup === null/);
  assert.match(worker, /existingKey\.identity_public_key === pub/);
  assert.match(worker, /existingKey\.identity_signing_public_key === signingPub/);
  assert.match(worker, /backupUnchanged: true/);
  assert.match(worker, /IDENTITY_BACKUP_INVALID/);
});
