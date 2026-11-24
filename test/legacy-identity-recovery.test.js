import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = path => readFile(new URL(path, import.meta.url), "utf8");

test("legacy identity upgrade preserves the original ECDH public key and marks the key local-only", async () => {
  const worker = await read("../worker/index.js");
  const client = await read("../public/app.js");
  assert.match(worker, /body\?\.legacyUpgrade && typeof body\.legacyUpgrade === "object"/);
  assert.match(worker, /existingKey\.identity_public_key === pub/);
  assert.match(worker, /identity_backup_version=2/);
  assert.match(worker, /legacy-local-only/);
  assert.match(worker, /Number\(existingKey\.identity_backup_version\) === 2/);
  assert.match(client, /saved\.publicKey===remote\.identityPublicKey/);
  assert.match(client, /privateKey:saved\.privateKey,publicKey:saved\.publicKey/);
  assert.match(client, /legacyLocalOnly:true/);
  assert.match(client, /api\("\/api\/keys\/legacy-challenge"/);
  assert.match(client, /function fromB64Url\(s\)/);
  assert.match(client, /fromB64Url\(challenge\.serverPublicKey\)/);
  assert.match(client, /!remote\.identitySigningPublicKey/);
  assert.match(client, /crypto\.subtle\.deriveBits\(\{name:"ECDH",public:serverPublicKey\},saved\.privateKey,256\)/);
  assert.match(worker, /identity-legacy\/verify/);
  assert.match(worker, /crypto\.subtle\.verify\("HMAC",\s*proofKey,\s*proofBytes,\s*message\)/);
  assert.match(worker, /this\.ctx\.storage\.delete\(storageKey\)/);
  assert.match(client, /IDENTITY_LEGACY_DEVICE_REQUIRED/);
});

test("legacy-local-only keys cannot be silently rotated without a portable backup", async () => {
  const worker = await read("../worker/index.js");
  const start = worker.indexOf('if (path === "/api/keys" && method === "PUT")');
  const end = worker.indexOf('if (path.startsWith("/api/keys/")', start);
  const route = worker.slice(start, end);
  assert.match(route, /identity_backup_version\) === 2/);
  assert.match(route, /IDENTITY_LEGACY_KEY_LOCKED/);
});

test("changed peer signing keys require an independently supplied exact fingerprint", async () => {
  const client = await read("../public/app.js");
  assert.match(client, /async function showPeerKeyChangeVerification/);
  assert.match(client, /別の安全な経路/);
  assert.match(client, /fingerprintsMatch\(input\.value,fingerprint\)/);
  const fingerprint = await read("../public/identity-fingerprint.js");
  assert.match(fingerprint, /actual\.length === 64 && target\.length === 64 && actual === target/);
  assert.match(client, /latest\.identitySigningPublicKey!==peer\.identitySigningPublicKey/);
  assert.match(client, /peerPins\[peerUserId\]=latest\.identitySigningPublicKey/);
  assert.match(client, /await showPeerKeyChangeVerification\(peerUserId,peer,previousSigningPublicKey\)/);
  assert.match(client, /IDENTITY_SIGNING_KEY_CHANGED/);
});
