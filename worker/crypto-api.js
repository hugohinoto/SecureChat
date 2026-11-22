const MATRIX_SERVER_NAME = "securechat.invalid";
const MAX_JSON_BODY = 256 * 1024;
const MAX_TO_DEVICE_EVENTS = 100;
const TO_DEVICE_TTL_MS = 60 * 60 * 1000;
const encoder = new TextEncoder();

function json(data, status = 200) {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
}

async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > MAX_JSON_BODY) throw new Error("REQUEST_TOO_LARGE");
  const raw = await request.text();
  if (encoder.encode(raw).byteLength > MAX_JSON_BODY) throw new Error("REQUEST_TOO_LARGE");
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw new Error("INVALID_JSON");
  }
}

function matrixUserId(userId) {
  return "@" + userId + ":" + MATRIX_SERVER_NAME;
}

function parseMatrixUserId(value) {
  if (typeof value !== "string") return null;
  const match = value.match(/^@([a-z0-9_]{3,32}):securechat\.invalid$/);
  return match ? match[1] : null;
}

function orderedPair(a, b) {
  return a < b ? [a, b] : [b, a];
}

function validDeviceId(value) {
  return typeof value === "string" && /^[A-Za-z0-9._=-]{8,64}$/.test(value);
}

function decodeBase64(value, min = 1, max = 4096) {
  if (typeof value !== "string" || value.length > max ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  try {
    const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
    return bytes.length >= min ? bytes : null;
  } catch {
    return null;
  }
}

function deviceAuthorizationMessage(userId, deviceId, curve25519Key, ed25519Key) {
  return encoder.encode(
    "SecureChat device authorization:v2\n" +
    matrixUserId(userId) + "\n" + deviceId + "\n" +
    curve25519Key + "\n" + ed25519Key
  );
}

async function verifyDeviceAuthorization(env, userId, deviceId, deviceKeys, signature) {
  if (!deviceKeys || typeof deviceKeys !== "object" ||
      deviceKeys.user_id !== matrixUserId(userId) ||
      deviceKeys.device_id !== deviceId ||
      !deviceKeys.keys || typeof deviceKeys.keys !== "object") return false;
  const curve25519Key = deviceKeys.keys["curve25519:" + deviceId];
  const ed25519Key = deviceKeys.keys["ed25519:" + deviceId];
  if (typeof curve25519Key !== "string" || typeof ed25519Key !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(curve25519Key) ||
      !/^[A-Za-z0-9_-]{43}$/.test(ed25519Key)) return false;
  const signatureBytes = decodeBase64(signature, 64, 128);
  if (!signatureBytes) return false;
  const row = await env.DB.prepare(
    "SELECT identity_signing_public_key FROM user_keys WHERE user_id=(SELECT id FROM users WHERE user_id=?)"
  ).bind(userId).first();
  if (typeof row?.identity_signing_public_key !== "string") return false;
  let publicBytes;
  try {
    const normalized = row.identity_signing_public_key.replace(/-/g, "+").replace(/_/g, "/");
    publicBytes = Uint8Array.from(atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey("raw", publicBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signatureBytes,
      deviceAuthorizationMessage(userId, deviceId, curve25519Key, ed25519Key)
    );
  } catch {
    return false;
  }
}

async function authorizedContact(env, callerId, targetUserId) {
  const target = await env.DB.prepare("SELECT id FROM users WHERE user_id=?").bind(targetUserId).first();
  if (!target) return null;
  if (target.id === callerId) return target;
  const [a, b] = orderedPair(callerId, target.id);
  const contact = await env.DB.prepare(
    "SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?"
  ).bind(a, b).first();
  return contact ? target : null;
}

async function requireDevice(env, userId, deviceId, now) {
  if (!validDeviceId(deviceId)) return null;
  const row = await env.DB.prepare(
    "SELECT device_id FROM crypto_devices WHERE user_id=? AND device_id=? AND revoked_at IS NULL"
  ).bind(userId, deviceId).first();
  if (!row) return null;
  await env.DB.prepare(
    "UPDATE crypto_devices SET last_seen_at=? WHERE user_id=? AND device_id=? AND revoked_at IS NULL"
  ).bind(now, userId, deviceId).run();
  return row;
}

function requestDeviceId(request) {
  return request.headers.get("X-SecureChat-Device") || "";
}

function validJsonObject(value, max = 16000) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  try { return JSON.stringify(value).length <= max; } catch { return false; }
}

async function uploadKeys(request, env, session, now) {
  const deviceId = requestDeviceId(request);
  if (!validDeviceId(deviceId)) return json({ error: "CRYPTO_DEVICE_REQUIRED" }, 400);
  let body;
  try { body = await readBody(request); } catch (error) { return json({ error: error.message }, 400); }
  const deviceKeys = body.device_keys;
  const accountSignature = body.account_authorization_signature;
  let device = await env.DB.prepare(
    "SELECT device_keys_json, account_authorization_signature, revoked_at FROM crypto_devices WHERE user_id=? AND device_id=?"
  ).bind(session.id, deviceId).first();

  if (deviceKeys !== undefined) {
    if (!validJsonObject(deviceKeys, 16000) ||
        deviceKeys.user_id !== matrixUserId(session.user_id) ||
        deviceKeys.device_id !== deviceId ||
        !Array.isArray(deviceKeys.algorithms) ||
        !deviceKeys.algorithms.includes("m.olm.v1.curve25519-aes-sha2") ||
        !deviceKeys.algorithms.includes("m.megolm.v1.aes-sha2") ||
        typeof accountSignature !== "string" ||
        !await verifyDeviceAuthorization(env, session.user_id, deviceId, deviceKeys, accountSignature)) {
      return json({ error: "CRYPTO_DEVICE_AUTHORIZATION_INVALID" }, 400);
    }
    if (device?.revoked_at) return json({ error: "CRYPTO_DEVICE_REVOKED" }, 409);
    if (device) {
      let previous;
      try { previous = JSON.parse(device.device_keys_json); } catch { return json({ error: "CRYPTO_DEVICE_CORRUPT" }, 503); }
      const previousCurve = previous?.keys?.["curve25519:" + deviceId];
      const previousEd = previous?.keys?.["ed25519:" + deviceId];
      const nextCurve = deviceKeys.keys?.["curve25519:" + deviceId];
      const nextEd = deviceKeys.keys?.["ed25519:" + deviceId];
      if (previousCurve !== nextCurve || previousEd !== nextEd ||
          device.account_authorization_signature !== accountSignature) {
        return json({ error: "CRYPTO_DEVICE_KEY_CHANGED", message: "端末IDに結び付いた公開鍵が変わっています。既存端末を失効し、新しい端末IDで登録してください。" }, 409);
      }
    } else {
      await env.DB.prepare(
        "INSERT INTO crypto_devices (user_id, device_id, device_keys_json, account_authorization_signature, created_at, updated_at, last_seen_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)"
      ).bind(session.id, deviceId, JSON.stringify(deviceKeys), accountSignature, now, now, now).run();
    }
  } else if (!device || device.revoked_at) {
    return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);
  } else {
    await env.DB.prepare(
      "UPDATE crypto_devices SET updated_at=?, last_seen_at=? WHERE user_id=? AND device_id=? AND revoked_at IS NULL"
    ).bind(now, now, session.id, deviceId).run();
  }

  const deviceRow = await env.DB.prepare(
    "SELECT 1 AS ok FROM crypto_devices WHERE user_id=? AND device_id=? AND revoked_at IS NULL"
  ).bind(session.id, deviceId).first();
  if (!deviceRow) return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);

  const oneTimeKeys = body.one_time_keys || {};
  const fallbackKeys = body.fallback_keys || {};
  if (!validJsonObject(oneTimeKeys, 16000) || !validJsonObject(fallbackKeys, 16000)) {
    return json({ error: "CRYPTO_KEYS_INVALID" }, 400);
  }
  const inserts = [];
  for (const [keyId, keyObject] of Object.entries({ ...oneTimeKeys, ...fallbackKeys })) {
    const isFallback = Object.hasOwn(fallbackKeys, keyId) ? 1 : 0;
    const separator = keyId.indexOf(":");
    if (separator < 1 || keyId.length > 160 ||
        !["signed_curve25519"].includes(keyId.slice(0, separator)) ||
        !validJsonObject(keyObject, 4096) ||
        typeof keyObject.key !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(keyObject.key) ||
        !validJsonObject(keyObject.signatures || {}, 2048)) {
      return json({ error: "CRYPTO_ONE_TIME_KEY_INVALID" }, 400);
    }
    inserts.push(env.DB.prepare(
      "INSERT OR IGNORE INTO crypto_one_time_keys (id, user_id, device_id, key_id, algorithm, key_json, is_fallback, created_at, claimed_at, claimed_by_user_id, claimed_by_device_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)"
    ).bind(crypto.randomUUID(), session.id, deviceId, keyId, keyId.slice(0, separator), JSON.stringify(keyObject), isFallback, now));
  }
  if (inserts.length) await env.DB.batch(inserts);
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM crypto_one_time_keys WHERE user_id=? AND device_id=? AND is_fallback=0 AND claimed_at IS NULL"
  ).bind(session.id, deviceId).first();
  return json({
    one_time_key_counts: { signed_curve25519: Number(count?.count || 0) },
    unused_fallback_key_types: []
  });
}

async function queryKeys(request, env, session) {
  let body;
  try { body = await readBody(request); } catch (error) { return json({ error: error.message }, 400); }
  if (!validJsonObject(body.device_keys, 8000)) return json({ error: "CRYPTO_KEYS_QUERY_INVALID" }, 400);
  const deviceKeys = {};
  const deviceAuthorizations = {};
  for (const [matrixId, requestedDeviceIds] of Object.entries(body.device_keys)) {
    const targetUserId = parseMatrixUserId(matrixId);
    if (!targetUserId || !Array.isArray(requestedDeviceIds) || requestedDeviceIds.length > 50) {
      return json({ error: "CRYPTO_KEYS_QUERY_INVALID" }, 400);
    }
    const target = await authorizedContact(env, session.id, targetUserId);
    if (!target) return json({ error: "CONTACT_PERMISSION_REQUIRED" }, 403);
    const records = await env.DB.prepare(
      "SELECT device_id, device_keys_json, account_authorization_signature FROM crypto_devices WHERE user_id=? AND revoked_at IS NULL"
    ).bind(target.id).all();
    const byDevice = {};
    const authorizations = {};
    for (const row of records.results || []) {
      if (requestedDeviceIds.length && !requestedDeviceIds.includes(row.device_id)) continue;
      try {
        const parsed = JSON.parse(row.device_keys_json);
        if (!await verifyDeviceAuthorization(env, targetUserId, row.device_id, parsed, row.account_authorization_signature)) continue;
        byDevice[row.device_id] = parsed;
        authorizations[row.device_id] = row.account_authorization_signature;
      } catch { /* Skip corrupt or unauthorised key records; never publish them. */ }
    }
    deviceKeys[matrixId] = byDevice;
    deviceAuthorizations[matrixId] = authorizations;
  }
  return json({ device_keys: deviceKeys, device_authorizations: deviceAuthorizations, failures: {} });
}

async function claimKeys(request, env, session, now) {
  const requesterDeviceId = requestDeviceId(request);
  if (!await requireDevice(env, session.id, requesterDeviceId, now)) return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);
  let body;
  try { body = await readBody(request); } catch (error) { return json({ error: error.message }, 400); }
  if (!validJsonObject(body.one_time_keys, 8000)) return json({ error: "CRYPTO_KEYS_CLAIM_INVALID" }, 400);
  const oneTimeKeys = {};
  for (const [matrixId, devices] of Object.entries(body.one_time_keys)) {
    const targetUserId = parseMatrixUserId(matrixId);
    if (!targetUserId || !devices || typeof devices !== "object" || Array.isArray(devices)) {
      return json({ error: "CRYPTO_KEYS_CLAIM_INVALID" }, 400);
    }
    const target = await authorizedContact(env, session.id, targetUserId);
    if (!target) return json({ error: "CONTACT_PERMISSION_REQUIRED" }, 403);
    oneTimeKeys[matrixId] = {};
    for (const [deviceId, algorithm] of Object.entries(devices)) {
      if (!validDeviceId(deviceId) || algorithm !== "signed_curve25519") continue;
      const device = await env.DB.prepare(
        "SELECT 1 AS ok FROM crypto_devices WHERE user_id=? AND device_id=? AND revoked_at IS NULL"
      ).bind(target.id, deviceId).first();
      if (!device) continue;
      let key = await env.DB.prepare(
        "SELECT id, key_id, key_json FROM crypto_one_time_keys WHERE user_id=? AND device_id=? AND algorithm=? AND is_fallback=0 AND claimed_at IS NULL ORDER BY created_at, id LIMIT 1"
      ).bind(target.id, deviceId, algorithm).first();
      if (!key) {
        key = await env.DB.prepare(
          "SELECT id, key_id, key_json FROM crypto_one_time_keys WHERE user_id=? AND device_id=? AND algorithm=? AND is_fallback=1 AND claimed_at IS NULL ORDER BY created_at, id LIMIT 1"
        ).bind(target.id, deviceId, algorithm).first();
      }
      if (!key) continue;
      const claimed = await env.DB.prepare(
        "UPDATE crypto_one_time_keys SET claimed_at=?, claimed_by_user_id=?, claimed_by_device_id=? WHERE id=? AND claimed_at IS NULL"
      ).bind(now, session.id, requesterDeviceId, key.id).run();
      if (Number(claimed.meta?.changes || 0) !== 1) continue;
      let value;
      try { value = JSON.parse(key.key_json); } catch { continue; }
      oneTimeKeys[matrixId][deviceId] = { [key.key_id]: value };
    }
  }
  return json({ one_time_keys: oneTimeKeys, failures: {} });
}

const ALLOWED_TO_DEVICE_TYPES = new Set([
  "m.room.encrypted",
  "m.room_key_request",
  "m.room_key.withheld",
  "m.key.verification.request",
  "m.key.verification.ready",
  "m.key.verification.start",
  "m.key.verification.accept",
  "m.key.verification.key",
  "m.key.verification.mac",
  "m.key.verification.done",
  "m.secret.request",
  "m.secret.send"
]);

async function sendToDevice(request, env, session, now) {
  const senderDeviceId = requestDeviceId(request);
  if (!await requireDevice(env, session.id, senderDeviceId, now)) return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);
  let body;
  try { body = await readBody(request); } catch (error) { return json({ error: error.message }, 400); }
  const eventType = body.event_type;
  const transactionId = body.transaction_id;
  const messages = body.messages;
  if (typeof eventType !== "string" || !ALLOWED_TO_DEVICE_TYPES.has(eventType) ||
      typeof transactionId !== "string" || transactionId.length < 8 || transactionId.length > 128 ||
      !validJsonObject(messages, 220000)) return json({ error: "CRYPTO_TO_DEVICE_INVALID" }, 400);
  let inserted = 0, total = 0;
  const statements = [];
  for (const [matrixId, deviceMap] of Object.entries(messages)) {
    const recipientName = parseMatrixUserId(matrixId);
    if (!recipientName || !deviceMap || typeof deviceMap !== "object" || Array.isArray(deviceMap)) {
      return json({ error: "CRYPTO_TO_DEVICE_INVALID" }, 400);
    }
    if (Object.keys(deviceMap).length > 50) return json({ error: "CRYPTO_TO_DEVICE_LIMIT" }, 413);
    const recipient = await authorizedContact(env, session.id, recipientName);
    if (!recipient) return json({ error: "CONTACT_PERMISSION_REQUIRED" }, 403);
    for (const [recipientDeviceId, content] of Object.entries(deviceMap)) {
      total++;
      if (total > MAX_TO_DEVICE_EVENTS || !validDeviceId(recipientDeviceId) || !validJsonObject(content, 32768)) {
        return json({ error: "CRYPTO_TO_DEVICE_LIMIT" }, 413);
      }
      const targetDevice = await env.DB.prepare(
        "SELECT 1 AS ok FROM crypto_devices WHERE user_id=? AND device_id=? AND revoked_at IS NULL"
      ).bind(recipient.id, recipientDeviceId).first();
      if (!targetDevice) continue;
      const messageId = crypto.randomUUID();
      statements.push(env.DB.prepare(
        "INSERT OR IGNORE INTO crypto_to_device_inbox (id, recipient_user_id, recipient_device_id, sender_user_id, sender_device_id, event_type, content_json, transaction_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(messageId, recipient.id, recipientDeviceId, session.id, senderDeviceId, eventType,
        JSON.stringify(content), transactionId, now, now + TO_DEVICE_TTL_MS));
    }
  }
  if (statements.length) {
    const result = await env.DB.batch(statements);
    inserted = result.reduce((sum, item) => sum + Number(item.meta?.changes || 0), 0);
  }
  return json({ event_id: transactionId, queued: inserted });
}

async function syncInbox(request, env, session, now) {
  const deviceId = requestDeviceId(request);
  if (!await requireDevice(env, session.id, deviceId, now)) return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);
  await env.DB.prepare("DELETE FROM crypto_to_device_inbox WHERE expires_at<=?").bind(now).run();
  const result = await env.DB.prepare(
    "SELECT id, sender_user_id, sender_device_id, event_type, content_json, created_at FROM crypto_to_device_inbox WHERE recipient_user_id=? AND recipient_device_id=? AND expires_at>? ORDER BY created_at, id LIMIT 100"
  ).bind(session.id, deviceId, now).all();
  const events = [];
  for (const row of result.results || []) {
    let content;
    try { content = JSON.parse(row.content_json); } catch { continue; }
    const sender = await env.DB.prepare("SELECT user_id FROM users WHERE id=?").bind(row.sender_user_id).first();
    if (!sender) continue;
    events.push({
      id: row.id,
      event: {
        type: row.event_type,
        sender: matrixUserId(sender.user_id),
        sender_device: row.sender_device_id,
        content
      }
    });
  }
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM crypto_one_time_keys WHERE user_id=? AND device_id=? AND algorithm='signed_curve25519' AND is_fallback=0 AND claimed_at IS NULL"
  ).bind(session.id, deviceId).first();
  return json({ events, one_time_key_counts: { signed_curve25519: Number(count?.count || 0) } });
}

async function acknowledgeInbox(request, env, session) {
  const deviceId = requestDeviceId(request);
  if (!await requireDevice(env, session.id, deviceId, Date.now())) return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);
  let body;
  try { body = await readBody(request); } catch (error) { return json({ error: error.message }, 400); }
  if (!Array.isArray(body.event_ids) || body.event_ids.length > 100 ||
      body.event_ids.some(id => typeof id !== "string" || !/^[a-f0-9-]{36}$/i.test(id))) {
    return json({ error: "CRYPTO_INBOX_ACK_INVALID" }, 400);
  }
  if (!body.event_ids.length) return json({ acknowledged: 0 });
  const placeholders = body.event_ids.map(() => "?").join(",");
  const result = await env.DB.prepare(
    "DELETE FROM crypto_to_device_inbox WHERE recipient_user_id=? AND recipient_device_id=? AND id IN (" + placeholders + ")"
  ).bind(session.id, deviceId, ...body.event_ids).run();
  return json({ acknowledged: Number(result.meta?.changes || 0) });
}

async function conversationContext(env, conversationId, userId) {
  if (!/^[a-f0-9-]{36}$/i.test(conversationId)) return null;
  const rows = await env.DB.prepare(
    "SELECT peer.user_id AS peer_id FROM conversation_members mine JOIN conversation_members peer ON peer.conversation_id=mine.conversation_id AND peer.user_id<>mine.user_id WHERE mine.conversation_id=? AND mine.user_id=? LIMIT 1"
  ).bind(conversationId, userId).all();
  const peerId = rows.results?.[0]?.peer_id;
  if (!peerId) return null;
  const [a, b] = orderedPair(userId, peerId);
  const contact = await env.DB.prepare(
    "SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?"
  ).bind(a, b).first();
  return contact ? { peerId } : null;
}

async function conversationCryptoMode(env, session, conversationId) {
  const context = await conversationContext(env, conversationId, session.id);
  if (!context) return null;
  const [mode, mine, peer] = await Promise.all([
    env.DB.prepare(
      "SELECT protocol_version, enabled_at FROM conversation_crypto_modes WHERE conversation_id=?"
    ).bind(conversationId).first(),
    env.DB.prepare(
      "SELECT 1 AS approved FROM conversation_crypto_approvals WHERE conversation_id=? AND user_id=?"
    ).bind(conversationId, session.id).first(),
    env.DB.prepare(
      "SELECT 1 AS approved FROM conversation_crypto_approvals WHERE conversation_id=? AND user_id=?"
    ).bind(conversationId, context.peerId).first()
  ]);
  return {
    protocolVersion: Number(mode?.protocol_version || 1),
    enabledAt: Number(mode?.enabled_at || 0),
    approvedByMe: !!mine,
    approvedByPeer: !!peer,
    pendingApproval: !mode && !!mine
  };
}

async function enableConversationV2(request, env, session, conversationId, now) {
  const context = await conversationContext(env, conversationId, session.id);
  if (!context) return json({ error: "CONVERSATION_NOT_FOUND" }, 404);
  const [self, peer] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) AS count FROM crypto_devices WHERE user_id=? AND revoked_at IS NULL").bind(session.id).first(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM crypto_devices WHERE user_id=? AND revoked_at IS NULL").bind(context.peerId).first()
  ]);
  if (Number(self?.count || 0) < 1 || Number(peer?.count || 0) < 1) {
    return json({ error: "CRYPTO_V2_DEVICES_REQUIRED", message: "双方の端末で新しい暗号化デバイスを登録する必要があります。" }, 409);
  }
  await env.DB.prepare(
    "INSERT OR IGNORE INTO conversation_crypto_approvals (conversation_id, user_id, approved_at) VALUES (?, ?, ?)"
  ).bind(conversationId, session.id, now).run();
  const approvals = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM conversation_crypto_approvals WHERE conversation_id=? AND user_id IN (?, ?)"
  ).bind(conversationId, session.id, context.peerId).first();
  if (Number(approvals?.count || 0) === 2) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO conversation_crypto_modes (conversation_id, protocol_version, enabled_by_user_id, enabled_at) VALUES (?, 2, ?, ?)"
    ).bind(conversationId, session.id, now).run();
  }
  const result = await conversationCryptoMode(env, session, conversationId);
  return json(result || { protocolVersion: 1 });
}

async function sendRoomMessage(request, env, session, conversationId, now) {
  const deviceId = requestDeviceId(request);
  if (!await requireDevice(env, session.id, deviceId, now)) return json({ error: "CRYPTO_DEVICE_NOT_REGISTERED" }, 409);
  const context = await conversationContext(env, conversationId, session.id);
  if (!context) return json({ error: "CONVERSATION_NOT_FOUND" }, 404);
  const mode = await env.DB.prepare(
    "SELECT protocol_version FROM conversation_crypto_modes WHERE conversation_id=?"
  ).bind(conversationId).first();
  if (Number(mode?.protocol_version || 1) !== 2) return json({ error: "CRYPTO_PROTOCOL_NOT_ENABLED" }, 409);
  let body;
  try { body = await readBody(request); } catch (error) { return json({ error: error.message }, 400); }
  if (!validJsonObject(body.encrypted_event, 12000) ||
      body.encrypted_event.algorithm !== "m.megolm.v1.aes-sha2" ||
      typeof body.encrypted_event.ciphertext !== "string" ||
      typeof body.encrypted_event.session_id !== "string" ||
      !/^[A-Za-z0-9_-]{8,128}$/.test(body.encrypted_event.session_id) ||
      typeof body.encrypted_event.sender_key !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.encrypted_event.sender_key) ||
      typeof body.encrypted_event.device_id !== "string" ||
      !validDeviceId(body.encrypted_event.device_id)) {
    return json({ error: "CRYPTO_ENVELOPE_INVALID" }, 400);
  }
  const encoded = JSON.stringify(body.encrypted_event);
  if (encoded.length < 80 || encoded.length > 12000) return json({ error: "CRYPTO_ENVELOPE_SIZE_INVALID" }, 400);
  const id = crypto.randomUUID(), expiresAt = now + 60 * 60 * 1000;
  await env.DB.prepare(
    "INSERT INTO encrypted_messages (id, conversation_id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at, protocol_version, sender_device_id) VALUES (?, ?, ?, ?, '', 'MATRIX-MEGOLM-V1', ?, ?, 2, ?)"
  ).bind(id, conversationId, session.id, encoded, now, expiresAt, deviceId).run();
  return json({ id, createdAt: now, expiresAt, protocolVersion: 2 }, 201);
}

export async function handleCryptoApi(request, env, session, { url, now = Date.now() }) {
  const path = url.pathname;
  const method = request.method;
  if (!path.startsWith("/api/crypto/")) return null;
  if (env.SECURECHAT_CRYPTO_V2_ENABLED !== "true") {
    return json({ error: "CRYPTO_V2_DISABLED", enabled: false }, 503);
  }

  if (path === "/api/crypto/status" && method === "GET") {
    const devices = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM crypto_devices WHERE user_id=? AND revoked_at IS NULL"
    ).bind(session.id).first();
    return json({ enabled: true, protocolVersion: 2, deviceCount: Number(devices?.count || 0) });
  }
  if (path === "/api/crypto/keys/upload" && method === "POST") return uploadKeys(request, env, session, now);
  if (path === "/api/crypto/keys/query" && method === "POST") return queryKeys(request, env, session);
  if (path === "/api/crypto/keys/claim" && method === "POST") return claimKeys(request, env, session, now);
  if (path === "/api/crypto/to-device" && method === "POST") return sendToDevice(request, env, session, now);
  if (path === "/api/crypto/sync" && method === "GET") return syncInbox(request, env, session, now);
  if (path === "/api/crypto/sync/ack" && method === "POST") return acknowledgeInbox(request, env, session);
  const modeMatch = path.match(/^\/api\/crypto\/conversations\/([a-f0-9-]{36})\/mode$/i);
  if (modeMatch && method === "GET") {
    const result = await conversationCryptoMode(env, session, modeMatch[1]);
    return result ? json(result) : json({ error: "CONVERSATION_NOT_FOUND" }, 404);
  }
  if (modeMatch && method === "POST") return enableConversationV2(request, env, session, modeMatch[1], now);
  const messageMatch = path.match(/^\/api\/crypto\/conversations\/([a-f0-9-]{36})\/messages$/i);
  if (messageMatch && method === "POST") return sendRoomMessage(request, env, session, messageMatch[1], now);
  return json({ error: "CRYPTO_ROUTE_NOT_FOUND" }, 404);
}

export { deviceAuthorizationMessage, matrixUserId, parseMatrixUserId };
