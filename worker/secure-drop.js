const MAX_ORIGINAL_BYTES = 25_000_000;
const MAX_STORED_BYTES = 25_000_000;
const D1_STORAGE_CAPACITY_BYTES = 3_000_000_000;
const D1_STORAGE_SOFT_LIMIT_BYTES = Math.floor(D1_STORAGE_CAPACITY_BYTES * 0.9);
const D1_CHUNK_SIZE_BYTES = 512 * 1024;
const PRIORITY_CREDIT_MULTIPLIER = 5;
const MONTHLY_CREDITS = 100;
const DOWNLOAD_LIMIT = 3;
const TRANSFER_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PENDING_GRACE_MS = 15 * 60 * 1000;
const JST_OFFSET_MS = 9 * 60 * 60 * 1000;
const CLEANUP_PAGE_SIZE = 1000;
const CLEANUP_MAX_PAGES_PER_RUN = 10;
const CLEANUP_BATCH_SIZE = 100;
const encoder = new TextEncoder();
const ENVELOPE_ALGORITHM = "ECDH-P256-HKDF-SHA256-AES-GCM-256";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const USER_ID_PATTERN = /^[a-z0-9_]{3,32}$/;

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

export function secureDropMonthKey(now) {
  return new Date(now + JST_OFFSET_MS).toISOString().slice(0, 7);
}

export function secureDropNextMonthStart(now) {
  const jst = new Date(now + JST_OFFSET_MS);
  return Date.UTC(jst.getUTCFullYear(), jst.getUTCMonth() + 1, 1) - JST_OFFSET_MS;
}

export function secureDropCreditsForBytes(bytes, multiplier = 1) {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_STORED_BYTES ||
      (multiplier !== 1 && multiplier !== PRIORITY_CREDIT_MULTIPLIER)) {
    throw new RangeError("INVALID_STORED_SIZE");
  }
  return Math.max(1, Math.ceil(bytes / 1_000_000)) * multiplier;
}

function decodeBase64(value) {
  if (typeof value !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("INVALID_BASE64");
  }
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,4096}$/.test(value)) {
    throw new Error("INVALID_BASE64URL");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}
function secureDropSenderSignatureMessage(envelope) {
  const signedFields = {
    version: envelope.version,
    algorithm: envelope.algorithm,
    recipientKeyFingerprint: envelope.recipientKeyFingerprint,
    ephemeralPublicKey: envelope.ephemeralPublicKey,
    salt: envelope.salt,
    iv: envelope.iv,
    wrappedFileKey: envelope.wrappedFileKey,
    fileIv: envelope.fileIv,
    senderUserId: envelope.senderUserId,
    senderSigningPublicKey: envelope.senderSigningPublicKey,
    ciphertextSha256: envelope.ciphertextSha256
  };
  return encoder.encode(
    "SecureChat SecureDrop sender signature v1\n" +
    envelope.senderUserId + "\n" + JSON.stringify(signedFields)
  );
}

export async function verifySecureDropKeyEnvelopeSignature(envelope) {
  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      decodeBase64(envelope.senderSigningPublicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      decodeBase64(envelope.senderSignature),
      secureDropSenderSignatureMessage(envelope)
    );
  } catch {
    return false;
  }
}

async function digest(value) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function validateSecureDropKeyEnvelope(envelope, recipientKeyFingerprint, senderUserId = null, senderSigningPublicKey = null) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) ||
      envelope.version !== 1 ||
      envelope.algorithm !== ENVELOPE_ALGORITHM ||
      typeof recipientKeyFingerprint !== "string" ||
      !/^[a-f0-9]{64}$/.test(recipientKeyFingerprint) ||
      envelope.recipientKeyFingerprint !== recipientKeyFingerprint ||
      (senderUserId !== null && envelope.senderUserId !== senderUserId) ||
      (senderSigningPublicKey !== null && envelope.senderSigningPublicKey !== senderSigningPublicKey)) return false;
  try {
    const ephemeral = decodeBase64(envelope.ephemeralPublicKey);
    const salt = decodeBase64(envelope.salt);
    const iv = decodeBase64(envelope.iv);
    const wrappedKey = decodeBase64(envelope.wrappedFileKey);
    const fileIv = decodeBase64(envelope.fileIv);
    const senderPublicKey = decodeBase64(envelope.senderSigningPublicKey);
    const senderSignature = decodeBase64(envelope.senderSignature);
    return ephemeral.length === 65 && ephemeral[0] === 4 &&
      salt.length === 16 && iv.length === 12 && wrappedKey.length === 48 && fileIv.length === 12 &&
      senderPublicKey.length === 65 && senderPublicKey[0] === 4 && senderSignature.length === 64 &&
      USER_ID_PATTERN.test(envelope.senderUserId) && /^[a-f0-9]{64}$/.test(envelope.ciphertextSha256);
  } catch {
    return false;
  }
}

export function createMeteredBody(body, maxBytes) {
  const state = { bytes: 0, finished: false };
  const stream = body.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      if (!(chunk instanceof Uint8Array)) throw new TypeError("INVALID_UPLOAD_CHUNK");
      state.bytes += chunk.byteLength;
      if (state.bytes > maxBytes) throw new RangeError("STORED_SIZE_LIMIT_EXCEEDED");
      controller.enqueue(chunk);
    },
    flush() {
      state.finished = true;
    }
  }));
  return { stream, state };
}

async function ensureMonthlyAccount(env, userId, month, now) {
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO secure_drop_credit_accounts (user_id, month_key, granted_credits, balance, updated_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(userId, month, MONTHLY_CREDITS, MONTHLY_CREDITS, now),
    env.DB.prepare(
      "INSERT OR IGNORE INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at) VALUES (?, ?, ?, ?, 'monthly_grant', 'monthly-grant', ?)"
    ).bind("grant:" + month + ":" + userId, userId, month, MONTHLY_CREDITS, now)
  ]);
  return env.DB.prepare(
    "SELECT granted_credits, balance, updated_at FROM secure_drop_credit_accounts WHERE user_id=? AND month_key=?"
  ).bind(userId, month).first();
}

async function refundCredits(env, userId, month, credits, transferId, now) {
  if (month !== secureDropMonthKey(now) || !Number.isSafeInteger(credits) || credits < 1) return;
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at) VALUES (?, ?, ?, ?, 'upload_refund', ?, ?)"
    ).bind("refund:" + transferId, userId, month, credits, transferId, now),
    env.DB.prepare(
      "UPDATE secure_drop_credit_accounts SET balance=MIN(granted_credits, balance+?), updated_at=? WHERE user_id=? AND month_key=? AND changes()=1"
    ).bind(credits, now, userId, month)
  ]);
}

async function lookupSenderSigningKey(env, ownerId) {
  const row = await env.DB.prepare(
    "SELECT identity_signing_public_key FROM user_keys WHERE user_id=?"
  ).bind(ownerId).first();
  return typeof row?.identity_signing_public_key === "string" ? row.identity_signing_public_key : null;
}

async function lookupRecipient(env, ownerId, recipientValue) {
  if (typeof recipientValue !== "string" ||
      (!UUID_PATTERN.test(recipientValue) && !USER_ID_PATTERN.test(recipientValue))) return null;
  const recipient = await env.DB.prepare(
    "SELECT u.id, u.user_id, k.identity_public_key FROM users u JOIN user_keys k ON k.user_id=u.id WHERE u.id=? OR u.user_id=? LIMIT 1"
  ).bind(recipientValue, recipientValue).first();
  if (!recipient || recipient.id === ownerId ||
      typeof recipient.identity_public_key !== "string" || !recipient.identity_public_key) return null;
  const [userA, userB] = ownerId < recipient.id ? [ownerId, recipient.id] : [recipient.id, ownerId];
  const contact = await env.DB.prepare(
    "SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?"
  ).bind(userA, userB).first();
  return contact ? recipient : null;
}

async function createPendingTransfer(env, details) {
  const {
    transferId, ownerId, recipientId, month, objectKey, tokenHash, originalBytes,
    storedBytes, envelopeJson, credits, now, expiresAt, priority, capacityLimit
  } = details;
  const results = await env.DB.batch([
    env.DB.prepare(
      "UPDATE secure_drop_credit_accounts SET balance=balance-?, updated_at=? WHERE user_id=? AND month_key=? AND balance>=? AND (SELECT COALESCE(SUM(stored_size_bytes),0) FROM secure_drop_transfers WHERE storage_backend='d1' AND status IN ('pending','ready','deleting')) + ? <= ?"
    ).bind(credits, now, ownerId, month, credits, storedBytes, capacityLimit),
    env.DB.prepare(
      "INSERT INTO secure_drop_transfers (id, user_id, month_key, object_key, token_hash, original_size_bytes, stored_size_bytes, created_at, expires_at, download_count, download_limit, recipient_user_id, key_envelope_json, status, updated_at, storage_backend, priority) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 3, ?, ?, 'pending', ?, 'd1', ? WHERE changes()=1"
    ).bind(transferId, ownerId, month, objectKey, tokenHash, originalBytes, storedBytes, now, expiresAt, recipientId, envelopeJson, now, priority),
    env.DB.prepare(
      "INSERT INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at) SELECT ?, ?, ?, ?, 'upload_debit', ?, ? WHERE EXISTS (SELECT 1 FROM secure_drop_transfers WHERE id=? AND status='pending')"
    ).bind("debit:" + transferId, ownerId, month, -credits, transferId, now, transferId)
  ]);
  return Number(results?.[0]?.meta?.changes || 0) === 1 &&
    Number(results?.[1]?.meta?.changes || 0) === 1;
}

async function digestBytes(value) {
  const hash = await crypto.subtle.digest("SHA-256", value);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readBodyBounded(body, maxBytes) {
  if (!body) throw new Error("UPLOAD_BODY_REQUIRED");
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error("STORED_SIZE_LIMIT_EXCEEDED");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function getD1StorageUsedBytes(env) {
  const row = await env.DB.prepare(
    "SELECT COALESCE(SUM(stored_size_bytes),0) AS used_bytes FROM secure_drop_transfers WHERE storage_backend='d1' AND status IN ('pending','ready','deleting')"
  ).first();
  return Number(row?.used_bytes || 0);
}

async function preemptPendingUploads(env, requestedBytes, now) {
  const usedBytes = await getD1StorageUsedBytes(env);
  const requiredBytes = Math.max(0, usedBytes + requestedBytes - D1_STORAGE_CAPACITY_BYTES);
  if (!requiredBytes) return true;
  const candidates = await env.DB.prepare(
    "SELECT id, stored_size_bytes FROM secure_drop_transfers WHERE storage_backend='d1' AND status='pending' AND priority=0 ORDER BY updated_at ASC LIMIT 200"
  ).all();
  const selected = [];
  let released = 0;
  for (const row of candidates.results || []) {
    selected.push(row);
    released += Number(row.stored_size_bytes || 0);
    if (released >= requiredBytes) break;
  }
  if (released < requiredBytes) return false;

  const statements = [];
  for (const row of selected) {
    statements.push(
      env.DB.prepare(
        "INSERT OR IGNORE INTO secure_drop_preempted_uploads (transfer_id, user_id, recipient_user_id, month_key, original_size_bytes, stored_size_bytes, created_at) SELECT id, user_id, recipient_user_id, month_key, original_size_bytes, stored_size_bytes, ? FROM secure_drop_transfers WHERE id=? AND storage_backend='d1' AND status='pending' AND priority=0"
      ).bind(now, row.id),
      env.DB.prepare(
        "INSERT OR IGNORE INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at) SELECT 'refund:preempt:' || t.id, t.user_id, t.month_key, -l.delta, 'upload_refund', t.id, ? FROM secure_drop_transfers t JOIN secure_drop_credit_ledger l ON l.id='debit:' || t.id WHERE t.id=? AND t.storage_backend='d1' AND t.status='pending' AND t.priority=0 AND l.delta<0"
      ).bind(now, row.id),
      env.DB.prepare(
        "UPDATE secure_drop_credit_accounts SET balance=MIN(granted_credits, balance + (SELECT delta FROM secure_drop_credit_ledger WHERE id='refund:preempt:' || ?)), updated_at=? WHERE user_id=(SELECT user_id FROM secure_drop_transfers WHERE id=?) AND month_key=(SELECT month_key FROM secure_drop_transfers WHERE id=?) AND changes()=1"
      ).bind(row.id, now, row.id, row.id),
      env.DB.prepare("DELETE FROM secure_drop_file_chunks WHERE transfer_id=?").bind(row.id),
      env.DB.prepare(
        "DELETE FROM secure_drop_transfers WHERE id=? AND storage_backend='d1' AND status='pending' AND priority=0 AND EXISTS (SELECT 1 FROM secure_drop_preempted_uploads WHERE transfer_id=?)"
      ).bind(row.id, row.id)
    );
  }
  await env.DB.batch(statements);
  return (await getD1StorageUsedBytes(env)) + requestedBytes <= D1_STORAGE_CAPACITY_BYTES;
}

async function verifyR2ObjectAbsent(env, objectKey) {
  try {
    await env.SECURE_DROP_R2.delete(objectKey);
    const remaining = await env.SECURE_DROP_R2.head(objectKey);
    return remaining === null;
  } catch {
    return false;
  }
}

async function queueDeletionVerification(env, transferId, objectKey, now, reason) {
  await env.DB.prepare(
    "INSERT INTO secure_drop_deletion_jobs (transfer_id, object_key, reason, attempts, next_attempt_at, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?, ?) ON CONFLICT(transfer_id) DO UPDATE SET object_key=excluded.object_key, reason=excluded.reason, next_attempt_at=MIN(secure_drop_deletion_jobs.next_attempt_at, excluded.next_attempt_at), updated_at=excluded.updated_at"
  ).bind(transferId, objectKey, reason, now, now, now).run();
}

async function verifyAndFinalizeDeletion(env, transferId, objectKey, now, reason = "user_delete", storageBackend = "r2") {
  if (storageBackend === "d1") {
    await env.DB.prepare("DELETE FROM secure_drop_file_chunks WHERE transfer_id=?").bind(transferId).run();
    const remaining = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM secure_drop_file_chunks WHERE transfer_id=?"
    ).bind(transferId).first();
    if (Number(remaining?.count || 0) !== 0) return false;
    await env.DB.batch([
      env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=? AND status='deleting' AND storage_backend='d1'").bind(transferId),
      env.DB.prepare("DELETE FROM secure_drop_deletion_jobs WHERE transfer_id=?").bind(transferId)
    ]);
    const transfer = await env.DB.prepare("SELECT 1 AS present FROM secure_drop_transfers WHERE id=?").bind(transferId).first();
    return !transfer;
  }
  const absent = await verifyR2ObjectAbsent(env, objectKey);
  if (!absent) {
    await queueDeletionVerification(env, transferId, objectKey, now, reason).catch(() => {});
    return false;
  }
  await env.DB.batch([
    env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=? AND status='deleting'").bind(transferId),
    env.DB.prepare("DELETE FROM secure_drop_deletion_jobs WHERE transfer_id=?").bind(transferId)
  ]);
  return true;
}

async function processDeletionJobs(env, now) {
  const rows = await env.DB.prepare(
    "SELECT transfer_id, object_key, reason, attempts FROM secure_drop_deletion_jobs WHERE next_attempt_at<=? ORDER BY next_attempt_at LIMIT ?"
  ).bind(now, CLEANUP_BATCH_SIZE).all();
  for (const row of rows.results || []) {
    const absent = await verifyR2ObjectAbsent(env, row.object_key);
    if (absent) {
      await env.DB.batch([
        env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=? AND status='deleting'").bind(row.transfer_id),
        env.DB.prepare("DELETE FROM secure_drop_deletion_jobs WHERE transfer_id=?").bind(row.transfer_id)
      ]);
      continue;
    }
    const attempts = Number(row.attempts || 0) + 1;
    const delay = Math.min(60 * 60 * 1000, 30_000 * (2 ** Math.min(attempts - 1, 7)));
    await env.DB.prepare(
      "UPDATE secure_drop_deletion_jobs SET attempts=?, next_attempt_at=?, updated_at=? WHERE transfer_id=?"
    ).bind(attempts, now + delay, now, row.transfer_id).run();
  }
}

async function abandonPendingTransfer(env, transfer, credits, now) {
  if (transfer.storageBackend === "d1") {
    try {
      await env.DB.batch([
        env.DB.prepare("DELETE FROM secure_drop_file_chunks WHERE transfer_id=?").bind(transfer.id),
        env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=? AND status='pending' AND storage_backend='d1'").bind(transfer.id)
      ]);
      const remaining = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM secure_drop_file_chunks WHERE transfer_id=?"
      ).bind(transfer.id).first();
      if (Number(remaining?.count || 0) !== 0) throw new Error("D1_CHUNK_DELETION_UNVERIFIED");
      await refundCredits(env, transfer.ownerId, transfer.month, credits, transfer.id, now);
      return;
    } catch {
      await env.DB.prepare(
        "UPDATE secure_drop_transfers SET status='deleting', updated_at=? WHERE id=? AND storage_backend='d1'"
      ).bind(now, transfer.id).run().catch(() => {});
      return;
    }
  }
  const objectDeleted = await verifyR2ObjectAbsent(env, transfer.objectKey);
  let refundCompleted = false;
  try {
    await refundCredits(env, transfer.ownerId, transfer.month, credits, transfer.id, now);
    refundCompleted = true;
  } catch {}
  if (objectDeleted && refundCompleted) {
    await env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=? AND status='pending'").bind(transfer.id).run().catch(() => {});
    await env.DB.prepare("DELETE FROM secure_drop_deletion_jobs WHERE transfer_id=?").bind(transfer.id).run().catch(() => {});
  } else {
    await env.DB.prepare(
      "UPDATE secure_drop_transfers SET status='deleting', updated_at=? WHERE id=?"
    ).bind(now, transfer.id).run().catch(() => {});
    await queueDeletionVerification(env, transfer.id, transfer.objectKey, now, "upload_rollback").catch(() => {});
  }
}

async function cleanupStaleTransfers(env, now) {
  const rows = await env.DB.prepare(
    "SELECT id, user_id, month_key, object_key, storage_backend, status FROM secure_drop_transfers WHERE (status='pending' AND updated_at<=?) OR (status='deleting' AND updated_at<=?) OR (status='ready' AND expires_at<=?) ORDER BY updated_at LIMIT ?"
  ).bind(now - PENDING_GRACE_MS, now - PENDING_GRACE_MS, now, CLEANUP_BATCH_SIZE).all();
  for (const row of rows.results || []) {
    if (row.storage_backend === "d1") {
      await env.DB.prepare("DELETE FROM secure_drop_file_chunks WHERE transfer_id=?").bind(row.id).run();
      const remaining = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM secure_drop_file_chunks WHERE transfer_id=?"
      ).bind(row.id).first();
      if (Number(remaining?.count || 0) !== 0) continue;
    } else {
      if (!env.SECURE_DROP_R2) continue;
      const objectDeleted = await verifyR2ObjectAbsent(env, row.object_key);
      if (!objectDeleted) {
        await queueDeletionVerification(env, row.id, row.object_key, now, "stale_transfer").catch(() => {});
        continue;
      }
    }
    if (row.status === "pending" && row.month_key === secureDropMonthKey(now)) {
      try {
        const debit = await env.DB.prepare(
          "SELECT -delta AS credits FROM secure_drop_credit_ledger WHERE id=? AND reason='upload_debit' AND delta<0"
        ).bind("debit:" + row.id).first();
        if (Number(debit?.credits || 0) > 0) {
          await refundCredits(env, row.user_id, row.month_key, Number(debit.credits), row.id, now);
        }
      } catch {
        continue;
      }
    }
    await env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=?").bind(row.id).run();
    await env.DB.prepare("DELETE FROM secure_drop_deletion_jobs WHERE transfer_id=?").bind(row.id).run();
  }
}

async function purgeOldMonthD1Only(env, now) {
  const current = secureDropMonthKey(now);
  const pending = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM secure_drop_transfers WHERE storage_backend='d1' AND month_key<>? AND status='pending'"
  ).bind(current).first();
  if (Number(pending?.count || 0) > 0) return false;
  await env.DB.prepare(
    "DELETE FROM secure_drop_file_chunks WHERE transfer_id IN (SELECT id FROM secure_drop_transfers WHERE storage_backend='d1' AND month_key<>?)"
  ).bind(current).run();
  const remaining = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM secure_drop_file_chunks c JOIN secure_drop_transfers t ON t.id=c.transfer_id WHERE t.storage_backend='d1' AND t.month_key<>?"
  ).bind(current).first();
  if (Number(remaining?.count || 0) !== 0) return false;
  await env.DB.prepare(
    "DELETE FROM secure_drop_transfers WHERE storage_backend='d1' AND month_key<>?"
  ).bind(current).run();
  const legacy = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM secure_drop_transfers WHERE storage_backend='r2' AND month_key<>?"
  ).bind(current).first();
  return Number(legacy?.count || 0) === 0;
}

async function purgeOldMonthObjects(env, now) {
  const bucket = env.SECURE_DROP_R2;
  const current = secureDropMonthKey(now);
  let state = await env.DB.prepare(
    "SELECT current_month, cursor, completed_at FROM secure_drop_maintenance WHERE id=1"
  ).first();
  if (!state || state.current_month !== current) {
    await env.DB.prepare(
      "INSERT INTO secure_drop_maintenance (id, current_month, cursor, completed_at) VALUES (1, ?, NULL, NULL) ON CONFLICT(id) DO UPDATE SET current_month=excluded.current_month, cursor=NULL, completed_at=NULL"
    ).bind(current).run();
    state = { current_month: current, cursor: null, completed_at: null };
  }
  const inFlightOldMonth = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM secure_drop_transfers WHERE month_key<>? AND status='pending'"
  ).bind(current).first();
  if (Number(inFlightOldMonth?.count || 0) > 0) return false;
  if (state.completed_at) return true;

  let cursor = state.cursor || undefined;
  for (let index = 0; index < CLEANUP_MAX_PAGES_PER_RUN; index += 1) {
    const page = await bucket.list({
      prefix: "secure-drop/",
      limit: CLEANUP_PAGE_SIZE,
      ...(cursor ? { cursor } : {})
    });
    const obsolete = (page.objects || []).filter((item) => {
      const parts = item.key.split("/");
      return parts.length >= 3 && parts[0] === "secure-drop" && parts[1] !== current;
    }).map((item) => item.key);
    if (obsolete.length) {
      await bucket.delete(obsolete);
      for (const key of obsolete) {
        const remaining = await bucket.head(key);
        if (remaining !== null) throw new Error("R2_DELETION_VERIFICATION_FAILED");
      }
    }

    if (page.truncated) {
      cursor = page.cursor;
      await env.DB.prepare(
        "UPDATE secure_drop_maintenance SET cursor=?, completed_at=NULL WHERE id=1 AND current_month=?"
      ).bind(cursor, current).run();
    } else {
      await env.DB.prepare(
        "DELETE FROM secure_drop_file_chunks WHERE transfer_id IN (SELECT id FROM secure_drop_transfers WHERE storage_backend='d1' AND month_key<>?)"
      ).bind(current).run();
      const remainingChunks = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM secure_drop_file_chunks c JOIN secure_drop_transfers t ON t.id=c.transfer_id WHERE t.storage_backend='d1' AND t.month_key<>?"
      ).bind(current).first();
      if (Number(remainingChunks?.count || 0) !== 0) throw new Error("D1_CHUNK_DELETION_VERIFICATION_FAILED");
      await env.DB.batch([
        env.DB.prepare("DELETE FROM secure_drop_deletion_jobs WHERE transfer_id IN (SELECT id FROM secure_drop_transfers WHERE month_key<>?)").bind(current),
        env.DB.prepare("DELETE FROM secure_drop_preempted_uploads WHERE month_key<>?").bind(current),
        env.DB.prepare("DELETE FROM secure_drop_transfers WHERE month_key<>?").bind(current),
        env.DB.prepare("DELETE FROM secure_drop_credit_ledger WHERE month_key<>?").bind(current),
        env.DB.prepare("DELETE FROM secure_drop_credit_accounts WHERE month_key<>?").bind(current),
        env.DB.prepare(
          "UPDATE secure_drop_maintenance SET cursor=NULL, completed_at=? WHERE id=1 AND current_month=?"
        ).bind(now, current)
      ]);
      return true;
    }
  }
  return false;
}

export async function handleSecureDropApi(request, env, context) {
  const { path, method, readCookie, getSession, sameOrigin, checkRateLimit } = context;
  if (!path.startsWith("/api/secure-drop/")) return null;

  if (method !== "GET" && !sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);

  let session;
  try {
    session = await getSession(env, readCookie(request));
  } catch {
    return json({ error: "AUTH_UNAVAILABLE" }, 503);
  }
  if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
  const now = Date.now();
  const currentMonth = secureDropMonthKey(now);

  if (path === "/api/secure-drop/credits" && method === "GET") {
    const [account, usedBytes] = await Promise.all([
      ensureMonthlyAccount(env, session.id, currentMonth, now),
      getD1StorageUsedBytes(env)
    ]);
    return json({
      month: currentMonth,
      granted: Number(account?.granted_credits || MONTHLY_CREDITS),
      balance: Number(account?.balance ?? 0),
      creditsPerMB: 1,
      priorityCreditsPerMB: PRIORITY_CREDIT_MULTIPLIER,
      billingBasis: "measured_encrypted_stored_bytes",
      storageBackend: "d1-chunks",
      storageUsedBytes: usedBytes,
      storageCapacityBytes: D1_STORAGE_CAPACITY_BYTES,
      storageSoftLimitBytes: D1_STORAGE_SOFT_LIMIT_BYTES,
      uploadsPaused: usedBytes >= D1_STORAGE_SOFT_LIMIT_BYTES,
      chunkSizeBytes: D1_CHUNK_SIZE_BYTES,
      maxStoredBytes: MAX_STORED_BYTES,
      maxOriginalBytes: MAX_ORIGINAL_BYTES,
      originalSizeIsClientReported: true,
      resetAt: secureDropNextMonthStart(now)
    });
  }

  if (path === "/api/secure-drop/files" && method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT t.id, t.user_id, t.recipient_user_id, owner.user_id AS owner_user_name, recipient.user_id AS recipient_user_name, t.original_size_bytes, t.stored_size_bytes, t.created_at, t.expires_at, t.download_count, t.download_limit, t.key_envelope_json, t.status FROM secure_drop_transfers t JOIN users owner ON owner.id=t.user_id JOIN users recipient ON recipient.id=t.recipient_user_id LEFT JOIN verified_contact_pairs contacts ON contacts.user_a_id=CASE WHEN t.user_id<t.recipient_user_id THEN t.user_id ELSE t.recipient_user_id END AND contacts.user_b_id=CASE WHEN t.user_id<t.recipient_user_id THEN t.recipient_user_id ELSE t.user_id END WHERE (t.user_id=? OR (t.recipient_user_id=? AND contacts.user_a_id IS NOT NULL)) AND t.month_key=? AND t.expires_at>? AND t.status='ready' ORDER BY t.created_at DESC LIMIT 100"
    ).bind(session.id, session.id, currentMonth, now).all();
    const preempted = await env.DB.prepare(
      "SELECT p.transfer_id, recipient.user_id AS peer_user_id, p.original_size_bytes, p.stored_size_bytes, p.created_at FROM secure_drop_preempted_uploads p JOIN users recipient ON recipient.id=p.recipient_user_id WHERE p.user_id=? AND p.month_key=? AND p.acknowledged_at IS NULL ORDER BY p.created_at ASC LIMIT 20"
    ).bind(session.id, currentMonth).all();
    return json({
      files: (rows.results || []).map((row) => {
        const received = row.recipient_user_id === session.id;
        return {
          id: row.id,
          direction: received ? "received" : "sent",
          peerUserId: received ? row.owner_user_name : row.recipient_user_name,
          senderUserId: row.owner_user_name,
          originalSizeBytes: Number(row.original_size_bytes),
          originalSizeIsClientReported: true,
          storedSizeBytes: Number(row.stored_size_bytes),
          createdAt: Number(row.created_at),
          expiresAt: Number(row.expires_at),
          downloadCount: Number(row.download_count),
          downloadLimit: DOWNLOAD_LIMIT,
          downloadsRemaining: Math.max(0, DOWNLOAD_LIMIT - Number(row.download_count)),
          priority: Number(row.priority || 0) === 1,
          ...(received ? {
            downloadPath: "/api/secure-drop/download/" + row.id,
            keyEnvelope: (() => { try { return JSON.parse(row.key_envelope_json); } catch { return null; } })()
          } : {})
        };
      }),
      preemptedUploads: (preempted.results || []).map((row) => ({
        transferId: row.transfer_id,
        peerUserId: row.peer_user_id,
        originalSizeBytes: Number(row.original_size_bytes),
        storedSizeBytes: Number(row.stored_size_bytes),
        createdAt: Number(row.created_at)
      }))
    });
  }

  const downloadMatch = path.match(/^\/api\/secure-drop\/download\/([a-f0-9-]{36})$/i);
  if (downloadMatch && method === "GET") {
    if (!await checkRateLimit(env, request, "secure-drop-download", 30)) {
      return json({ error: "RATE_LIMITED" }, 429);
    }
    const transferId = downloadMatch[1];
    const transfer = await env.DB.prepare(
      "SELECT object_key, stored_size_bytes, expires_at, month_key, download_count, status, user_id, recipient_user_id, storage_backend, key_envelope_json FROM secure_drop_transfers WHERE id=? AND recipient_user_id=?"
    ).bind(transferId, session.id).first();
    if (!transfer || transfer.month_key !== currentMonth || transfer.expires_at <= now ||
        transfer.status !== "ready") {
      return json({ error: "TRANSFER_EXPIRED_OR_NOT_FOUND" }, 404);
    }
    const [contactA, contactB] = transfer.user_id < transfer.recipient_user_id
      ? [transfer.user_id, transfer.recipient_user_id]
      : [transfer.recipient_user_id, transfer.user_id];
    const activeContact = await env.DB.prepare(
      "SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?"
    ).bind(contactA, contactB).first();
    if (!activeContact) return json({ error: "TRANSFER_EXPIRED_OR_NOT_FOUND" }, 404);
    if (Number(transfer.download_count) >= DOWNLOAD_LIMIT) {
      return json({ error: "DOWNLOAD_LIMIT_REACHED" }, 410);
    }
    let payloadBody;
    let payloadSize = Number(transfer.stored_size_bytes);
    if (transfer.storage_backend === "d1") {
      const chunks = await env.DB.prepare(
        "SELECT chunk_index, chunk_data, chunk_size_bytes, sha256 FROM secure_drop_file_chunks WHERE transfer_id=? ORDER BY chunk_index ASC"
      ).bind(transferId).all();
      const rows = chunks.results || [];
      const expectedCount = Math.ceil(payloadSize / D1_CHUNK_SIZE_BYTES);
      let total = 0;
      const assembled = new Uint8Array(payloadSize);
      let valid = rows.length === expectedCount;
      for (let i = 0; valid && i < rows.length; i += 1) {
        const row = rows[i];
        const data = row.chunk_data instanceof Uint8Array
          ? row.chunk_data
          : new Uint8Array(row.chunk_data);
        const expectedLength = Math.min(D1_CHUNK_SIZE_BYTES, payloadSize - total);
        if (Number(row.chunk_index) !== i || data.byteLength !== expectedLength ||
            Number(row.chunk_size_bytes) !== expectedLength ||
            await digestBytes(data) !== row.sha256) {
          valid = false;
          break;
        }
        assembled.set(data, total);
        total += data.byteLength;
      }
      let envelope = null;
      try { envelope = JSON.parse(transfer.key_envelope_json); } catch {}
      if (!valid || total !== payloadSize || !envelope ||
          await digestBytes(assembled) !== envelope.ciphertextSha256) {
        await env.DB.prepare(
          "UPDATE secure_drop_transfers SET status='deleting', updated_at=? WHERE id=? AND status='ready'"
        ).bind(now, transferId).run().catch(() => {});
        return json({ error: "STORED_FILE_INTEGRITY_MISMATCH" }, 503);
      }
      payloadBody = assembled;
    } else {
      if (!env.SECURE_DROP_R2) {
        return json({ error: "LEGACY_STORAGE_UNAVAILABLE", message: "この旧保存ファイルは現在取得できません。" }, 503);
      }
      const object = await env.SECURE_DROP_R2.get(transfer.object_key);
      if (!object) return json({ error: "FILE_NOT_FOUND" }, 404);
      if (Number(object.size) !== payloadSize) {
        await env.DB.prepare(
          "UPDATE secure_drop_transfers SET status='deleting', updated_at=? WHERE id=? AND status='ready'"
        ).bind(now, transferId).run().catch(() => {});
        return json({ error: "STORED_FILE_INTEGRITY_MISMATCH" }, 503);
      }
      payloadBody = object.body;
    }
    const consumed = await env.DB.prepare(
      "UPDATE secure_drop_transfers SET download_count=download_count+1, updated_at=? WHERE id=? AND month_key=? AND expires_at>? AND status='ready' AND download_count<3 AND recipient_user_id=? RETURNING download_count"
    ).bind(now, transferId, currentMonth, now, session.id).first();
    if (!consumed) return json({ error: "DOWNLOAD_LIMIT_REACHED" }, 410);
    return new Response(payloadBody, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(payloadSize),
        "Content-Disposition": 'attachment; filename="secure-drop-' + transferId + '.bin"',
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  if (path === "/api/secure-drop/files" && method === "POST") {
    if (!await checkRateLimit(env, request, "secure-drop-upload", 10)) {
      return json({ error: "RATE_LIMITED" }, 429);
    }
    const originalBytes = Number(request.headers.get("X-Secure-Drop-Original-Size"));
    const storedSizeHeader = request.headers.get("X-Secure-Drop-Stored-Size") || request.headers.get("Content-Length");
    const declaredStoredBytes = /^[1-9][0-9]{0,8}$/.test(storedSizeHeader || "")
      ? Number(storedSizeHeader)
      : NaN;
    if (!Number.isSafeInteger(originalBytes) || originalBytes < 1 || originalBytes > MAX_ORIGINAL_BYTES) {
      return json({ error: "INVALID_REPORTED_ORIGINAL_SIZE", maxBytes: MAX_ORIGINAL_BYTES }, 400);
    }
    if (!Number.isSafeInteger(declaredStoredBytes) || declaredStoredBytes < 17 ||
        declaredStoredBytes > MAX_STORED_BYTES || !request.body) {
      return json({ error: "INVALID_STORED_FILE_SIZE", maxBytes: MAX_STORED_BYTES }, 413);
    }
    if (request.headers.get("X-Secure-Drop-Payload") !== "encrypted-v1") {
      return json({ error: "ENCRYPTED_PAYLOAD_REQUIRED" }, 400);
    }
    const uploadId = request.headers.get("X-Secure-Drop-Upload-Id") || "";
    if (!UUID_PATTERN.test(uploadId)) return json({ error: "UPLOAD_ID_REQUIRED" }, 400);
    const priority = request.headers.get("X-Secure-Drop-Priority") === "1" ? 1 : 0;
    const recipientId = request.headers.get("X-Secure-Drop-Recipient-Id") || "";
    const encodedEnvelope = request.headers.get("X-Secure-Drop-Key-Envelope") || "";
    let envelope;
    try {
      envelope = JSON.parse(new TextDecoder().decode(decodeBase64Url(encodedEnvelope)));
    } catch {
      return json({ error: "SECURE_DROP_KEY_ENVELOPE_INVALID" }, 400);
    }
    const recipient = await lookupRecipient(env, session.id, recipientId);
    if (!recipient) return json({ error: "SECURE_DROP_RECIPIENT_NOT_AUTHORIZED" }, 403);
    const [recipientFingerprint, senderSigningPublicKey] = await Promise.all([
      digest(recipient.identity_public_key),
      lookupSenderSigningKey(env, session.id)
    ]);
    if (!senderSigningPublicKey ||
        !validateSecureDropKeyEnvelope(envelope, recipientFingerprint, session.user_id, senderSigningPublicKey)) {
      return json({ error: "SECURE_DROP_KEY_ENVELOPE_INVALID" }, 400);
    }
    if (!await verifySecureDropKeyEnvelopeSignature(envelope)) {
      return json({ error: "SECURE_DROP_SENDER_SIGNATURE_INVALID" }, 400);
    }

    const credits = secureDropCreditsForBytes(
      declaredStoredBytes,
      priority ? PRIORITY_CREDIT_MULTIPLIER : 1
    );
    const account = await ensureMonthlyAccount(env, session.id, currentMonth, now);
    if (!account || Number(account.balance) < credits) {
      return json({ error: "INSUFFICIENT_CREDITS", required: credits, balance: Number(account?.balance || 0) }, 402);
    }

    const envelopeJson = JSON.stringify(envelope);
    const existing = await env.DB.prepare(
      "SELECT id, recipient_user_id, original_size_bytes, stored_size_bytes, key_envelope_json, status, storage_backend, priority, month_key FROM secure_drop_transfers WHERE id=? AND user_id=?"
    ).bind(uploadId, session.id).first();
    if (existing && (
      existing.recipient_user_id !== recipient.id ||
      Number(existing.original_size_bytes) !== originalBytes ||
      Number(existing.stored_size_bytes) !== declaredStoredBytes ||
      existing.key_envelope_json !== envelopeJson ||
      existing.storage_backend !== "d1" ||
      Number(existing.priority || 0) !== priority
    )) {
      return json({ error: "UPLOAD_ID_CONFLICT" }, 409);
    }
    if (existing?.status === "ready") {
      return json({
        created: true,
        alreadyComplete: true,
        id: uploadId,
        recipientUserId: recipient.user_id,
        downloadPath: "/api/secure-drop/download/" + uploadId,
        originalSizeBytes: originalBytes,
        originalSizeIsClientReported: true,
        storedSizeBytes: declaredStoredBytes,
        creditsConsumed: credits,
        downloadsRemaining: Math.max(0, DOWNLOAD_LIMIT - Number(existing.download_count || 0)),
        expiresAt: Math.min(now + TRANSFER_TTL_MS, secureDropNextMonthStart(now))
      }, 201);
    }
    if (existing && (existing.status !== "pending" || existing.month_key !== currentMonth)) {
      return json({ error: "UPLOAD_RESERVATION_UNAVAILABLE" }, 409);
    }

    const expiresAt = Math.min(now + TRANSFER_TTL_MS, secureDropNextMonthStart(now));
    const objectKey = "d1:" + uploadId;
    const tokenHash = await digest("disabled-secure-drop-token:" + uploadId);
    if (!existing) {
      let usedBytes = await getD1StorageUsedBytes(env);
      const capacityLimit = priority ? D1_STORAGE_CAPACITY_BYTES : D1_STORAGE_SOFT_LIMIT_BYTES;
      if (priority && usedBytes + declaredStoredBytes > D1_STORAGE_CAPACITY_BYTES) {
        const reclaimed = await preemptPendingUploads(env, declaredStoredBytes, now);
        if (!reclaimed) {
          return json({
            error: "SECURE_DROP_CAPACITY_REACHED",
            usedBytes,
            capacityBytes: D1_STORAGE_CAPACITY_BYTES
          }, 507);
        }
        usedBytes = await getD1StorageUsedBytes(env);
      }
      if (usedBytes + declaredStoredBytes > capacityLimit) {
        return json({
          error: priority ? "SECURE_DROP_CAPACITY_REACHED" : "SECURE_DROP_UPLOADS_PAUSED",
          usedBytes,
          capacityBytes: D1_STORAGE_CAPACITY_BYTES,
          softLimitBytes: D1_STORAGE_SOFT_LIMIT_BYTES
        }, 507);
      }
      let pendingCreated = false;
      try {
        pendingCreated = await createPendingTransfer(env, {
          transferId: uploadId,
          ownerId: session.id,
          recipientId: recipient.id,
          month: currentMonth,
          objectKey,
          tokenHash,
          originalBytes,
          storedBytes: declaredStoredBytes,
          envelopeJson,
          credits,
          now,
          expiresAt,
          priority,
          capacityLimit
        });
      } catch {
        return json({ error: "CREDIT_RESERVATION_FAILED" }, 503);
      }
      if (!pendingCreated) {
        const [refreshed, refreshedUsage] = await Promise.all([
          env.DB.prepare(
            "SELECT balance FROM secure_drop_credit_accounts WHERE user_id=? AND month_key=?"
          ).bind(session.id, currentMonth).first(),
          getD1StorageUsedBytes(env)
        ]);
        if (Number(refreshed?.balance || 0) < credits) {
          return json({ error: "INSUFFICIENT_CREDITS", required: credits, balance: Number(refreshed?.balance || 0) }, 402);
        }
        return json({
          error: priority ? "SECURE_DROP_CAPACITY_REACHED" : "SECURE_DROP_UPLOADS_PAUSED",
          usedBytes: refreshedUsage,
          capacityBytes: D1_STORAGE_CAPACITY_BYTES,
          softLimitBytes: D1_STORAGE_SOFT_LIMIT_BYTES
        }, 507);
      }
    }

    let ciphertext;
    try {
      ciphertext = await readBodyBounded(request.body, MAX_STORED_BYTES);
      if (ciphertext.byteLength !== declaredStoredBytes) throw new Error("STORED_SIZE_MISMATCH");
      if (await digestBytes(ciphertext) !== envelope.ciphertextSha256) {
        throw new Error("STORED_FILE_INTEGRITY_MISMATCH");
      }
    } catch (error) {
      const code = String(error?.message || error);
      if (code !== "UPLOAD_BODY_REQUIRED") {
        await abandonPendingTransfer(env, {
          id: uploadId,
          ownerId: session.id,
          month: currentMonth,
          objectKey,
          storageBackend: "d1"
        }, credits, Date.now());
      }
      if (code === "STORED_SIZE_LIMIT_EXCEEDED") {
        return json({ error: "STORED_FILE_TOO_LARGE", maxBytes: MAX_STORED_BYTES }, 413);
      }
      if (code === "STORED_SIZE_MISMATCH") return json({ error: "STORED_SIZE_MISMATCH" }, 400);
      if (code === "STORED_FILE_INTEGRITY_MISMATCH") return json({ error: code }, 400);
      return json({ error: "UPLOAD_BODY_INVALID" }, 400);
    }

    const statements = [];
    const chunkCount = Math.ceil(ciphertext.byteLength / D1_CHUNK_SIZE_BYTES);
    for (let index = 0; index < chunkCount; index += 1) {
      const start = index * D1_CHUNK_SIZE_BYTES;
      const data = ciphertext.slice(start, Math.min(ciphertext.byteLength, start + D1_CHUNK_SIZE_BYTES));
      const chunkHash = await digestBytes(data);
      statements.push(env.DB.prepare(
        "INSERT INTO secure_drop_file_chunks (transfer_id, chunk_index, chunk_data, chunk_size_bytes, sha256, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM secure_drop_transfers WHERE id=? AND user_id=? AND month_key=? AND status='pending' AND storage_backend='d1')"
      ).bind(uploadId, index, data, data.byteLength, chunkHash, now, uploadId, session.id, currentMonth));
    }
    statements.push(env.DB.prepare(
      "UPDATE secure_drop_transfers SET status='ready', stored_size_bytes=?, updated_at=? WHERE id=? AND user_id=? AND month_key=? AND status='pending' AND storage_backend='d1' AND (SELECT COUNT(*) FROM secure_drop_file_chunks WHERE transfer_id=?)=? AND (SELECT COALESCE(SUM(chunk_size_bytes),0) FROM secure_drop_file_chunks WHERE transfer_id=?)=? AND (SELECT MIN(chunk_index) FROM secure_drop_file_chunks WHERE transfer_id=?)=0 AND (SELECT MAX(chunk_index) FROM secure_drop_file_chunks WHERE transfer_id=?)=?"
    ).bind(declaredStoredBytes, Date.now(), uploadId, session.id, currentMonth, uploadId, chunkCount, uploadId, declaredStoredBytes, uploadId, uploadId, chunkCount - 1));

    let storedResults;
    try {
      storedResults = await env.DB.batch(statements);
    } catch {
      return json({ error: "UPLOAD_STORAGE_FAILED", message: "D1への暗号化データ保存に失敗しました。暗号化データは送信端末に保持してください。" }, 503);
    }
    if (Number(storedResults?.[storedResults.length - 1]?.meta?.changes || 0) !== 1) {
      const current = await env.DB.prepare(
        "SELECT status FROM secure_drop_transfers WHERE id=? AND user_id=?"
      ).bind(uploadId, session.id).first();
      if (!current) return json({ error: "UPLOAD_PREEMPTED", message: "優先容量確保のため、このアップロード予約は取り消されました。端末内の保留データから再送信できます。" }, 409);
      if (current.status !== "ready") {
        return json({ error: "UPLOAD_FINALIZATION_PENDING", message: "保存完了を確認できませんでした。端末内データを保持して再送信してください。" }, 503);
      }
    }

    return json({
      created: true,
      id: uploadId,
      recipientUserId: recipient.user_id,
      downloadPath: "/api/secure-drop/download/" + uploadId,
      originalSizeBytes: originalBytes,
      originalSizeIsClientReported: true,
      storedSizeBytes: declaredStoredBytes,
      creditsConsumed: credits,
      downloadsRemaining: DOWNLOAD_LIMIT,
      expiresAt
    }, 201);
  }

  const deleteMatch = path.match(/^\/api\/secure-drop\/files\/([a-f0-9-]{36})$/i);
  if (deleteMatch && method === "DELETE") {
    const transferId = deleteMatch[1];
    const row = await env.DB.prepare(
      "SELECT object_key, storage_backend FROM secure_drop_transfers WHERE id=? AND user_id=? AND month_key=? AND status IN ('ready','deleting')"
    ).bind(transferId, session.id, currentMonth).first();
    if (!row) return json({ error: "TRANSFER_NOT_FOUND" }, 404);
    await env.DB.prepare(
      "UPDATE secure_drop_transfers SET status='deleting', updated_at=? WHERE id=? AND user_id=? AND month_key=?"
    ).bind(now, transferId, session.id, currentMonth).run();
    const verified = await verifyAndFinalizeDeletion(env, transferId, row.object_key, now, "user_delete", row.storage_backend);
    if (!verified) {
      return json({
        deleted: false,
        status: "verifying",
        error: "DELETE_PENDING",
        message: "削除要求を受け付けました。実際の削除を確認できるまで再試行します。"
      }, 202);
    }
    return json({ deleted: true, verified: true });
  }

  return json({ error: "NOT_FOUND" }, 404);
}

export async function runSecureDropMaintenance(env, now = Date.now()) {
  const current = secureDropMonthKey(now);
  try {
    if (env.SECURE_DROP_R2) await processDeletionJobs(env, now);
    await cleanupStaleTransfers(env, now);
    if (!env.SECURE_DROP_R2) {
      const completed = await purgeOldMonthD1Only(env, now);
      return { month: current, status: completed ? "ok" : "more_pending" };
    }
    const completed = await purgeOldMonthObjects(env, now);
    return { month: current, status: completed ? "ok" : "more_pending" };
  } catch {
    // Never log file keys, bearer material, or user identifiers. The next cron tick retries.
    return { month: current, status: "retry_pending" };
  }
}

export const SECURE_DROP_LIMITS = Object.freeze({
  maxOriginalBytes: MAX_ORIGINAL_BYTES,
  maxStoredBytes: MAX_STORED_BYTES,
  storageCapacityBytes: D1_STORAGE_CAPACITY_BYTES,
  storageSoftLimitBytes: D1_STORAGE_SOFT_LIMIT_BYTES,
  chunkSizeBytes: D1_CHUNK_SIZE_BYTES,
  priorityCreditMultiplier: PRIORITY_CREDIT_MULTIPLIER,
  monthlyCredits: MONTHLY_CREDITS,
  downloadLimit: DOWNLOAD_LIMIT,
  transferTtlMs: TRANSFER_TTL_MS
});
