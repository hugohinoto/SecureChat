const MAX_ORIGINAL_BYTES = 100_000_000;
const MAX_STORED_BYTES = 101_000_000;
const MONTHLY_CREDITS = 100;
const DOWNLOAD_LIMIT = 3;
const TRANSFER_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const JST_OFFSET_MS = 9 * 60 * 60 * 1000;
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", ...headers } });
}

function monthKey(now) {
  return new Date(now + JST_OFFSET_MS).toISOString().slice(0, 7);
}

function nextMonthStart(now) {
  const jst = new Date(now + JST_OFFSET_MS);
  return Date.UTC(jst.getUTCFullYear(), jst.getUTCMonth() + 1, 1) - JST_OFFSET_MS;
}

function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function digest(value) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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
  // A previous month's balance is expired; never recreate rows after the monthly purge.
  if (monthKey(now) !== month) return;
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE secure_drop_credit_accounts SET balance=MIN(granted_credits, balance+?), updated_at=? WHERE user_id=? AND month_key=?"
    ).bind(credits, now, userId, month),
    env.DB.prepare(
      "INSERT OR IGNORE INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at) VALUES (?, ?, ?, ?, 'upload_refund', ?, ?)"
    ).bind("refund:" + transferId, userId, month, credits, transferId, now)
  ]);
}

async function purgeOldMonthObjects(env, now) {
  const bucket = env.SECURE_DROP_R2;
  if (!bucket) return;
  const current = monthKey(now);
  let state = await env.DB.prepare(
    "SELECT current_month, cursor, completed_at FROM secure_drop_maintenance WHERE id=1"
  ).first();
  if (!state || state.current_month !== current) {
    await env.DB.prepare(
      "INSERT INTO secure_drop_maintenance (id, current_month, cursor, completed_at) VALUES (1, ?, NULL, NULL) ON CONFLICT(id) DO UPDATE SET current_month=excluded.current_month, cursor=NULL, completed_at=NULL"
    ).bind(current).run();
    state = { current_month: current, cursor: null, completed_at: null };
  }

  await env.DB.batch([
    env.DB.prepare("DELETE FROM secure_drop_transfers WHERE month_key<>?").bind(current),
    env.DB.prepare("DELETE FROM secure_drop_credit_ledger WHERE month_key<>?").bind(current),
    env.DB.prepare("DELETE FROM secure_drop_credit_accounts WHERE month_key<>?").bind(current)
  ]);

  if (state.completed_at) return;
  const page = await bucket.list({
    prefix: "secure-drop/",
    limit: 1000,
    ...(state.cursor ? { cursor: state.cursor } : {})
  });
  const obsolete = (page.objects || []).filter((item) => {
    const parts = item.key.split("/");
    return parts.length >= 3 && parts[0] === "secure-drop" && parts[1] !== current;
  }).map((item) => item.key);
  if (obsolete.length) await bucket.delete(obsolete);
  await env.DB.prepare(
    "UPDATE secure_drop_maintenance SET cursor=?, completed_at=? WHERE id=1 AND current_month=?"
  ).bind(page.truncated ? page.cursor : null, page.truncated ? null : now, current).run();
}

export async function handleSecureDropApi(request, env, context) {
  const { url, path, method, readCookie, getSession, sameOrigin, checkRateLimit } = context;
  if (!path.startsWith("/api/secure-drop/")) return null;

  if (method !== "GET" && !sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
  if (!env.SECURE_DROP_R2) return json({ error: "SECURE_DROP_STORAGE_UNAVAILABLE", message: "ファイル保存先がまだ設定されていません。" }, 503);

  const now = Date.now();
  const currentMonth = monthKey(now);
  const downloadMatch = path.match(/^\/api\/secure-drop\/download\/([a-f0-9-]{36})$/i);

  if (downloadMatch && method === "GET") {
    if (!await checkRateLimit(env, request, "secure-drop-download", 30)) return json({ error: "RATE_LIMITED" }, 429);
    const transferId = downloadMatch[1];
    const suppliedToken = request.headers.get("X-Secure-Drop-Token") || "";
    if (!/^[A-Za-z0-9_-]{40,48}$/.test(suppliedToken)) return json({ error: "INVALID_DOWNLOAD_TOKEN" }, 401);
    const transfer = await env.DB.prepare(
      "SELECT object_key, token_hash, expires_at, month_key, download_count, download_limit FROM secure_drop_transfers WHERE id=?"
    ).bind(transferId).first();
    if (!transfer || transfer.month_key !== currentMonth || transfer.expires_at <= now) return json({ error: "TRANSFER_EXPIRED_OR_NOT_FOUND" }, 404);
    if (await digest(suppliedToken) !== transfer.token_hash) return json({ error: "INVALID_DOWNLOAD_TOKEN" }, 403);
    if (Number(transfer.download_count) >= DOWNLOAD_LIMIT) return json({ error: "DOWNLOAD_LIMIT_REACHED" }, 410);

    const object = await env.SECURE_DROP_R2.get(transfer.object_key);
    if (!object) return json({ error: "FILE_NOT_FOUND" }, 404);
    const consumed = await env.DB.prepare(
      "UPDATE secure_drop_transfers SET download_count=download_count+1 WHERE id=? AND month_key=? AND expires_at>? AND download_count<3 AND token_hash=? RETURNING download_count"
    ).bind(transferId, currentMonth, now, transfer.token_hash).first();
    if (!consumed) return json({ error: "DOWNLOAD_LIMIT_REACHED" }, 410);
    return new Response(object.body, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(object.size),
        "Content-Disposition": 'attachment; filename="secure-drop-' + transferId + '.bin"',
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  let session;
  try { session = await getSession(env, readCookie(request)); }
  catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
  if (!session) return json({ error: "UNAUTHENTICATED" }, 401);

  if (path === "/api/secure-drop/credits" && method === "GET") {
    const account = await ensureMonthlyAccount(env, session.id, currentMonth, now);
    return json({
      month: currentMonth,
      granted: Number(account?.granted_credits || MONTHLY_CREDITS),
      balance: Number(account?.balance || 0),
      creditsPerMB: 1,
      maxFileBytes: MAX_ORIGINAL_BYTES,
      resetAt: nextMonthStart(now)
    });
  }

  if (path === "/api/secure-drop/files" && method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT id, original_size_bytes, stored_size_bytes, created_at, expires_at, download_count, download_limit FROM secure_drop_transfers WHERE user_id=? AND month_key=? AND expires_at>? ORDER BY created_at DESC LIMIT 100"
    ).bind(session.id, currentMonth, now).all();
    return json({ files: rows.results || [] });
  }

  if (path === "/api/secure-drop/files" && method === "POST") {
    if (!await checkRateLimit(env, request, "secure-drop-upload", 10)) return json({ error: "RATE_LIMITED" }, 429);
    const originalBytes = Number(request.headers.get("X-Secure-Drop-Original-Size"));
    const storedBytes = Number(request.headers.get("Content-Length"));
    if (!Number.isSafeInteger(originalBytes) || originalBytes < 1 || originalBytes > MAX_ORIGINAL_BYTES) {
      return json({ error: "ORIGINAL_FILE_TOO_LARGE", maxBytes: MAX_ORIGINAL_BYTES }, 413);
    }
    if (!Number.isSafeInteger(storedBytes) || storedBytes < 1 || storedBytes > MAX_STORED_BYTES || !request.body) {
      return json({ error: "INVALID_STORED_FILE_SIZE", maxBytes: MAX_STORED_BYTES }, 413);
    }
    if (request.headers.get("X-Secure-Drop-Payload") !== "encrypted-v1") {
      return json({ error: "ENCRYPTED_PAYLOAD_REQUIRED" }, 400);
    }

    const credits = Math.max(1, Math.ceil(originalBytes / 1_000_000));
    const account = await ensureMonthlyAccount(env, session.id, currentMonth, now);
    if (!account || Number(account.balance) < credits) {
      return json({ error: "INSUFFICIENT_CREDITS", required: credits, balance: Number(account?.balance || 0) }, 402);
    }

    const transferId = crypto.randomUUID();
    const downloadToken = token();
    const tokenHash = await digest(downloadToken);
    const objectKey = "secure-drop/" + currentMonth + "/" + transferId;
    const expiresAt = Math.min(now + TRANSFER_TTL_MS, nextMonthStart(now));
    const debit = await env.DB.prepare(
      "UPDATE secure_drop_credit_accounts SET balance=balance-?, updated_at=? WHERE user_id=? AND month_key=? AND balance>=? RETURNING balance"
    ).bind(credits, now, session.id, currentMonth, credits).first();
    if (!debit) return json({ error: "INSUFFICIENT_CREDITS" }, 402);

    try {
      const storedObject = await env.SECURE_DROP_R2.put(objectKey, request.body, {
        httpMetadata: { contentType: "application/octet-stream" },
        customMetadata: { month: currentMonth, transferId }
      });
      // Do not let an upload that crossed the month boundary recreate old-month data
      // after the scheduled purge has already completed.
      if (monthKey(Date.now()) !== currentMonth || Date.now() >= expiresAt) {
        throw new Error("MONTH_CLOSED");
      }
      if (storedObject?.size != null && Number(storedObject.size) !== storedBytes) {
        throw new Error("STORED_SIZE_MISMATCH");
      }
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO secure_drop_transfers (id, user_id, month_key, object_key, token_hash, original_size_bytes, stored_size_bytes, created_at, expires_at, download_count, download_limit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 3)"
        ).bind(transferId, session.id, currentMonth, objectKey, tokenHash, originalBytes, storedBytes, now, expiresAt),
        env.DB.prepare(
          "INSERT INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at) VALUES (?, ?, ?, ?, 'upload_debit', ?, ?)"
        ).bind("debit:" + transferId, session.id, currentMonth, -credits, transferId, now)
      ]);
    } catch (error) {
      await env.SECURE_DROP_R2.delete(objectKey).catch(() => {});
      await refundCredits(env, session.id, currentMonth, credits, transferId, Date.now()).catch(() => {});
      if (String(error?.message || error) === "MONTH_CLOSED") {
        return json({ error: "MONTHLY_RESET_IN_PROGRESS", message: "月次リセット時刻をまたいだため、転送を中止しました。" }, 409);
      }
      return json({ error: "UPLOAD_STORAGE_FAILED", message: "転送ファイルを保存できませんでした。クレジットは返却処理を行いました。" }, 503);
    }

    return json({
      created: true,
      id: transferId,
      downloadPath: "/api/secure-drop/download/" + transferId,
      downloadToken,
      originalSizeBytes: originalBytes,
      storedSizeBytes: storedBytes,
      creditsConsumed: credits,
      downloadsRemaining: DOWNLOAD_LIMIT,
      expiresAt
    }, 201);
  }

  const deleteMatch = path.match(/^\/api\/secure-drop\/files\/([a-f0-9-]{36})$/i);
  if (deleteMatch && method === "DELETE") {
    const row = await env.DB.prepare(
      "SELECT object_key FROM secure_drop_transfers WHERE id=? AND user_id=? AND month_key=?"
    ).bind(deleteMatch[1], session.id, currentMonth).first();
    if (!row) return json({ error: "TRANSFER_NOT_FOUND" }, 404);
    await env.SECURE_DROP_R2.delete(row.object_key);
    await env.DB.prepare("DELETE FROM secure_drop_transfers WHERE id=? AND user_id=?").bind(deleteMatch[1], session.id).run();
    return json({ deleted: true });
  }

  return json({ error: "NOT_FOUND" }, 404);
}

export async function runSecureDropMaintenance(env, now = Date.now()) {
  const current = monthKey(now);
  try {
    await purgeOldMonthObjects(env, now);
    return { month: current, status: "ok" };
  } catch {
    // Do not log file keys, tokens, or user identifiers. The next cron tick retries.
    return { month: current, status: "retry_pending" };
  }
}
