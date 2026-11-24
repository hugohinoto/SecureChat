import { DurableObject } from "cloudflare:workers";
import { handleAdminFeatures } from "./admin-features.js";
import { encryptStored, migrateSensitiveRows } from "./data-crypto.js";
import { identityKeyTransitionMessage, verifyIdentityKeyProof, verifyIdentityKeyTransition } from "./identity-keys.js";
import { handleCryptoApi } from "./crypto-api.js";
import { handleSecureDropApi, runSecureDropMaintenance } from "./secure-drop.js";

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 100_000;
const ADMIN_PASSWORD_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
const MAX_MESSAGE_LENGTH = 2_000;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_RETENTION_MS = 24 * 60 * 60 * 1000;

const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store", ...headers }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function randomToken() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function createOtp() {
  const limit = Math.floor(0x1_0000_0000 / 100_000_000) * 100_000_000;
  let value;
  do { value = crypto.getRandomValues(new Uint32Array(1))[0]; } while (value >= limit);
  return String(value % 100_000_000).padStart(8, "0");
}

async function otpDigest(env, invitationId, purpose, code) {
  const pepper = env.CONTACT_OTP_PEPPER;
  if (typeof pepper !== "string" || pepper.length < 32) throw new Error("CONTACT_OTP_NOT_CONFIGURED");
  const key = await crypto.subtle.importKey("raw", encoder.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(invitationId + ":" + purpose + ":" + code));
  return base64url(new Uint8Array(signature));
}

function orderedPair(left, right) {
  return left < right ? [left, right] : [right, left];
}

function normalizeUserId(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9_]{3,32}$/.test(normalized) ? normalized : null;
}

function validPassword(value) {
  return typeof value === "string" &&
    Array.from(value).length >= 12 &&
    Array.from(value).length <= 128 &&
    encoder.encode(value).byteLength <= 512;
}

function validIdentityBackup(value) {
  if (!value || typeof value !== "object" || value.version !== 1) return false;
  const validBase64 = (input, maxLength) =>
    typeof input === "string" &&
    input.length <= maxLength &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input);
  try {
    const salt = validBase64(value.salt, 64) ? atob(value.salt) : "";
    const iv = validBase64(value.iv, 32) ? atob(value.iv) : "";
    const ciphertext = validBase64(value.ciphertext, 16000) ? atob(value.ciphertext) : "";
    return salt.length === 16 && iv.length === 12 && ciphertext.length >= 64 && ciphertext.length <= 12000;
  } catch {
    return false;
  }
}

async function derivePassword(password, salt, iterations = PASSWORD_ITERATIONS) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256
  );
  return new Uint8Array(bits);
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function cookieName(request) {
  return new URL(request.url).protocol === "https:" ? "__Host-sc_session" : "sc_session";
}

function readCookie(request) {
  const name = cookieName(request);
  const cookieHeader = request.headers.get("Cookie") ?? "";
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

function setSessionCookie(response, request, token) {
  const secure = new URL(request.url).protocol === "https:";
  const name = secure ? "__Host-sc_session" : "sc_session";
  response.headers.append(
    "Set-Cookie",
    `${name}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secure ? "; Secure" : ""}`
  );
}

function clearSessionCookie(response, request) {
  const secure = new URL(request.url).protocol === "https:";
  const name = secure ? "__Host-sc_session" : "sc_session";
  response.headers.append(
    "Set-Cookie",
    `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secure ? "; Secure" : ""}`
  );
}

async function getSession(env, token) {
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(
    `SELECT users.id, users.user_id, users.is_admin, users.password_changed_at, sessions.created_at, sessions.expires_at
       FROM sessions
       JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > ?
      LIMIT 1`
  ).bind(tokenHash, Date.now()).first();
}

async function createSession(env, userId) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
  ).bind(tokenHash, userId, now + SESSION_TTL_SECONDS * 1000, now).run();
  return { token, tokenHash };
}

async function checkRateLimit(env, request, action, maxAttempts) {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  // Store only a one-way digest, never the visitor's raw IP address.
  const bucketKey = await sha256("securechat-rate-limit:" + action + ":" + ip);
  const now = Date.now();
  const resetBefore = now - AUTH_WINDOW_MS;
  const expiresAt = now + RATE_LIMIT_RETENTION_MS;
  const bucket = await env.DB.prepare(
    `INSERT INTO rate_limit_buckets (bucket_key, window_started_at, request_count, expires_at)
     VALUES (?, ?, 1, ?)
     ON CONFLICT(bucket_key) DO UPDATE SET
       request_count = CASE
         WHEN rate_limit_buckets.window_started_at <= ? THEN 1
         ELSE rate_limit_buckets.request_count + 1
       END,
       window_started_at = CASE
         WHEN rate_limit_buckets.window_started_at <= ? THEN excluded.window_started_at
         ELSE rate_limit_buckets.window_started_at
       END,
       expires_at = excluded.expires_at
     RETURNING request_count`
  ).bind(bucketKey, now, expiresAt, resetBefore, resetBefore).first();
  return Number(bucket?.request_count ?? (maxAttempts + 1)) <= maxAttempts;
}

function securityHeaders(response, request) {
  const url = new URL(request.url);
  const wsOrigin = url.protocol === "https:" ? `wss://${url.host}` : `ws://${url.host}`;
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      `connect-src 'self' ${wsOrigin}`,
      "object-src 'none'",
      "base-uri 'self'",
      "frame-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "upgrade-insecure-requests"
    ].join("; ")
  );
  if (url.protocol === "https:") {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readJson(request) {
  const length = Number(request.headers.get("Content-Length") ?? 0);
  if (length > 16 * 1024) throw new Error("REQUEST_TOO_LARGE");
  try {
    return await request.json();
  } catch {
    throw new Error("INVALID_JSON");
  }
}

async function writeAdminAudit(env, session, action, targetUserId = null, details = {}) {
  const id = crypto.randomUUID();
  const encryptedDetails = await encryptStored(env, "admin-audit:" + id, JSON.stringify(details).slice(0, 4000));
  await env.DB.prepare(
    "INSERT INTO admin_audit_logs (id, admin_user_id, action, target_user_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(id, session.id, action, targetUserId, encryptedDetails, Date.now()).run();
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  const secureDropResponse = await handleSecureDropApi(request, env, {
    url, path, method, readCookie, getSession, sameOrigin, checkRateLimit
  });
  if (secureDropResponse) return secureDropResponse;

  const featureResponse = await handleAdminFeatures(request, env, {
    url, readCookie, getSession, checkRateLimit, sameOrigin, readJson, writeAdminAudit
  });
  if (featureResponse) return featureResponse;

  if (path.startsWith("/api/admin/")) {
    if (method !== "GET" && !sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    let admin;
    try { admin = await getSession(env, readCookie(request)); }
    catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!admin) return json({ error: "UNAUTHENTICATED" }, 401);
    if (Number(admin.is_admin) !== 1) return json({ error: "ADMIN_REQUIRED" }, 403);
    if (!admin.password_changed_at || Date.now() - Number(admin.password_changed_at) >= ADMIN_PASSWORD_MAX_AGE_MS) return json({ error: "PASSWORD_CHANGE_REQUIRED", message: "管理者パスワードの有効期限が切れています。先にパスワードを変更してください。" }, 428);
    if (Date.now() - Number(admin.created_at) > 15 * 60 * 1000) {
      return json({ error: "ADMIN_REAUTH_REQUIRED", message: "管理者操作には直近15分以内のログインが必要です。ログアウトして再ログインしてください。" }, 428);
    }
    if (method !== "GET" && !await checkRateLimit(env, request, "admin-write", 30)) {
      return json({ error: "RATE_LIMITED" }, 429);
    }

    try {
      if (path === "/api/admin/overview" && method === "GET") {
        const now = Date.now();
        const [users, admins, sessions, messages, invitations, announcements, audit] = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS count FROM users").first(),
          env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE is_admin=1").first(),
          env.DB.prepare("SELECT COUNT(*) AS count FROM sessions WHERE expires_at>?").bind(now).first(),
          env.DB.prepare("SELECT COUNT(*) AS count FROM encrypted_messages WHERE expires_at>?").bind(now).first(),
          env.DB.prepare("SELECT COUNT(*) AS count FROM contact_invitations WHERE expires_at>?").bind(now).first(),
          env.DB.prepare("SELECT COUNT(*) AS count FROM announcements WHERE published=1 AND (expires_at>? OR (expires_at IS NULL AND published_at>?))").bind(now, now - 48 * 60 * 60 * 1000).first(),
          env.DB.prepare("SELECT COUNT(*) AS count FROM admin_audit_logs WHERE created_at>?").bind(now - 24 * 60 * 60 * 1000).first()
        ]);
        return json({
          database: "connected",
          users: Number(users?.count || 0),
          administrators: Number(admins?.count || 0),
          activeSessions: Number(sessions?.count || 0),
          activeMessages: Number(messages?.count || 0),
          pendingInvitations: Number(invitations?.count || 0),
          publishedAnnouncements: Number(announcements?.count || 0),
          adminActions24h: Number(audit?.count || 0),
          checkedAt: now,
          workerErrors: "Cloudflare Observabilityで確認してください。Workerログはこの管理APIからは取得できません。"
        });
      }

      if (path === "/api/admin/users" && method === "GET") {
        const q = (url.searchParams.get("q") || "").trim().toLowerCase().slice(0, 32);
        const page = Math.max(0, Math.min(1000, Number.parseInt(url.searchParams.get("page") || "0", 10) || 0));
        const filter = /^[a-z0-9_]{1,32}$/.test(q) ? q : "";
        const count = await env.DB.prepare(
          filter ? "SELECT COUNT(*) AS count FROM users WHERE user_id LIKE ?" : "SELECT COUNT(*) AS count FROM users"
        ).bind(...(filter ? [filter + "%"] : [])).first();
        const rows = await env.DB.prepare(
          filter
            ? "SELECT id, user_id, is_admin, created_at, last_login_at FROM users WHERE user_id LIKE ? ORDER BY created_at DESC LIMIT 50 OFFSET ?"
            : "SELECT id, user_id, is_admin, created_at, last_login_at FROM users ORDER BY created_at DESC LIMIT 50 OFFSET ?"
        ).bind(...(filter ? [filter + "%", page * 50] : [page * 50])).all();
        return json({ users: rows.results || [], total: Number(count?.count || 0), page, pageSize: 50 });
      }

      if (path === "/api/admin/users/delete" && method === "POST") {
        let body;
        try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
        const targetId = typeof body?.userId === "string" ? body.userId : "";
        const confirmation = typeof body?.confirmUserId === "string" ? body.confirmUserId.trim().toLowerCase() : "";
        if (!targetId || targetId.length > 64) return json({ error: "INVALID_USER" }, 400);
        const target = await env.DB.prepare("SELECT id, user_id, is_admin FROM users WHERE id=?").bind(targetId).first();
        if (!target) return json({ error: "USER_NOT_FOUND" }, 404);
        if (target.id === admin.id) return json({ error: "CANNOT_DELETE_SELF", message: "ログイン中の管理者自身は削除できません。" }, 403);
        if (Number(target.is_admin) === 1) return json({ error: "ADMIN_ACCOUNT_PROTECTED", message: "管理者アカウントの削除は管理者パスキー機能の実装後に行えます。" }, 403);
        if (confirmation !== target.user_id) return json({ error: "CONFIRMATION_MISMATCH", message: "確認用ユーザーIDが一致しません。" }, 400);

        const sessions = await env.DB.prepare("SELECT token_hash FROM sessions WHERE user_id=?").bind(target.id).all();
        const room = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("open-lounge"));
        await Promise.allSettled((sessions.results || []).map(({ token_hash }) =>
          room.fetch("https://chat-room.internal/revoke", {
            method: "POST",
            headers: { "X-Session-Hash": token_hash }
          })
        ));
        await writeAdminAudit(env, admin, "user.delete", target.id, { userId: target.user_id });
        await env.DB.prepare("DELETE FROM users WHERE id=? AND is_admin=0").bind(target.id).run();
        return json({ deleted: true, userId: target.user_id });
      }

      if (path === "/api/admin/announcements" && method === "GET") {
        const rows = await env.DB.prepare(
          "SELECT id, title, body, published, created_at, updated_at, published_at FROM announcements ORDER BY created_at DESC LIMIT 100"
        ).all();
        return json({ announcements: rows.results || [] });
      }

      if (path === "/api/admin/announcements" && method === "POST") {
        let body;
        try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
        const title = typeof body?.title === "string" ? body.title.trim() : "";
        const content = typeof body?.body === "string" ? body.body.trim() : "";
        const published = body?.published === true ? 1 : 0;
        if (!title || title.length > 100 || !content || content.length > 3000) {
          return json({ error: "INVALID_ANNOUNCEMENT", message: "タイトルは1〜100文字、本文は1〜3000文字で入力してください。" }, 400);
        }
        const now = Date.now(), id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO announcements (id, title, body, published, created_by_user_id, created_at, updated_at, published_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(id, title, content, published, admin.id, now, now, published ? now : null).run();
        await writeAdminAudit(env, admin, published ? "announcement.publish" : "announcement.create", id, { title });
        return json({ created: true, id }, 201);
      }

      const announcementMatch = path.match(/^\/api\/admin\/announcements\/([a-f0-9-]+)$/i);
      if (announcementMatch && method === "PUT") {
        let body;
        try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
        const title = typeof body?.title === "string" ? body.title.trim() : "";
        const content = typeof body?.body === "string" ? body.body.trim() : "";
        const published = body?.published === true ? 1 : 0;
        if (!title || title.length > 100 || !content || content.length > 3000) return json({ error: "INVALID_ANNOUNCEMENT" }, 400);
        const now = Date.now();
        const result = await env.DB.prepare(
          "UPDATE announcements SET title=?, body=?, published=?, updated_at=?, published_at=CASE WHEN ?=1 AND published_at IS NULL THEN ? WHEN ?=0 THEN NULL ELSE published_at END WHERE id=?"
        ).bind(title, content, published, now, published, now, published, announcementMatch[1]).run();
        if (!result.meta?.changes) return json({ error: "ANNOUNCEMENT_NOT_FOUND" }, 404);
        await writeAdminAudit(env, admin, published ? "announcement.update_publish" : "announcement.update", announcementMatch[1], { title });
        return json({ updated: true });
      }

      if (announcementMatch && method === "DELETE") {
        const result = await env.DB.prepare("DELETE FROM announcements WHERE id=?").bind(announcementMatch[1]).run();
        if (!result.meta?.changes) return json({ error: "ANNOUNCEMENT_NOT_FOUND" }, 404);
        await writeAdminAudit(env, admin, "announcement.delete", announcementMatch[1]);
        return json({ deleted: true });
      }

      if (path === "/api/admin/audit-logs" && method === "GET") {
        const rows = await env.DB.prepare(
          "SELECT l.id, l.action, l.target_user_id, l.details_json, l.created_at, u.user_id AS admin_user_id FROM admin_audit_logs l LEFT JOIN users u ON u.id=l.admin_user_id ORDER BY l.created_at DESC LIMIT 100"
        ).all();
        return json({ logs: rows.results || [] });
      }
      return json({ error: "NOT_FOUND" }, 404);
    } catch (error) {
      console.error("Admin API failed:");
      return json({ error: "ADMIN_OPERATION_FAILED", message: "管理操作を完了できませんでした。" }, 503);
    }
  }

  if (path === "/api/announcements" && method === "GET") {
    try {
      const rows = await env.DB.prepare(
        "SELECT id, title, body, published_at FROM announcements WHERE published=1 ORDER BY published_at DESC LIMIT 20"
      ).all();
      return json({ announcements: rows.results || [] });
    } catch {
      return json({ error: "ANNOUNCEMENTS_UNAVAILABLE" }, 503);
    }
  }

  if (path === "/api/health" && method === "GET") {
    try {
      await env.DB.prepare("SELECT 1").first();
      return json({
        status: "ok",
        database: "connected",
        authentication: true,
        clientSideEncryption: true,
        endToEndEncryption: false,
        messagePersistence: true,
        messageRetentionSeconds: 3600,
        contactVerification: "mutual-one-time-code",
        contactVerificationConfigured: typeof env.CONTACT_OTP_PEPPER === "string" && env.CONTACT_OTP_PEPPER.length >= 32,
        applicationDataEncryptionConfigured: typeof env.APP_DATA_ENCRYPTION_KEY === "string" && encoder.encode(env.APP_DATA_ENCRYPTION_KEY).byteLength >= 32,
        contactVerificationDiagnostic: {
          pepperPresent: typeof env.CONTACT_OTP_PEPPER !== "undefined",
          pepperIsString: typeof env.CONTACT_OTP_PEPPER === "string",
          pepperMeetsMinimumLength: typeof env.CONTACT_OTP_PEPPER === "string" && env.CONTACT_OTP_PEPPER.length >= 32
        },
        mode: "Client-encrypted private-chat prototype; public-key identity verification and forward secrecy are not implemented"
      });
    } catch {
      return json({ status: "unavailable", database: "unavailable" }, 503);
    }
  }

  if (path === "/api/auth/me" && method === "GET") {
    try {
      const session = await getSession(env, readCookie(request));
      return json(session
        ? { authenticated: true, user: { id: session.id, userId: session.user_id, isAdmin: Number(session.is_admin) === 1, mustChangePassword: Number(session.is_admin) === 1 && (!session.password_changed_at || Date.now() - Number(session.password_changed_at) >= ADMIN_PASSWORD_MAX_AGE_MS) } }
        : { authenticated: false, user: null });
    } catch {
      return json({ error: "AUTH_UNAVAILABLE", message: "認証サービスを利用できません。" }, 503);
    }
  }

  if (path === "/api/registration-invitations" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    if (!await checkRateLimit(env, request, "registration-invite", 3)) {
      return json({ error: "RATE_LIMITED", message: "招待コードの発行回数が多すぎます。時間をおいてください。" }, 429);
    }
    let session;
    try { session = await getSession(env, readCookie(request)); }
    catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    try {
      const active = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM registration_invites WHERE created_by_user_id=? AND used_at IS NULL AND expires_at>?"
      ).bind(session.id, Date.now()).first();
      if ((active?.count ?? 0) >= 5) {
        return json({ error: "INVITE_LIMIT_REACHED", message: "有効な招待コードは最大5件までです。使用または期限切れを待ってください。" }, 429);
      }
      const code = randomToken();
      const now = Date.now();
      const expiresAt = now + 24 * 60 * 60 * 1000;
      await env.DB.prepare(
        "INSERT INTO registration_invites (id, created_by_user_id, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(crypto.randomUUID(), session.id, await sha256(code), expiresAt, now).run();
      return json({ code, expiresAt }, 201);
    } catch (error) {
      console.error("Registration invitation failed:");
      return json({ error: "INVITATION_UNAVAILABLE", message: "招待コードを発行できませんでした。" }, 503);
    }
  }

  if (path === "/api/auth/register" && method === "POST") {
    if (!sameOrigin(request)) {
      return json({ error: "ORIGIN_REJECTED", message: "このリクエストは許可されていません。" }, 403);
    }
    if (!await checkRateLimit(env, request, "register", 4)) {
      return json({ error: "RATE_LIMITED", message: "試行回数が多すぎます。時間をおいて再試行してください。" }, 429);
    }

    let body;
    try { body = await readJson(request); }
    catch (error) {
      return json({ error: error.message, message: "リクエスト形式を確認してください。" }, 400);
    }

    const userId = normalizeUserId(body?.userId);
    const password = body?.password;
    const inviteCode = typeof body?.inviteCode === "string" ? body.inviteCode.trim() : "";
    if (!/^[A-Za-z0-9_-]{40,64}$/.test(inviteCode)) {
      return json({ error: "INVITE_CODE_REQUIRED", message: "有効な招待コードを入力してください。" }, 403);
    }
    if (!userId) {
      return json({ error: "INVALID_USER_ID", message: "ユーザーIDは半角英小文字・数字・アンダースコアで3〜32文字にしてください。" }, 400);
    }
    if (!validPassword(password)) {
      return json({ error: "INVALID_PASSWORD", message: "パスワードは12〜128文字で入力してください。" }, 400);
    }

    const inviteHash = await sha256(inviteCode);
    const validInvite = await env.DB.prepare(
      "SELECT 1 AS ok FROM registration_invites WHERE code_hash=? AND used_at IS NULL AND expires_at>? LIMIT 1"
    ).bind(inviteHash, Date.now()).first();
    if (!validInvite) {
      return json({ error: "INVITE_CODE_INVALID", message: "招待コードが無効・使用済み・期限切れです。" }, 403);
    }

    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const passwordHash = await derivePassword(password, salt);
      const userUuid = crypto.randomUUID();
      const now = Date.now();
      const registration = await env.DB.batch([
        env.DB.prepare(
          "UPDATE registration_invites SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at>? RETURNING id"
        ).bind(now, inviteHash, now),
        env.DB.prepare(
          "INSERT INTO users (id, user_id, password_salt, password_hash, password_iterations, created_at, password_changed_at) SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM registration_invites WHERE code_hash=? AND used_at=? AND expires_at>?)"
        ).bind(userUuid, userId, base64url(salt), base64url(passwordHash), PASSWORD_ITERATIONS, now, now, inviteHash, now, now)
      ]);
      if (!registration[0]?.results?.length || registration[1]?.meta?.changes !== 1) {
        return json({ error: "INVITE_CODE_INVALID", message: "招待コードが無効・使用済み・期限切れです。" }, 403);
      }

      const session = await createSession(env, userUuid);
      const response = json({
        authenticated: true,
        user: { id: userUuid, userId }
      }, 201);
      setSessionCookie(response, request, session.token);
      return response;
    } catch (error) {
      if (String(error.message).includes("UNIQUE")) {
        return json({ error: "USER_ID_TAKEN", message: "このユーザーIDは既に使用されています。" }, 409);
      }
      console.error("Account registration failed:");
      return json({ error: "REGISTRATION_UNAVAILABLE", message: "アカウントを作成できませんでした。時間をおいて再試行してください。" }, 503);
    }
  }

  if (path === "/api/auth/login" && method === "POST") {
    if (!sameOrigin(request)) {
      return json({ error: "ORIGIN_REJECTED", message: "このリクエストは許可されていません。" }, 403);
    }
    if (!await checkRateLimit(env, request, "login", 10)) {
      return json({ error: "RATE_LIMITED", message: "試行回数が多すぎます。時間をおいて再試行してください。" }, 429);
    }

    let body;
    try { body = await readJson(request); }
    catch (error) {
      return json({ error: error.message, message: "リクエスト形式を確認してください。" }, 400);
    }

    const userId = normalizeUserId(body?.userId);
    const password = body?.password;
    if (!userId || !validPassword(password)) {
      return json({ error: "INVALID_CREDENTIALS", message: "ユーザーIDまたはパスワードが正しくありません。" }, 401);
    }

    try {
      const user = await env.DB.prepare(
        "SELECT id, user_id, is_admin, password_changed_at, password_salt, password_hash, password_iterations FROM users WHERE user_id = ? LIMIT 1"
      ).bind(userId).first();

      const salt = user ? fromBase64url(user.password_salt) : encoder.encode("securechat-dummy-salt");
      const iterations = user?.password_iterations ?? PASSWORD_ITERATIONS;
      const derived = await derivePassword(password, salt, iterations);
      const expected = user ? fromBase64url(user.password_hash) : new Uint8Array(32);
      const matches = constantTimeEqual(derived, expected);

      if (!user || !matches) {
        return json({ error: "INVALID_CREDENTIALS", message: "ユーザーIDまたはパスワードが正しくありません。" }, 401);
      }

      const now = Date.now();
      await env.DB.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now, user.id).run();
      const session = await createSession(env, user.id);
      const response = json({
        authenticated: true,
        user: { id: user.id, userId: user.user_id, isAdmin: Number(user.is_admin) === 1, mustChangePassword: Number(user.is_admin) === 1 && (!user.password_changed_at || now - Number(user.password_changed_at) >= ADMIN_PASSWORD_MAX_AGE_MS) }
      });
      setSessionCookie(response, request, session.token);
      return response;
    } catch (error) {
      console.error("Login failed:");
      return json({ error: "LOGIN_UNAVAILABLE", message: "ログインできませんでした。時間をおいて再試行してください。" }, 503);
    }
  }

  if (path === "/api/auth/admin/change-password" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    if (typeof env.APP_DATA_ENCRYPTION_KEY !== "string" || encoder.encode(env.APP_DATA_ENCRYPTION_KEY).byteLength < 32) {
      return json({ error: "DATA_ENCRYPTION_NOT_CONFIGURED", message: "管理操作ログ用の暗号鍵が未設定です。管理者パスワードは変更されていません。" }, 503);
    }
    if (!await checkRateLimit(env, request, "admin-password-change", 5)) return json({ error: "RATE_LIMITED" }, 429);
    let session;
    try { session = await getSession(env, readCookie(request)); } catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    if (Number(session.is_admin) !== 1) return json({ error: "ADMIN_REQUIRED" }, 403);
    let body;
    try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
    const currentPassword = body?.currentPassword;
    const newPassword = body?.newPassword;
    if (!validPassword(currentPassword) || !validPassword(newPassword)) return json({ error: "INVALID_PASSWORD", message: "現在のパスワードと新しいパスワードはそれぞれ12〜128文字で入力してください。" }, 400);
    if (currentPassword === newPassword) return json({ error: "PASSWORD_UNCHANGED", message: "新しいパスワードは現在のものと異なるものにしてください。" }, 400);
    if (body?.identityBackup !== undefined && !validIdentityBackup(body.identityBackup)) {
      return json({ error: "IDENTITY_BACKUP_INVALID", message: "暗号鍵バックアップの形式が正しくありません。パスワードは変更されていません。" }, 400);
    }
    try {
      const user = await env.DB.prepare("SELECT password_salt, password_hash, password_iterations FROM users WHERE id=? AND is_admin=1").bind(session.id).first();
      if (!user) return json({ error: "ADMIN_REQUIRED" }, 403);
      const derived = await derivePassword(currentPassword, fromBase64url(user.password_salt), user.password_iterations);
      if (!constantTimeEqual(derived, fromBase64url(user.password_hash))) return json({ error: "INVALID_CREDENTIALS", message: "現在のパスワードが正しくありません。" }, 401);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const hash = await derivePassword(newPassword, salt);
      const now = Date.now();
      const oldSessions = await env.DB.prepare("SELECT token_hash FROM sessions WHERE user_id=?").bind(session.id).all();
      const room = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("open-lounge"));
      await Promise.allSettled((oldSessions.results || []).map(({token_hash}) => room.fetch("https://chat-room.internal/revoke", { method:"POST", headers:{"X-Session-Hash":token_hash} })));
      const statements = [
        env.DB.prepare("UPDATE users SET password_salt=?, password_hash=?, password_iterations=?, password_changed_at=? WHERE id=? AND is_admin=1").bind(base64url(salt), base64url(hash), PASSWORD_ITERATIONS, now, session.id),
        env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(session.id)
      ];
      if (body?.identityBackup) {
        statements.push(env.DB.prepare(
          "UPDATE user_keys SET identity_backup_version=1, identity_backup_salt=?, identity_backup_iv=?, identity_backup_ciphertext=?, updated_at=? WHERE user_id=?"
        ).bind(body.identityBackup.salt, body.identityBackup.iv, body.identityBackup.ciphertext, now, session.id));
      }
      await env.DB.batch(statements);
      const freshSession = await createSession(env, session.id);
      await writeAdminAudit(env, session, "admin.password.change", session.id, { changedAt: now, maxAgeDays: 90 });
      const response = json({ changed: true, user: { id: session.id, userId: session.user_id, isAdmin: true, mustChangePassword: false } });
      setSessionCookie(response, request, freshSession.token);
      return response;
    } catch (error) {
      console.error("Admin password change failed:");
      return json({ error: "PASSWORD_CHANGE_FAILED", message: "パスワードを変更できませんでした。" }, 503);
    }
  }

  if (path === "/api/auth/delete" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    if (!await checkRateLimit(env, request, "delete-account", 3)) {
      return json({ error: "RATE_LIMITED", message: "試行回数が多すぎます。時間をおいてください。" }, 429);
    }
    let session;
    try { session = await getSession(env, readCookie(request)); }
    catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    if (Number(session.is_admin) === 1) return json({ error: "ADMIN_ACCOUNT_PROTECTED", message: "管理者アカウントは通常のアカウント削除機能では削除できません。" }, 403);
    let body;
    try { body = await readJson(request); }
    catch (error) { return json({ error: error.message }, 400); }
    if (!validPassword(body?.password)) {
      return json({ error: "PASSWORD_REQUIRED", message: "確認のため、現在のパスワードを入力してください。" }, 400);
    }
    try {
      const user = await env.DB.prepare(
        "SELECT password_salt, password_hash, password_iterations FROM users WHERE id=?"
      ).bind(session.id).first();
      if (!user) return json({ error: "USER_NOT_FOUND" }, 404);
      const derived = await derivePassword(body.password, fromBase64url(user.password_salt), user.password_iterations);
      if (!constantTimeEqual(derived, fromBase64url(user.password_hash))) {
        return json({ error: "INVALID_CREDENTIALS", message: "パスワードが正しくありません。" }, 401);
      }
      const sessions = await env.DB.prepare("SELECT token_hash FROM sessions WHERE user_id=?").bind(session.id).all();
      const room = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("open-lounge"));
      await Promise.all((sessions.results || []).map(({ token_hash }) =>
        room.fetch("https://chat-room.internal/revoke", {
          method: "POST",
          headers: { "X-Session-Hash": token_hash }
        })
      ));
      await env.DB.prepare("DELETE FROM users WHERE id=?").bind(session.id).run();
      const response = json({ deleted: true });
      clearSessionCookie(response, request);
      return response;
    } catch (error) {
      console.error("Account deletion failed:");
      return json({ error: "DELETE_FAILED", message: "アカウントを削除できませんでした。" }, 503);
    }
  }

  if (path === "/api/auth/logout" && method === "POST") {
    if (!sameOrigin(request)) {
      return json({ error: "ORIGIN_REJECTED", message: "このリクエストは許可されていません。" }, 403);
    }
    try {
      const token = readCookie(request);
      if (token) {
        const tokenHash = await sha256(token);
        await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
        const id = env.CHAT_ROOM.idFromName("open-lounge");
        const stub = env.CHAT_ROOM.get(id);
        await stub.fetch("https://chat-room.internal/revoke", {
          method: "POST",
          headers: { "X-Session-Hash": tokenHash }
        });
      }
      const response = new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
      clearSessionCookie(response, request);
      return response;
    } catch {
      return json({ error: "LOGOUT_UNAVAILABLE", message: "ログアウトを完了できませんでした。" }, 503);
    }
  }


  // Authenticated private-chat API. Only ciphertext is accepted as message content.
  if (path.startsWith("/api/") && (path === "/api/users/search" || path === "/api/contacts" || path.startsWith("/api/contacts/") || path === "/api/contact-invitations" || path.startsWith("/api/contact-invitations/") || path === "/api/keys" || path.startsWith("/api/keys/") || path === "/api/conversations" || path.startsWith("/api/conversations/") || path.startsWith("/api/crypto/"))) {
    if (method !== "GET" && !sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    let session;
    try { session = await getSession(env, readCookie(request)); } catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    const me = session.id;
    const now = Date.now();

    if (path.startsWith("/api/crypto/")) {
      if (method !== "GET" && !await checkRateLimit(env, request, "crypto-v2-write", 60)) {
        return json({ error: "RATE_LIMITED", message: "暗号鍵操作の回数が多すぎます。時間をおいて再試行してください。" }, 429);
      }
      return handleCryptoApi(request, env, session, { url, now });
    }

    if (path === "/api/users/search" && method === "GET") {
      const q = (url.searchParams.get("q") || "").trim().toLowerCase();
      if (!/^[a-z0-9_]{1,32}$/.test(q)) return json({ users: [] });
      const rows = await env.DB.prepare("SELECT user_id FROM users WHERE user_id LIKE ? AND id <> ? ORDER BY user_id LIMIT 20").bind(q + "%", me).all();
      return json({ users: rows.results.map((r) => ({ userId: r.user_id })) });
    }
    if (path === "/api/contacts" && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT u.user_id FROM verified_contact_pairs p JOIN users u ON u.id=CASE WHEN p.user_a_id=? THEN p.user_b_id ELSE p.user_a_id END WHERE p.user_a_id=? OR p.user_b_id=? ORDER BY u.user_id"
      ).bind(me, me, me).all();
      return json({ contacts: rows.results.map((r) => ({ userId: r.user_id })) });
    }

    if (path === "/api/contact-invitations" && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT i.id, a.user_id AS inviter_user_id, b.user_id AS invitee_user_id, i.invitee_verified_at, i.inviter_verified_at, i.inviter_code_expires_at, i.invitee_code_expires_at, i.expires_at FROM contact_invitations i JOIN users a ON a.id=i.inviter_user_id JOIN users b ON b.id=i.invitee_user_id WHERE i.expires_at>? AND (i.inviter_user_id=? OR i.invitee_user_id=?) ORDER BY i.created_at DESC LIMIT 50"
      ).bind(now, me, me).all();
      return json({ invitations: rows.results });
    }

    if (path === "/api/contact-invitations" && method === "POST") {
      if (!await checkRateLimit(env, request, "contact-invite", 10)) return json({ error: "RATE_LIMITED", message: "招待の発行回数が多すぎます。時間をおいて再試行してください。" }, 429);
      let body;
      try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
      const userId = normalizeUserId(body?.userId);
      if (!userId) return json({ error: "INVALID_USER_ID" }, 400);
      const target = await env.DB.prepare("SELECT id FROM users WHERE user_id=?").bind(userId).first();
      if (!target) return json({ error: "USER_NOT_FOUND" }, 404);
      if (target.id === me) return json({ error: "SELF_CONTACT" }, 400);
      const [pairA, pairB] = orderedPair(me, target.id);
      const linked = await env.DB.prepare("SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?").bind(pairA, pairB).first();
      if (linked) return json({ error: "ALREADY_CONTACT" }, 409);
      const pending = await env.DB.prepare("SELECT id FROM contact_invitations WHERE expires_at>? AND ((inviter_user_id=? AND invitee_user_id=?) OR (inviter_user_id=? AND invitee_user_id=?)) LIMIT 1").bind(now, me, target.id, target.id, me).first();
      if (pending) return json({ error: "INVITATION_EXISTS" }, 409);
      const id = crypto.randomUUID(), code = createOtp();
      let digest;
      try { digest = await otpDigest(env, id, "inviter", code); }
      catch { return json({ error: "OTP_NOT_CONFIGURED", message: "OTP用サーバー秘密鍵が未設定です。" }, 503); }
      await env.DB.prepare("INSERT INTO contact_invitations (id, inviter_user_id, invitee_user_id, inviter_code_hash, inviter_code_expires_at, inviter_attempts, expires_at, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)").bind(id, me, target.id, digest, now + 300000, now + 86400000, now).run();
      return json({ invitationId: id, code, expiresAt: now + 300000 }, 201);
    }

    const invitationAccept = path.match(/^\/api\/contact-invitations\/([a-f0-9-]+)\/accept$/i);
    if (invitationAccept && method === "POST") {
      let body;
      try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
      const code = typeof body?.code === "string" ? body.code.trim() : "";
      if (!/^\d{8}$/.test(code)) return json({ error: "INVALID_OTP_FORMAT" }, 400);
      const inv = await env.DB.prepare("SELECT * FROM contact_invitations WHERE id=? AND invitee_user_id=?").bind(invitationAccept[1], me).first();
      if (!inv || inv.expires_at <= now) return json({ error: "INVITATION_NOT_FOUND" }, 404);
      if (inv.invitee_verified_at) return json({ error: "INVITATION_ALREADY_VERIFIED" }, 409);
      if (inv.inviter_attempts >= 5) return json({ error: "OTP_ATTEMPTS_EXCEEDED" }, 429);
      if (!inv.inviter_code_hash || inv.inviter_code_expires_at <= now) return json({ error: "OTP_EXPIRED" }, 410);
      let digest;
      try { digest = await otpDigest(env, inv.id, "inviter", code); } catch { return json({ error: "OTP_NOT_CONFIGURED" }, 503); }
      if (!constantTimeEqual(encoder.encode(digest), encoder.encode(inv.inviter_code_hash))) {
        await env.DB.prepare("UPDATE contact_invitations SET inviter_attempts=inviter_attempts+1 WHERE id=? AND inviter_attempts<5").bind(inv.id).run();
        return json({ error: "OTP_INVALID" }, 400);
      }
      await env.DB.prepare("UPDATE contact_invitations SET invitee_verified_at=?, inviter_code_hash=NULL, expires_at=? WHERE id=? AND invitee_user_id=?").bind(now, now + 86400000, inv.id, me).run();
      return json({ accepted: true, invitationId: inv.id });
    }

    const responseCodeMatch = path.match(/^\/api\/contact-invitations\/([a-f0-9-]+)\/response-code$/i);
    if (responseCodeMatch && method === "POST") {
      const inv = await env.DB.prepare("SELECT * FROM contact_invitations WHERE id=? AND invitee_user_id=?").bind(responseCodeMatch[1], me).first();
      if (!inv || inv.expires_at <= now) return json({ error: "INVITATION_NOT_FOUND" }, 404);
      if (!inv.invitee_verified_at) return json({ error: "INVITATION_NOT_ACCEPTED" }, 403);
      if (inv.inviter_verified_at) return json({ error: "INVITATION_COMPLETE" }, 409);
      let code, digest;
      try { code = createOtp(); digest = await otpDigest(env, inv.id, "invitee", code); }
      catch { return json({ error: "OTP_NOT_CONFIGURED" }, 503); }
      await env.DB.prepare("UPDATE contact_invitations SET invitee_code_hash=?, invitee_code_expires_at=?, invitee_attempts=0, expires_at=? WHERE id=? AND invitee_user_id=?").bind(digest, now + 300000, now + 86400000, inv.id, me).run();
      return json({ code, expiresAt: now + 300000 });
    }

    const invitationConfirm = path.match(/^\/api\/contact-invitations\/([a-f0-9-]+)\/confirm$/i);
    if (invitationConfirm && method === "POST") {
      let body;
      try { body = await readJson(request); } catch (error) { return json({ error: error.message }, 400); }
      const code = typeof body?.code === "string" ? body.code.trim() : "";
      if (!/^\d{8}$/.test(code)) return json({ error: "INVALID_OTP_FORMAT" }, 400);
      const inv = await env.DB.prepare("SELECT * FROM contact_invitations WHERE id=? AND inviter_user_id=?").bind(invitationConfirm[1], me).first();
      if (!inv || inv.expires_at <= now) return json({ error: "INVITATION_NOT_FOUND" }, 404);
      if (!inv.invitee_verified_at) return json({ error: "INVITATION_NOT_ACCEPTED" }, 403);
      if (inv.invitee_attempts >= 5) return json({ error: "OTP_ATTEMPTS_EXCEEDED" }, 429);
      if (!inv.invitee_code_hash || inv.invitee_code_expires_at <= now) return json({ error: "OTP_EXPIRED" }, 410);
      let digest;
      try { digest = await otpDigest(env, inv.id, "invitee", code); } catch { return json({ error: "OTP_NOT_CONFIGURED" }, 503); }
      if (!constantTimeEqual(encoder.encode(digest), encoder.encode(inv.invitee_code_hash))) {
        await env.DB.prepare("UPDATE contact_invitations SET invitee_attempts=invitee_attempts+1 WHERE id=? AND invitee_attempts<5").bind(inv.id).run();
        return json({ error: "OTP_INVALID" }, 400);
      }
      const [pairA, pairB] = orderedPair(inv.inviter_user_id, inv.invitee_user_id);
      const oldConversations = await env.DB.prepare("SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=? JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=?").bind(inv.inviter_user_id, inv.invitee_user_id).all();
      await env.DB.batch([
        env.DB.prepare("INSERT OR IGNORE INTO contacts (owner_user_id, contact_user_id, created_at) VALUES (?, ?, ?)").bind(inv.inviter_user_id, inv.invitee_user_id, now),
        env.DB.prepare("INSERT OR IGNORE INTO contacts (owner_user_id, contact_user_id, created_at) VALUES (?, ?, ?)").bind(inv.invitee_user_id, inv.inviter_user_id, now),
        env.DB.prepare("INSERT OR REPLACE INTO verified_contact_pairs (user_a_id, user_b_id, verified_at) VALUES (?, ?, ?)").bind(pairA, pairB, now),
        ...oldConversations.results.map(row => env.DB.prepare("DELETE FROM conversations WHERE id=?").bind(row.id)),
        env.DB.prepare("DELETE FROM contact_invitations WHERE id=?").bind(inv.id)
      ]);
      const peer = await env.DB.prepare("SELECT user_id FROM users WHERE id=?").bind(inv.invitee_user_id).first();
      return json({ verified: true, userId: peer?.user_id || "" });
    }

    const reissueMatch = path.match(/^\/api\/contact-invitations\/([a-f0-9-]+)\/reissue$/i);
    if (reissueMatch && method === "POST") {
      const inv = await env.DB.prepare("SELECT * FROM contact_invitations WHERE id=? AND inviter_user_id=?").bind(reissueMatch[1], me).first();
      if (!inv || inv.expires_at <= now) return json({ error: "INVITATION_NOT_FOUND" }, 404);
      if (inv.invitee_verified_at) return json({ error: "INVITATION_ALREADY_ACCEPTED" }, 409);
      let code, digest;
      try { code = createOtp(); digest = await otpDigest(env, inv.id, "inviter", code); }
      catch { return json({ error: "OTP_NOT_CONFIGURED" }, 503); }
      await env.DB.prepare("UPDATE contact_invitations SET inviter_code_hash=?, inviter_code_expires_at=?, inviter_attempts=0 WHERE id=?").bind(digest, now + 300000, inv.id).run();
      return json({ code, expiresAt: now + 300000 });
    }
    const removeContactMatch = path.match(new RegExp("^/api/contacts/([a-z0-9_]{3,32})$"));
    if (removeContactMatch && method === "DELETE") {
      const userId = normalizeUserId(removeContactMatch[1]);
      const target = await env.DB.prepare("SELECT id FROM users WHERE user_id=?").bind(userId).first();
      if (!target) return json({ error: "USER_NOT_FOUND" }, 404);
      const [pairA, pairB] = orderedPair(me, target.id);
      const exists = await env.DB.prepare("SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?").bind(pairA, pairB).first();
      if (!exists) return json({ error: "CONTACT_NOT_FOUND" }, 404);
      const rows = await env.DB.prepare("SELECT id FROM conversations WHERE id IN (SELECT a.conversation_id FROM conversation_members a JOIN conversation_members b ON b.conversation_id=a.conversation_id WHERE a.user_id=? AND b.user_id=?)").bind(me, target.id).all();
      const statements = [
        env.DB.prepare("DELETE FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?").bind(pairA, pairB),
        env.DB.prepare("DELETE FROM contacts WHERE owner_user_id=? AND contact_user_id=?").bind(me, target.id),
        env.DB.prepare("DELETE FROM contacts WHERE owner_user_id=? AND contact_user_id=?").bind(target.id, me),
        env.DB.prepare("DELETE FROM contact_invitations WHERE (inviter_user_id=? AND invitee_user_id=?) OR (inviter_user_id=? AND invitee_user_id=?)").bind(me, target.id, target.id, me),
        ...rows.results.map((row) => env.DB.prepare("DELETE FROM conversations WHERE id=?").bind(row.id))
      ];
      await env.DB.batch(statements);
      return json({ removed: true, userId, conversationsRemoved: rows.results.length });
    }
    if (path === "/api/keys/backup" && method === "GET") {
      const key = await env.DB.prepare(
        "SELECT identity_public_key, identity_signing_public_key, identity_key_signature, identity_transition_from, identity_transition_signature, identity_backup_version, identity_backup_salt, identity_backup_iv, identity_backup_ciphertext FROM user_keys WHERE user_id=?"
      ).bind(me).first();
      if (!key) return json({ identityRegistered: false, backupAvailable: false, identityMode: "unregistered" });
      const backupAvailable = Number(key.identity_backup_version) === 1 &&
        !!key.identity_backup_salt && !!key.identity_backup_iv && !!key.identity_backup_ciphertext;
      return json({
        identityRegistered: true,
        backupAvailable,
        identityMode: backupAvailable ? "portable" : Number(key.identity_backup_version) === 2 ? "legacy-local-only" : "setup-required",
        identityPublicKey: key.identity_public_key,
        identitySigningPublicKey: key.identity_signing_public_key,
        identityKeySignature: key.identity_key_signature,
        ...(backupAvailable ? {
          backup: {
            version: 1,
            salt: key.identity_backup_salt,
            iv: key.identity_backup_iv,
            ciphertext: key.identity_backup_ciphertext
          }
        } : {})
      });
    }
    if (path === "/api/keys/legacy-challenge" && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
      if (!await checkRateLimit(env, request, "legacy-identity-challenge", 5)) {
        return json({ error: "RATE_LIMITED" }, 429);
      }
      const legacyKey = await env.DB.prepare(
        "SELECT identity_public_key, identity_signing_public_key, identity_backup_version FROM user_keys WHERE user_id=?"
      ).bind(me).first();
      if (!legacyKey || legacyKey.identity_signing_public_key ||
          Number(legacyKey.identity_backup_version || 0) !== 0) {
        return json({ error: "IDENTITY_LEGACY_UPGRADE_NOT_AVAILABLE" }, 409);
      }
      let pair, privateJwk, serverPublicKey;
      try {
        pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
        privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
        serverPublicKey = base64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
      } catch {
        return json({ error: "IDENTITY_LEGACY_CHALLENGE_FAILED" }, 503);
      }
      const challengeId = randomToken();
      const challenge = randomToken();
      const expiresAt = Date.now() + 5 * 60 * 1000;
      const room = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("open-lounge"));
      const stored = await room.fetch("https://chat-room.internal/identity-legacy/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: session.user_id,
          challengeId,
          identityPublicKey: legacyKey.identity_public_key,
          serverPrivateJwk: privateJwk,
          challenge,
          expiresAt
        })
      });
      if (!stored.ok) return json({ error: "IDENTITY_LEGACY_CHALLENGE_FAILED" }, 503);
      return json({
        challengeId,
        challenge,
        identityPublicKey: legacyKey.identity_public_key,
        serverPublicKey,
        expiresAt
      });
    }

    if (path === "/api/keys" && method === "PUT") {
      let body;
      try { body = await readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
      const pub = body?.identityPublicKey, signingPub = body?.identitySigningPublicKey, signature = body?.identityKeySignature;
      if (typeof pub !== "string" || pub.length < 80 || pub.length > 128 ||
          typeof signingPub !== "string" || signingPub.length < 80 || signingPub.length > 128 ||
          typeof signature !== "string" || signature.length < 80 || signature.length > 128) {
        return json({ error: "IDENTITY_KEY_PROOF_REQUIRED", message: "署名付き公開鍵が必要です。アプリを更新して再ログインしてください。" }, 400);
      }
      const validProof = await verifyIdentityKeyProof({
        userId: session.user_id,
        identityPublicKey: pub,
        identitySigningPublicKey: signingPub,
        identityKeySignature: signature
      });
      if (!validProof) return json({ error: "IDENTITY_KEY_PROOF_INVALID" }, 400);

      const existingKey = await env.DB.prepare(
        "SELECT identity_public_key, identity_signing_public_key, identity_key_signature, identity_backup_version FROM user_keys WHERE user_id=?"
      ).bind(me).first();

      // A pre-signed-key account may attach a signer to its existing ECDH key
      // once, but only without changing that ECDH key. Version 2 marks this
      // legacy identity as local-device-only and prevents later silent rotation.
      if ((body?.identityBackup === undefined || body?.identityBackup === null) &&
          body?.legacyUpgrade && typeof body.legacyUpgrade === "object" &&
          existingKey &&
          existingKey.identity_public_key === pub &&
          !existingKey.identity_signing_public_key &&
          Number(existingKey.identity_backup_version || 0) === 0) {
        const challengeId = body.legacyUpgrade.challengeId;
        const proof = body.legacyUpgrade.proof;
        if (typeof challengeId !== "string" || challengeId.length < 32 || challengeId.length > 64 ||
            typeof proof !== "string" || proof.length < 40 || proof.length > 128) {
          return json({ error: "IDENTITY_LEGACY_PROOF_REQUIRED" }, 400);
        }
        const room = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("open-lounge"));
        const verification = await room.fetch("https://chat-room.internal/identity-legacy/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId: session.user_id, challengeId, identityPublicKey: pub, proof })
        });
        const verified = await verification.json().catch(() => ({}));
        if (!verification.ok || verified.valid !== true) {
          return json({ error: "IDENTITY_LEGACY_PROOF_INVALID", message: "元の暗号鍵を確認できませんでした。元の端末で再試行してください。" }, 403);
        }
        const upgrade = await env.DB.prepare(
          "UPDATE user_keys SET identity_signing_public_key=?, identity_key_signature=?, identity_backup_version=2, key_version=key_version+1, updated_at=? WHERE user_id=? AND identity_public_key=? AND (identity_signing_public_key IS NULL OR identity_signing_public_key='') AND identity_backup_version=0"
        ).bind(signingPub, signature, now, me, pub).run();
        if (Number(upgrade.meta?.changes || 0) === 1) {
          return json({ saved: true, legacyLocalOnly: true, backupAvailable: false });
        }
        return json({
          error: "IDENTITY_KEY_CONFLICT",
          message: "別端末で旧形式の鍵移行が完了しました。ページを再読み込みしてください。"
        }, 409);
      }

      // Older cached clients may only reuse the exact identity already stored.
      // Legacy-local-only records may not be rotated without a portable backup.
      if (body?.identityBackup === undefined || body?.identityBackup === null) {
        if (existingKey &&
            existingKey.identity_public_key === pub &&
            existingKey.identity_signing_public_key === signingPub) {
          return json({ saved: true, backupUnchanged: true, legacyLocalOnly: Number(existingKey.identity_backup_version) === 2 });
        }
        return json({
          error: Number(existingKey?.identity_backup_version) === 2 ? "IDENTITY_LEGACY_KEY_LOCKED" : "IDENTITY_BACKUP_REQUIRED",
          message: Number(existingKey?.identity_backup_version) === 2
            ? "この旧形式の暗号鍵は元の端末内だけに保存されています。鍵の安全な復旧手段がないため、自動変更を禁止しています。元の端末と保存データを保持してください。"
            : "この端末のアプリが古い可能性があります。ページを再読み込みしてください。新しい端末での鍵登録には暗号化バックアップが必要です。"
        }, 400);
      }
      if (!validIdentityBackup(body.identityBackup)) {
        return json({
          error: "IDENTITY_BACKUP_INVALID",
          message: "暗号化バックアップの形式が正しくありません。ページを再読み込みして再度ログインしてください。"
        }, 400);
      }

      if (existingKey && Number(existingKey.identity_backup_version) === 2 &&
          (existingKey.identity_public_key !== pub || existingKey.identity_signing_public_key !== signingPub)) {
        return json({ error: "IDENTITY_LEGACY_KEY_LOCKED", message: "この旧形式の暗号鍵は元の端末内だけに保存されています。自動鍵変更はできません。元の端末と保存データを保持してください。" }, 409);
      }

      let transitionFrom = null, transitionSignature = null;
      if (existingKey) {
        const sameIdentity = existingKey.identity_public_key === pub &&
          existingKey.identity_signing_public_key === signingPub;
        if (!sameIdentity) {
          transitionFrom = body?.previousIdentitySigningPublicKey;
          transitionSignature = body?.identityTransitionSignature;
          if (typeof transitionFrom !== "string" ||
              transitionFrom !== existingKey.identity_signing_public_key ||
              typeof transitionSignature !== "string" ||
              !await verifyIdentityKeyTransition({
                userId: session.user_id,
                previousSigningPublicKey: transitionFrom,
                identityPublicKey: pub,
                identitySigningPublicKey: signingPub,
                identityTransitionSignature: transitionSignature
              })) {
            return json({
              error: "IDENTITY_KEY_CONFLICT",
              message: "このアカウントには別端末の暗号鍵が登録されています。元の端末で再ログインして同期バックアップを作成してください。"
            }, 409);
          }
        }
      }

      if (!existingKey) {
        try {
          await env.DB.prepare(
            "INSERT INTO user_keys (user_id, identity_public_key, signed_prekey, signed_prekey_signature, identity_signing_public_key, identity_key_signature, identity_transition_from, identity_transition_signature, identity_backup_version, identity_backup_salt, identity_backup_iv, identity_backup_ciphertext, key_version, updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 1, ?, ?, ?, 1, ?)"
          ).bind(me, pub, pub, "legacy-placeholder-not-used", signingPub, signature,
            body.identityBackup.salt, body.identityBackup.iv, body.identityBackup.ciphertext, now).run();
        } catch (error) {
          if (String(error?.message || error).includes("UNIQUE")) {
            return json({ error: "IDENTITY_KEY_CONFLICT", message: "別端末で暗号鍵の初期設定が完了しました。もう一度ログインしてください。" }, 409);
          }
          throw error;
        }
      } else {
        const update = await env.DB.prepare(
          "UPDATE user_keys SET identity_public_key=?, signed_prekey=?, signed_prekey_signature=?, identity_signing_public_key=?, identity_key_signature=?, identity_transition_from=COALESCE(?, identity_transition_from), identity_transition_signature=COALESCE(?, identity_transition_signature), identity_backup_version=1, identity_backup_salt=?, identity_backup_iv=?, identity_backup_ciphertext=?, key_version=key_version+1, updated_at=? WHERE user_id=? AND identity_signing_public_key=?"
        ).bind(pub, pub, "legacy-placeholder-not-used", signingPub, signature,
          transitionFrom, transitionSignature, body.identityBackup.salt, body.identityBackup.iv,
          body.identityBackup.ciphertext, now, me, existingKey.identity_signing_public_key).run();
        if (Number(update.meta?.changes || 0) !== 1) {
          return json({ error: "IDENTITY_KEY_CONFLICT", message: "別端末で暗号鍵の更新が完了しました。もう一度ログインしてください。" }, 409);
        }
      }
      return json({ saved: true, transition: !!transitionFrom });
    }
    if (path.startsWith("/api/keys/") && method === "GET") {
      const userId = normalizeUserId(decodeURIComponent(path.slice("/api/keys/".length)));
      if (!userId) return json({ error: "INVALID_USER_ID" }, 400);
      const key = await env.DB.prepare(
        "SELECT k.identity_public_key, k.identity_signing_public_key, k.identity_key_signature, k.identity_transition_from, k.identity_transition_signature, k.key_version FROM user_keys k JOIN users u ON u.id=k.user_id WHERE u.user_id=?"
      ).bind(userId).first();
      return key ? json({
        userId,
        identityPublicKey: key.identity_public_key,
        identitySigningPublicKey: key.identity_signing_public_key,
        identityKeySignature: key.identity_key_signature,
        previousIdentitySigningPublicKey: key.identity_transition_from,
        identityTransitionSignature: key.identity_transition_signature,
        keyVersion: Number(key.key_version)
      }) : json({ error: "KEY_NOT_FOUND" }, 404);
    }
    if (path === "/api/conversations" && method === "POST") {
      const body = await readJson(request);
      const peerId = normalizeUserId(body?.recipientUserId);
      if (!peerId) return json({ error: "INVALID_CONVERSATION" }, 400);
      const peer = await env.DB.prepare("SELECT id FROM users WHERE user_id=?").bind(peerId).first();
      if (!peer) return json({ error: "USER_NOT_FOUND" }, 404);
      if (peer.id === me) return json({ error: "SELF_CONVERSATION" }, 400);
      const [pairA, pairB] = orderedPair(me, peer.id);
      const mutualContacts = await env.DB.prepare("SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?").bind(pairA, pairB).first();
      if (!mutualContacts) return json({ error: "MUTUAL_OTP_REQUIRED", message: "双方のワンタイムコード確認が完了した相手とだけチャットできます。" }, 403);
      const peerKey = await env.DB.prepare("SELECT user_id FROM user_keys WHERE user_id=?").bind(peer.id).first();
      if (!peerKey) return json({ error: "RECIPIENT_KEY_MISSING" }, 409);

      // The pair table is the database-level uniqueness gate. The batch is atomic:
      // concurrent requests may stage candidates, but only one pair mapping survives.
      const existing = await env.DB.prepare(
        "SELECT conversation_id FROM conversation_pairs WHERE user_a_id=? AND user_b_id=?"
      ).bind(pairA, pairB).first();
      if (existing) return json({ conversationId: existing.conversation_id, existing: true });

      const id = crypto.randomUUID();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO conversations (id, created_by, created_at, expires_in_seconds) VALUES (?, ?, ?, 3600)").bind(id, me, now),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)").bind(id, me, now),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)").bind(id, peer.id, now),
        env.DB.prepare("INSERT OR IGNORE INTO conversation_pairs (user_a_id, user_b_id, conversation_id, created_at) VALUES (?, ?, ?, ?)").bind(pairA, pairB, id, now),
        env.DB.prepare("DELETE FROM conversations WHERE id=? AND NOT EXISTS (SELECT 1 FROM conversation_pairs WHERE user_a_id=? AND user_b_id=? AND conversation_id=?)").bind(id, pairA, pairB, id)
      ]);
      const canonical = await env.DB.prepare(
        "SELECT conversation_id FROM conversation_pairs WHERE user_a_id=? AND user_b_id=?"
      ).bind(pairA, pairB).first();
      if (!canonical) return json({ error: "CONVERSATION_CREATE_FAILED" }, 503);
      const created = canonical.conversation_id === id;
      return json({ conversationId: canonical.conversation_id, existing: !created }, created ? 201 : 200);
    }
    if (path === "/api/conversations" && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT c.id, u.user_id AS peer_user_id, c.created_at, (SELECT COUNT(*) FROM encrypted_messages em LEFT JOIN conversation_reads cr ON cr.conversation_id=em.conversation_id AND cr.user_id=? WHERE em.conversation_id=c.id AND em.sender_user_id<>? AND em.expires_at>? AND (cr.last_read_at IS NULL OR em.created_at>cr.last_read_at OR (em.created_at=cr.last_read_at AND em.id>COALESCE(cr.last_read_message_id,'')))) AS unread_count FROM conversations c JOIN conversation_pairs cp ON cp.conversation_id=c.id JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? JOIN conversation_members peer ON peer.conversation_id=c.id AND peer.user_id<>? JOIN users u ON u.id=peer.user_id JOIN verified_contact_pairs p ON p.user_a_id=CASE WHEN mine.user_id<peer.user_id THEN mine.user_id ELSE peer.user_id END AND p.user_b_id=CASE WHEN mine.user_id<peer.user_id THEN peer.user_id ELSE mine.user_id END ORDER BY c.created_at DESC"
      ).bind(me, me, now, me, me).all();
      return json({ conversations: (rows.results || []).map(row => ({ ...row, unread_count: Number(row.unread_count || 0) })) });
    }
    const match = path.match(/^\/api\/conversations\/([a-f0-9-]+)(?:\/(messages|key))?$/i);
    if (match) {
      const id = match[1], sub = match[2] || "";
      const member = await env.DB.prepare("SELECT 1 AS ok FROM conversation_members WHERE conversation_id=? AND user_id=?").bind(id, me).first();
      if (!member) return json({ error: "CONVERSATION_NOT_FOUND" }, 404);
      const peerMember = await env.DB.prepare("SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>? LIMIT 1").bind(id, me).first();
      if (!peerMember) return json({ error: "CONVERSATION_NOT_FOUND" }, 404);
      const [pairA, pairB] = orderedPair(me, peerMember.user_id);
      const mutualContacts = await env.DB.prepare("SELECT 1 AS ok FROM verified_contact_pairs WHERE user_a_id=? AND user_b_id=?").bind(pairA, pairB).first();
      if (!mutualContacts) return json({ error: "CONTACT_PERMISSION_REQUIRED", message: "このユーザーとのOTP確認が解除されています。" }, 403);
      if (sub === "key" && method === "GET") {
        const row = await env.DB.prepare("SELECT key_envelope FROM conversation_keys WHERE conversation_id=? AND user_id=?").bind(id, me).first();
        return row ? json({ keyEnvelope: row.key_envelope }) : json({ error: "KEY_ENVELOPE_NOT_FOUND" }, 404);
      }
      if (sub === "messages" && method === "GET") {
        await env.DB.prepare("DELETE FROM encrypted_messages WHERE conversation_id=? AND expires_at<=?").bind(id, now).run();
        const afterValue = url.searchParams.get("after");
        let rows;
        if (afterValue !== null) {
          const after = Number(afterValue);
          const afterId = url.searchParams.get("afterId") || "";
          if (!Number.isSafeInteger(after) || after < 0 || afterId.length > 64) return json({ error: "INVALID_CURSOR" }, 400);
          rows = await env.DB.prepare("SELECT id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at, protocol_version, sender_device_id FROM encrypted_messages WHERE conversation_id=? AND expires_at>? AND (created_at>? OR (created_at=? AND id>?)) ORDER BY created_at, id LIMIT 500").bind(id, now, after, after, afterId).all();
        } else {
          rows = await env.DB.prepare("SELECT id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at, protocol_version, sender_device_id FROM encrypted_messages WHERE conversation_id=? AND expires_at>? ORDER BY created_at, id LIMIT 500").bind(id, now).all();
        }
        const messages = rows.results || [];
        const lastRead = messages[messages.length - 1];
        if (lastRead) {
          await env.DB.prepare(
            "INSERT INTO conversation_reads (conversation_id, user_id, last_read_at, last_read_message_id, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(conversation_id, user_id) DO UPDATE SET last_read_at=excluded.last_read_at, last_read_message_id=excluded.last_read_message_id, updated_at=excluded.updated_at WHERE excluded.last_read_at>conversation_reads.last_read_at OR (excluded.last_read_at=conversation_reads.last_read_at AND excluded.last_read_message_id>conversation_reads.last_read_message_id)"
          ).bind(id, me, Number(lastRead.created_at), lastRead.id, now).run();
        }
        return json({ messages });
      }
      if (sub === "messages" && method === "POST") {
        const protocolMode = await env.DB.prepare(
          "SELECT protocol_version FROM conversation_crypto_modes WHERE conversation_id=?"
        ).bind(id).first();
        if (Number(protocolMode?.protocol_version || 1) !== 1) {
          return json({ error: "CRYPTO_PROTOCOL_V2_REQUIRED", message: "この会話は前方秘匿性v2へ移行済みです。最新版を再読み込みしてください。" }, 426);
        }
        let body;
        try { body = await readJson(request); }
        catch (error) { return json({ error: error.message }, 400); }
        if (typeof body?.ciphertext !== "string" ||
            body.ciphertext.length < 24 || body.ciphertext.length > 12000 ||
            !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body.ciphertext) ||
            typeof body?.nonce !== "string" ||
            body.algorithm !== "AES-GCM-256") {
          return json({ error: "CIPHERTEXT_REQUIRED" }, 400);
        }
        let cipherBytes, nonceBytes;
        try {
          cipherBytes = Uint8Array.from(atob(body.ciphertext), (char) => char.charCodeAt(0));
          nonceBytes = Uint8Array.from(atob(body.nonce), (char) => char.charCodeAt(0));
        } catch {
          return json({ error: "INVALID_CIPHERTEXT_ENCODING" }, 400);
        }
        if (cipherBytes.length < 16 || cipherBytes.length > 9000 || nonceBytes.length !== 12) {
          return json({ error: "INVALID_CIPHERTEXT_SIZE" }, 400);
        }
        const msgId = crypto.randomUUID(), expires = now + 3600000;
        const inserted = await env.DB.prepare(
          "INSERT INTO encrypted_messages (id, conversation_id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at, protocol_version, sender_device_id) SELECT ?, ?, ?, ?, ?, 'AES-GCM-256', ?, ?, 1, NULL WHERE NOT EXISTS (SELECT 1 FROM conversation_crypto_modes WHERE conversation_id=? AND protocol_version=2)"
        ).bind(msgId, id, me, body.ciphertext, body.nonce, now, expires, id).run();
        if (Number(inserted.meta?.changes || 0) !== 1) {
          return json({ error: "CRYPTO_PROTOCOL_V2_REQUIRED", message: "この会話は前方秘匿性v2へ移行済みです。最新版を再読み込みしてください。" }, 426);
        }
        return json({ id: msgId, createdAt: now, expiresAt: expires, protocolVersion: 1 }, 201);
      }
    }
  }

  return json({ error: "NOT_FOUND", path }, 404);
}

export default {
  async scheduled(controller, env, ctx) {
    const now = Date.now();
    ctx.waitUntil(Promise.all([
      env.DB.prepare("DELETE FROM encrypted_messages WHERE expires_at <= ?").bind(now).run(),
      env.DB.prepare("DELETE FROM contact_invitations WHERE expires_at <= ?").bind(now).run(),
      env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run(),
      env.DB.prepare("DELETE FROM registration_invites WHERE expires_at <= ? OR (used_at IS NOT NULL AND used_at <= ?)").bind(now, now - 7 * 24 * 60 * 60 * 1000).run(),
      env.DB.prepare("DELETE FROM rate_limit_buckets WHERE expires_at <= ?").bind(now).run(),
      migrateSensitiveRows(env, now),
      runSecureDropMaintenance(env, now)
    ]));
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol === "http:") {
      url.protocol = "https:";
      return securityHeaders(Response.redirect(url.toString(), 308), request);
    }

    if (url.pathname === "/ws") {
      return securityHeaders(
        json({ error: "WEBSOCKET_DISABLED", message: "この旧式WebSocket経路は無効です。" }, 404),
        request
      );
    }

    if (url.pathname.startsWith("/api/")) {
      const response = await handleApi(request, env);
      return securityHeaders(response, request);
    }

    if (url.pathname === "/") {
      const indexUrl = new URL("/index.html", url);
      return securityHeaders(await env.ASSETS.fetch(new Request(indexUrl, request)), request);
    }

    if (url.pathname === "/admin" || url.pathname === "/admin/" || url.pathname === "/admin.html") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return securityHeaders(json({ error: "METHOD_NOT_ALLOWED" }, 405), request);
      }
      let adminSession;
      try {
        adminSession = await getSession(env, readCookie(request));
      } catch {
        return securityHeaders(json({ error: "AUTH_UNAVAILABLE", message: "管理者認証を確認できません。" }, 503), request);
      }
      if (!adminSession) {
        return securityHeaders(json({ error: "UNAUTHENTICATED", message: "ログイン後に管理者コンソールへアクセスしてください。" }, 401), request);
      }
      if (Number(adminSession.is_admin) !== 1) {
        return securityHeaders(json({ error: "ADMIN_REQUIRED", message: "このアカウントには管理者権限がありません。" }, 403), request);
      }
      if (!adminSession.password_changed_at ||
          Date.now() - Number(adminSession.password_changed_at) >= ADMIN_PASSWORD_MAX_AGE_MS) {
        return securityHeaders(json({ error: "PASSWORD_CHANGE_REQUIRED", message: "管理者パスワードを変更してからアクセスしてください。" }, 428), request);
      }
      if (Date.now() - Number(adminSession.created_at) > AUTH_WINDOW_MS) {
        return securityHeaders(json({ error: "ADMIN_REAUTH_REQUIRED", message: "管理者コンソールを開くには、ログアウトして再ログインしてください。" }, 428), request);
      }
      const adminUrl = new URL("/admin.html", url);
      const assetResponse = await env.ASSETS.fetch(new Request(adminUrl, request));
      const headers = new Headers(assetResponse.headers);
      headers.set("Cache-Control", "no-store");
      headers.set("Pragma", "no-cache");
      return securityHeaders(new Response(assetResponse.body, {
        status: assetResponse.status,
        statusText: assetResponse.statusText,
        headers
      }), request);
    }

    if (url.pathname === "/bug-report" || url.pathname === "/bug-report/") {
      const reportUrl = new URL("/bug-report.html", url);
      return securityHeaders(await env.ASSETS.fetch(new Request(reportUrl, request)), request);
    }

    const assetResponse = await env.ASSETS.fetch(request);
    return securityHeaders(assetResponse, request);
  }
};

export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/identity-legacy/challenge" && request.method === "POST") {
      let body;
      try { body = await readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
      if (typeof body?.userId !== "string" || !/^[a-z0-9_]{3,32}$/.test(body.userId) ||
          typeof body.challengeId !== "string" || body.challengeId.length < 32 || body.challengeId.length > 64 ||
          typeof body.identityPublicKey !== "string" || body.identityPublicKey.length < 80 || body.identityPublicKey.length > 128 ||
          !body.serverPrivateJwk || typeof body.serverPrivateJwk.d !== "string" ||
          typeof body.challenge !== "string" || body.challenge.length < 32 || body.challenge.length > 64 ||
          !Number.isSafeInteger(body.expiresAt) || body.expiresAt <= Date.now() ||
          body.expiresAt > Date.now() + 5 * 60 * 1000) {
        return json({ error: "INVALID_LEGACY_CHALLENGE" }, 400);
      }
      await this.ctx.storage.put("identity-legacy:" + body.userId, {
        challengeId: body.challengeId,
        identityPublicKey: body.identityPublicKey,
        serverPrivateJwk: body.serverPrivateJwk,
        challenge: body.challenge,
        expiresAt: body.expiresAt
      });
      await this.scheduleNextExpiry();
      return json({ stored: true });
    }

    if (url.pathname === "/identity-legacy/verify" && request.method === "POST") {
      let body;
      try { body = await readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
      if (typeof body?.userId !== "string" || !/^[a-z0-9_]{3,32}$/.test(body.userId) ||
          typeof body.challengeId !== "string" || typeof body.identityPublicKey !== "string" ||
          typeof body.proof !== "string") {
        return json({ valid: false }, 400);
      }
      const storageKey = "identity-legacy:" + body.userId;
      const pending = await this.ctx.storage.get(storageKey);
      // Challenges are one-use, even when the proof is invalid.
      await this.ctx.storage.delete(storageKey);
      await this.scheduleNextExpiry();
      if (!pending || pending.expiresAt <= Date.now() ||
          pending.challengeId !== body.challengeId ||
          pending.identityPublicKey !== body.identityPublicKey) {
        return json({ valid: false });
      }
      try {
        const privateKey = await crypto.subtle.importKey(
          "jwk", pending.serverPrivateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]
        );
        const legacyPublicKey = await crypto.subtle.importKey(
          "raw", fromBase64url(pending.identityPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []
        );
        const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: legacyPublicKey }, privateKey, 256);
        const proofKey = await crypto.subtle.importKey(
          "raw", shared, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
        );
        const proofBytes = fromBase64url(body.proof);
        if (proofBytes.length !== 32) return json({ valid: false });
        const message = encoder.encode(
          "SecureChat legacy-identity-possession:v1\\n" +
          body.userId + "\\n" + pending.challengeId + "\\n" +
          pending.identityPublicKey + "\\n" + pending.challenge
        );
        const valid = await crypto.subtle.verify("HMAC", proofKey, proofBytes, message);
        return json({ valid });
      } catch {
        return json({ valid: false });
      }
    }

    if (url.pathname === "/revoke" && request.method === "POST") {
      const tokenHash = request.headers.get("X-Session-Hash");
      if (!tokenHash) return new Response("Unauthorized", { status: 401 });
      for (const socket of this.ctx.getWebSockets()) {
        const attachment = socket.deserializeAttachment();
        if (attachment?.tokenHash === tokenHash) socket.close(4001, "Session revoked");
      }
      return new Response(null, { status: 204 });
    }

    if (url.pathname !== "/ws" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Not found", { status: 404 });
    }

    const token = readCookie(request);
    const session = await getSession(this.env, token);
    if (!session) return new Response("Unauthorized", { status: 401 });

    const tokenHash = await sha256(token);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const clientId = crypto.randomUUID();

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({
      clientId,
      userId: session.user_id,
      tokenHash,
      expiresAt: session.expires_at,
      windowStartedAt: Date.now(),
      messageCount: 0
    });
    await this.scheduleNextExpiry();
    server.send(JSON.stringify({
      type: "server:hello",
      clientId,
      userId: session.user_id,
      serverTime: new Date().toISOString()
    }));

    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(socket, message) {
    const attachment = socket.deserializeAttachment();
    if (!attachment) {
      socket.close(1011, "Connection state missing");
      return;
    }
    if (Date.now() >= attachment.expiresAt) {
      socket.close(4001, "Session expired");
      return;
    }

    if (typeof message !== "string") {
      socket.send(JSON.stringify({
        type: "server:error",
        code: "BINARY_NOT_SUPPORTED",
        message: "現在はテキストメッセージのみ利用できます。"
      }));
      return;
    }

    let payload;
    try { payload = JSON.parse(message); }
    catch {
      socket.send(JSON.stringify({
        type: "server:error",
        code: "INVALID_JSON",
        message: "メッセージ形式を読み取れませんでした。"
      }));
      return;
    }

    if (!payload || typeof payload !== "object" || Array.isArray(payload) || payload.type !== "chat:send" || typeof payload.text !== "string") {
      socket.send(JSON.stringify({
        type: "server:error",
        code: "INVALID_MESSAGE",
        message: "未対応のメッセージ形式です。"
      }));
      return;
    }

    const text = payload.text.trim();
    if (!text) return;
    if (Array.from(text).length > MAX_MESSAGE_LENGTH) {
      socket.send(JSON.stringify({
        type: "server:error",
        code: "MESSAGE_TOO_LONG",
        message: `メッセージは${MAX_MESSAGE_LENGTH.toLocaleString("ja-JP")}文字以内にしてください。`
      }));
      return;
    }

    const now = Date.now();
    if (now - attachment.windowStartedAt >= 10_000) {
      attachment.windowStartedAt = now;
      attachment.messageCount = 0;
    }
    attachment.messageCount += 1;
    socket.serializeAttachment(attachment);

    if (attachment.messageCount > 12) {
      socket.send(JSON.stringify({
        type: "server:error",
        code: "RATE_LIMITED",
        message: "送信が速すぎます。少し待ってから再送してください。"
      }));
      return;
    }

    const outgoing = JSON.stringify({
      type: "chat:message",
      id: crypto.randomUUID(),
      sender: { id: attachment.clientId, userId: attachment.userId },
      text,
      sentAt: new Date().toISOString()
    });

    for (const client of this.ctx.getWebSockets()) {
      try { client.send(outgoing); } catch { /* A closing socket is skipped. */ }
    }
  }

  async webSocketClose(socket) {
    try { socket.close(); } catch { /* The runtime may already have closed it. */ }
    await this.scheduleNextExpiry();
  }

  async alarm() {
    const now = Date.now();
    for (const socket of this.ctx.getWebSockets()) {
      const attachment = socket.deserializeAttachment();
      if (attachment && now >= attachment.expiresAt) {
        socket.close(4001, "Session expired");
      }
    }
    const pendingLegacyChallenges = await this.ctx.storage.list({ prefix: "identity-legacy:" });
    for (const [key, challenge] of pendingLegacyChallenges) {
      if (!challenge || challenge.expiresAt <= now) await this.ctx.storage.delete(key);
    }
    await this.scheduleNextExpiry();
  }

  async scheduleNextExpiry() {
    const expiries = this.ctx.getWebSockets()
      .map((socket) => socket.deserializeAttachment()?.expiresAt)
      .filter((value) => Number.isFinite(value) && value > Date.now());
    const pendingLegacyChallenges = await this.ctx.storage.list({ prefix: "identity-legacy:" });
    for (const challenge of pendingLegacyChallenges.values()) {
      if (challenge && Number.isFinite(challenge.expiresAt) && challenge.expiresAt > Date.now()) {
        expiries.push(challenge.expiresAt);
      }
    }
    if (expiries.length === 0) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    await this.ctx.storage.setAlarm(Math.min(...expiries));
  }

  webSocketError(socket) {
    try { socket.close(1011, "WebSocket error"); } catch { /* Ignore close races. */ }
  }
}
