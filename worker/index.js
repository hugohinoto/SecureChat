import { DurableObject } from "cloudflare:workers";

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 100_000;
const MAX_MESSAGE_LENGTH = 2_000;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const authAttempts = new Map();

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
    `SELECT users.id, users.user_id, sessions.expires_at
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

function checkRateLimit(request, action, maxAttempts) {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const key = `${action}:${ip}`;
  const now = Date.now();
  let bucket = authAttempts.get(key);
  if (!bucket || now - bucket.startedAt >= AUTH_WINDOW_MS) {
    bucket = { startedAt: now, count: 0 };
    authAttempts.set(key, bucket);
  }
  bucket.count += 1;
  if (authAttempts.size > 5_000) {
    for (const [entry, value] of authAttempts) {
      if (now - value.startedAt >= AUTH_WINDOW_MS) authAttempts.delete(entry);
    }
  }
  return bucket.count <= maxAttempts;
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
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      `connect-src 'self' ${wsOrigin}`,
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'"
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

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

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
        ? { authenticated: true, user: { id: session.id, userId: session.user_id } }
        : { authenticated: false, user: null });
    } catch {
      return json({ error: "AUTH_UNAVAILABLE", message: "認証サービスを利用できません。" }, 503);
    }
  }

  if (path === "/api/auth/register" && method === "POST") {
    if (!sameOrigin(request)) {
      return json({ error: "ORIGIN_REJECTED", message: "このリクエストは許可されていません。" }, 403);
    }
    if (!checkRateLimit(request, "register", 4)) {
      return json({ error: "RATE_LIMITED", message: "試行回数が多すぎます。時間をおいて再試行してください。" }, 429);
    }

    let body;
    try { body = await readJson(request); }
    catch (error) {
      return json({ error: error.message, message: "リクエスト形式を確認してください。" }, 400);
    }

    const userId = normalizeUserId(body?.userId);
    const password = body?.password;
    if (!userId) {
      return json({ error: "INVALID_USER_ID", message: "ユーザーIDは半角英小文字・数字・アンダースコアで3〜32文字にしてください。" }, 400);
    }
    if (!validPassword(password)) {
      return json({ error: "INVALID_PASSWORD", message: "パスワードは12〜128文字で入力してください。" }, 400);
    }

    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const passwordHash = await derivePassword(password, salt);
      const userUuid = crypto.randomUUID();
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO users (id, user_id, password_salt, password_hash, password_iterations, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(
        userUuid,
        userId,
        base64url(salt),
        base64url(passwordHash),
        PASSWORD_ITERATIONS,
        now
      ).run();

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
      console.error("Account registration failed:", error.message);
      return json({ error: "REGISTRATION_UNAVAILABLE", message: "アカウントを作成できませんでした。時間をおいて再試行してください。" }, 503);
    }
  }

  if (path === "/api/auth/login" && method === "POST") {
    if (!sameOrigin(request)) {
      return json({ error: "ORIGIN_REJECTED", message: "このリクエストは許可されていません。" }, 403);
    }
    if (!checkRateLimit(request, "login", 10)) {
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
        "SELECT id, user_id, password_salt, password_hash, password_iterations FROM users WHERE user_id = ? LIMIT 1"
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
        user: { id: user.id, userId: user.user_id }
      });
      setSessionCookie(response, request, session.token);
      return response;
    } catch (error) {
      console.error("Login failed:", error.message);
      return json({ error: "LOGIN_UNAVAILABLE", message: "ログインできませんでした。時間をおいて再試行してください。" }, 503);
    }
  }

  if (path === "/api/auth/delete" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    if (!checkRateLimit(request, "delete-account", 3)) {
      return json({ error: "RATE_LIMITED", message: "試行回数が多すぎます。時間をおいてください。" }, 429);
    }
    let session;
    try { session = await getSession(env, readCookie(request)); }
    catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
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
      console.error("Account deletion failed:", error.message);
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
  if (path.startsWith("/api/") && (path === "/api/users/search" || path === "/api/contacts" || path.startsWith("/api/contacts/") || path === "/api/contact-invitations" || path.startsWith("/api/contact-invitations/") || path === "/api/keys" || path.startsWith("/api/keys/") || path === "/api/conversations" || path.startsWith("/api/conversations/"))) {
    if (method !== "GET" && !sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    let session;
    try { session = await getSession(env, readCookie(request)); } catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    const me = session.id;
    const now = Date.now();

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
      if (!checkRateLimit(request, "contact-invite", 10)) return json({ error: "RATE_LIMITED", message: "招待の発行回数が多すぎます。時間をおいて再試行してください。" }, 429);
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
    if (path === "/api/keys" && method === "PUT") {
      const body = await readJson(request);
      const pub = body?.identityPublicKey;
      if (typeof pub !== "string" || pub.length < 80 || pub.length > 128) return json({ error: "INVALID_PUBLIC_KEY" }, 400);
      try {
        const raw = Uint8Array.from(atob(pub), (char) => char.charCodeAt(0));
        if (raw.length !== 65 || raw[0] !== 4) return json({ error: "INVALID_PUBLIC_KEY" }, 400);
      } catch {
        return json({ error: "INVALID_PUBLIC_KEY" }, 400);
      }
      await env.DB.prepare("INSERT INTO user_keys (user_id, identity_public_key, signed_prekey, signed_prekey_signature, key_version, updated_at) VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT(user_id) DO UPDATE SET identity_public_key=excluded.identity_public_key, signed_prekey=excluded.signed_prekey, signed_prekey_signature=excluded.signed_prekey_signature, key_version=user_keys.key_version+1, updated_at=excluded.updated_at").bind(me, pub, pub, "not-used-static-ecdh-v1", now).run();
      return json({ saved: true });
    }
    if (path.startsWith("/api/keys/") && method === "GET") {
      const userId = normalizeUserId(decodeURIComponent(path.slice("/api/keys/".length)));
      if (!userId) return json({ error: "INVALID_USER_ID" }, 400);
      const key = await env.DB.prepare("SELECT k.identity_public_key FROM user_keys k JOIN users u ON u.id=k.user_id WHERE u.user_id=?").bind(userId).first();
      return key ? json({ userId, identityPublicKey: key.identity_public_key }) : json({ error: "KEY_NOT_FOUND" }, 404);
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
      const existing = await env.DB.prepare("SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=? JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=? LIMIT 1").bind(me, peer.id).first();
      if (existing) return json({ conversationId: existing.id, existing: true });
      const id = crypto.randomUUID();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO conversations (id, created_by, created_at, expires_in_seconds) VALUES (?, ?, ?, 3600)").bind(id, me, now),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)").bind(id, me, now),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)").bind(id, peer.id, now)
      ]);
      return json({ conversationId: id, existing: false }, 201);
    }
    if (path === "/api/conversations" && method === "GET") {
      const rows = await env.DB.prepare("SELECT c.id, u.user_id AS peer_user_id, c.created_at FROM conversations c JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? JOIN conversation_members peer ON peer.conversation_id=c.id AND peer.user_id<>? JOIN users u ON u.id=peer.user_id JOIN verified_contact_pairs p ON p.user_a_id=CASE WHEN mine.user_id<peer.user_id THEN mine.user_id ELSE peer.user_id END AND p.user_b_id=CASE WHEN mine.user_id<peer.user_id THEN peer.user_id ELSE mine.user_id END ORDER BY c.created_at DESC").bind(me, me).all();
      return json({ conversations: rows.results });
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
          rows = await env.DB.prepare("SELECT id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at FROM encrypted_messages WHERE conversation_id=? AND expires_at>? AND (created_at>? OR (created_at=? AND id>?)) ORDER BY created_at, id LIMIT 500").bind(id, now, after, after, afterId).all();
        } else {
          rows = await env.DB.prepare("SELECT id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at FROM encrypted_messages WHERE conversation_id=? AND expires_at>? ORDER BY created_at, id LIMIT 500").bind(id, now).all();
        }
        return json({ messages: rows.results });
      }
      if (sub === "messages" && method === "POST") {
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
        await env.DB.prepare("INSERT INTO encrypted_messages (id, conversation_id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'AES-GCM-256', ?, ?)").bind(msgId, id, me, body.ciphertext, body.nonce, now, expires).run();
        return json({ id: msgId, createdAt: now, expiresAt: expires }, 201);
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
      env.DB.prepare("DELETE FROM contact_invitations WHERE expires_at <= ?").bind(now).run()
    ]));
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol === "http:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 308);
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
    await this.scheduleNextExpiry();
  }

  async scheduleNextExpiry() {
    const expiries = this.ctx.getWebSockets()
      .map((socket) => socket.deserializeAttachment()?.expiresAt)
      .filter((value) => Number.isFinite(value) && value > Date.now());
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
