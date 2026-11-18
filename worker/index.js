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
        endToEndEncryption: false,
        messagePersistence: false,
        mode: "Cloudflare Workers prototype"
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
  if (path.startsWith("/api/") && (path === "/api/users/search" || path === "/api/contacts" || path === "/api/contacts/add" || path === "/api/keys" || path.startsWith("/api/keys/") || path === "/api/conversations" || path.startsWith("/api/conversations/"))) {
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
      const rows = await env.DB.prepare("SELECT u.user_id FROM contacts c JOIN users u ON u.id=c.contact_user_id WHERE c.owner_user_id=? ORDER BY u.user_id").bind(me).all();
      return json({ contacts: rows.results.map((r) => ({ userId: r.user_id })) });
    }
    if (path === "/api/contacts/add" && method === "POST") {
      const body = await readJson(request);
      const userId = normalizeUserId(body?.userId);
      if (!userId) return json({ error: "INVALID_USER_ID" }, 400);
      const target = await env.DB.prepare("SELECT id FROM users WHERE user_id=?").bind(userId).first();
      if (!target) return json({ error: "USER_NOT_FOUND" }, 404);
      if (target.id === me) return json({ error: "SELF_CONTACT" }, 400);
      await env.DB.prepare("INSERT OR IGNORE INTO contacts (owner_user_id, contact_user_id, created_at) VALUES (?, ?, ?)").bind(me, target.id, now).run();
      return json({ added: true, userId });
    }
    if (path === "/api/keys" && method === "PUT") {
      const body = await readJson(request);
      const pub = body?.identityPublicKey;
      if (typeof pub !== "string" || pub.length < 20 || pub.length > 4096) return json({ error: "INVALID_PUBLIC_KEY" }, 400);
      await env.DB.prepare("INSERT INTO user_keys (user_id, identity_public_key, signed_prekey, signed_prekey_signature, key_version, updated_at) VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT(user_id) DO UPDATE SET identity_public_key=excluded.identity_public_key, signed_prekey=excluded.signed_prekey, signed_prekey_signature=excluded.signed_prekey_signature, key_version=user_keys.key_version+1, updated_at=excluded.updated_at").bind(me, pub, pub, "client-managed-v1", now).run();
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
      const mine = body?.myKeyEnvelope;
      const theirs = body?.theirKeyEnvelope;
      if (!peerId || typeof mine !== "string" || typeof theirs !== "string" || mine.length > 8192 || theirs.length > 8192) return json({ error: "INVALID_CONVERSATION" }, 400);
      const peer = await env.DB.prepare("SELECT id FROM users WHERE user_id=?").bind(peerId).first();
      if (!peer) return json({ error: "USER_NOT_FOUND" }, 404);
      if (peer.id === me) return json({ error: "SELF_CONVERSATION" }, 400);
      const peerKey = await env.DB.prepare("SELECT user_id FROM user_keys WHERE user_id=?").bind(peer.id).first();
      if (!peerKey) return json({ error: "RECIPIENT_KEY_MISSING" }, 409);
      const existing = await env.DB.prepare("SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=? JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=? LIMIT 1").bind(me, peer.id).first();
      if (existing) return json({ conversationId: existing.id, existing: true });
      const id = crypto.randomUUID();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO conversations (id, created_by, created_at, expires_in_seconds) VALUES (?, ?, ?, 3600)").bind(id, me, now),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)").bind(id, me, now),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)").bind(id, peer.id, now),
        env.DB.prepare("INSERT INTO conversation_keys (conversation_id, user_id, key_envelope, created_at) VALUES (?, ?, ?, ?)").bind(id, me, mine, now),
        env.DB.prepare("INSERT INTO conversation_keys (conversation_id, user_id, key_envelope, created_at) VALUES (?, ?, ?, ?)").bind(id, peer.id, theirs, now)
      ]);
      return json({ conversationId: id, existing: false }, 201);
    }
    if (path === "/api/conversations" && method === "GET") {
      const rows = await env.DB.prepare("SELECT c.id, u.user_id AS peer_user_id, c.created_at FROM conversations c JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? JOIN conversation_members peer ON peer.conversation_id=c.id AND peer.user_id<>? JOIN users u ON u.id=peer.user_id ORDER BY c.created_at DESC").bind(me, me).all();
      return json({ conversations: rows.results });
    }
    const match = path.match(/^\/api\/conversations\/([a-f0-9-]+)(?:\/(messages|key))?$/i);
    if (match) {
      const id = match[1], sub = match[2] || "";
      const member = await env.DB.prepare("SELECT 1 AS ok FROM conversation_members WHERE conversation_id=? AND user_id=?").bind(id, me).first();
      if (!member) return json({ error: "CONVERSATION_NOT_FOUND" }, 404);
      if (sub === "key" && method === "GET") {
        const row = await env.DB.prepare("SELECT key_envelope FROM conversation_keys WHERE conversation_id=? AND user_id=?").bind(id, me).first();
        return row ? json({ keyEnvelope: row.key_envelope }) : json({ error: "KEY_ENVELOPE_NOT_FOUND" }, 404);
      }
      if (sub === "messages" && method === "GET") {
        await env.DB.prepare("DELETE FROM encrypted_messages WHERE conversation_id=? AND expires_at<=?").bind(id, now).run();
        const rows = await env.DB.prepare("SELECT id, sender_user_id, ciphertext, nonce, algorithm, created_at, expires_at FROM encrypted_messages WHERE conversation_id=? AND expires_at>? ORDER BY created_at LIMIT 500").bind(id, now).all();
        return json({ messages: rows.results });
      }
      if (sub === "messages" && method === "POST") {
        const body = await readJson(request);
        if (typeof body?.ciphertext !== "string" || body.ciphertext.length < 1 || body.ciphertext.length > 12000 || typeof body?.nonce !== "string" || body.nonce.length > 128 || body.algorithm !== "AES-GCM-256") return json({ error: "CIPHERTEXT_REQUIRED" }, 400);
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
    ctx.waitUntil(env.DB.prepare("DELETE FROM encrypted_messages WHERE expires_at <= ?").bind(Date.now()).run());
  },
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      if (request.method !== "GET" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return new Response("WebSocket upgrade required", { status: 426 });
      }
      const id = env.CHAT_ROOM.idFromName("open-lounge");
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
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
