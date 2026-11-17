import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { WebSocket, WebSocketServer } from "ws";
import { pool } from "./db.js";
import {
  createDatabaseSession,
  createPasswordRecord,
  deleteDatabaseSession,
  findDatabaseSession,
  hashSessionToken,
  normalizeUserId,
  readSessionToken,
  clearSessionCookie,
  setSessionCookie,
  validatePassword,
  verifyPassword
} from "./auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDirectory = path.resolve(__dirname, "../public");

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const NODE_ENV = process.env.NODE_ENV ?? "development";
const IS_PRODUCTION = NODE_ENV === "production";
const MAX_MESSAGE_LENGTH = 2_000;
const RATE_WINDOW_MS = 10_000;
const CHAT_RATE_LIMIT = 12;
const AUTH_RATE_WINDOW_MS = 15 * 60 * 1000;

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use((request, response, next) => {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");

  const requestHost = request.get("host");
  const websocketOrigin = requestHost
    ? `${request.secure ? "wss" : "ws"}://${requestHost}`
    : "'self'";

  response.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      `connect-src 'self' ${websocketOrigin}`,
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'"
    ].join("; ")
  );

  if (IS_PRODUCTION) {
    response.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }

  next();
});

app.use(express.json({ limit: "16kb", strict: true }));

app.use("/api", (_request, response, next) => {
  response.setHeader("Cache-Control", "no-store");
  next();
});

function createRateLimiter(maxAttempts, windowMs) {
  const buckets = new Map();

  return (request, response, next) => {
    const key = request.ip || "unknown";
    const now = Date.now();
    let bucket = buckets.get(key);

    if (!bucket || now - bucket.startedAt >= windowMs) {
      bucket = { startedAt: now, count: 0 };
      buckets.set(key, bucket);
    }

    bucket.count += 1;

    if (bucket.count > maxAttempts) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((windowMs - (now - bucket.startedAt)) / 1000)
      );
      response.setHeader("Retry-After", String(retryAfterSeconds));
      response.status(429).json({
        error: "RATE_LIMITED",
        message: "試行回数が多すぎます。時間をおいて再試行してください。"
      });
      return;
    }

    // Bound memory use in this single-process prototype.
    if (buckets.size > 5_000) {
      for (const [bucketKey, value] of buckets) {
        if (now - value.startedAt >= windowMs) buckets.delete(bucketKey);
      }
    }

    next();
  };
}

function requireSameOrigin(request, response, next) {
  const origin = request.get("origin");
  const host = request.get("host");

  try {
    if (!origin || !host) throw new Error("Missing origin");
    const parsedOrigin = new URL(origin);
    const expectedProtocol = IS_PRODUCTION ? "https:" : request.protocol + ":";

    if (
      parsedOrigin.host.toLowerCase() !== host.toLowerCase() ||
      parsedOrigin.protocol !== expectedProtocol
    ) {
      throw new Error("Origin mismatch");
    }

    next();
  } catch {
    response.status(403).json({
      error: "ORIGIN_REJECTED",
      message: "このリクエストは許可されていません。"
    });
  }
}

function getRequestSessionToken(request) {
  return readSessionToken(request.headers.cookie, IS_PRODUCTION);
}

async function getAuthenticatedSession(request) {
  const token = getRequestSessionToken(request);
  if (!token) return null;
  return findDatabaseSession(pool, token);
}

const loginRateLimit = createRateLimiter(10, AUTH_RATE_WINDOW_MS);
const registerRateLimit = createRateLimiter(4, AUTH_RATE_WINDOW_MS);

app.get("/api/health", async (_request, response) => {
  try {
    await pool.query("SELECT 1");
    response.json({
      status: "ok",
      database: "connected",
      authentication: true,
      endToEndEncryption: false,
      messagePersistence: false,
      mode: "authenticated prototype"
    });
  } catch {
    response.status(503).json({
      status: "unavailable",
      database: "unavailable"
    });
  }
});

app.get("/api/auth/me", async (request, response) => {
  try {
    const session = await getAuthenticatedSession(request);

    if (!session) {
      response.json({ authenticated: false, user: null });
      return;
    }

    response.json({
      authenticated: true,
      user: {
        id: session.id,
        userId: session.user_id
      }
    });
  } catch {
    response.status(503).json({
      error: "AUTH_UNAVAILABLE",
      message: "認証サービスを利用できません。"
    });
  }
});

app.post("/api/auth/register", requireSameOrigin, registerRateLimit, async (request, response) => {
  const userId = normalizeUserId(request.body?.userId);
  const password = request.body?.password;

  if (!userId) {
    response.status(400).json({
      error: "INVALID_USER_ID",
      message: "ユーザーIDは半角英小文字・数字・アンダースコアで3〜32文字にしてください。"
    });
    return;
  }

  if (!validatePassword(password)) {
    response.status(400).json({
      error: "INVALID_PASSWORD",
      message: "パスワードは12〜128文字で入力してください。"
    });
    return;
  }

  try {
    const passwordRecord = await createPasswordRecord(password);
    const userIdValue = randomUUID();

    const created = await pool.query(
      `INSERT INTO users (id, user_id, password_salt, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, user_id`,
      [userIdValue, userId, passwordRecord.salt, passwordRecord.hash]
    );

    const user = created.rows[0];
    const token = await createDatabaseSession(pool, user.id);
    setSessionCookie(response, token, IS_PRODUCTION);

    response.status(201).json({
      authenticated: true,
      user: {
        id: user.id,
        userId: user.user_id
      }
    });
  } catch (error) {
    if (error.code === "23505") {
      response.status(409).json({
        error: "USER_ID_TAKEN",
        message: "このユーザーIDは既に使用されています。"
      });
      return;
    }

    console.error("Account registration failed:", error.code ?? error.name);
    response.status(503).json({
      error: "REGISTRATION_UNAVAILABLE",
      message: "アカウントを作成できませんでした。時間をおいて再試行してください。"
    });
  }
});

app.post("/api/auth/login", requireSameOrigin, loginRateLimit, async (request, response) => {
  const userId = normalizeUserId(request.body?.userId);
  const password = request.body?.password;

  if (
    !userId ||
    typeof password !== "string" ||
    password.length > 128 ||
    Buffer.byteLength(password, "utf8") > 512
  ) {
    response.status(401).json({
      error: "INVALID_CREDENTIALS",
      message: "ユーザーIDまたはパスワードが正しくありません。"
    });
    return;
  }

  try {
    const lookup = await pool.query(
      `SELECT id, user_id, password_salt, password_hash
         FROM users
        WHERE user_id = $1
        LIMIT 1`,
      [userId]
    );

    const user = lookup.rows[0] ?? null;
    // The same expensive password derivation runs for unknown IDs to reduce
    // account-enumeration timing differences.
    const passwordMatches = await verifyPassword(
      password,
      user?.password_salt,
      user?.password_hash
    );

    if (!user || !passwordMatches) {
      response.status(401).json({
        error: "INVALID_CREDENTIALS",
        message: "ユーザーIDまたはパスワードが正しくありません。"
      });
      return;
    }

    await pool.query(
      "UPDATE users SET last_login_at = NOW() WHERE id = $1",
      [user.id]
    );

    const token = await createDatabaseSession(pool, user.id);
    setSessionCookie(response, token, IS_PRODUCTION);

    response.json({
      authenticated: true,
      user: {
        id: user.id,
        userId: user.user_id
      }
    });
  } catch (error) {
    console.error("Login failed:", error.code ?? error.name);
    response.status(503).json({
      error: "LOGIN_UNAVAILABLE",
      message: "ログインできませんでした。時間をおいて再試行してください。"
    });
  }
});

app.post("/api/auth/logout", requireSameOrigin, async (request, response) => {
  try {
    const token = getRequestSessionToken(request);
    if (token) {
      await deleteDatabaseSession(pool, token);
      const tokenHash = hashSessionToken(token);
      for (const client of webSocketServer.clients) {
        if (client.sessionTokenHash === tokenHash) {
          client.close(4001, "Session revoked");
        }
      }
    }
    clearSessionCookie(response, IS_PRODUCTION);
    response.status(204).end();
  } catch {
    response.status(503).json({
      error: "LOGOUT_UNAVAILABLE",
      message: "ログアウトを完了できませんでした。"
    });
  }
});

app.use(
  express.static(publicDirectory, {
    index: "index.html",
    etag: true,
    maxAge: IS_PRODUCTION ? "1h" : 0
  })
);

app.use((request, response) => {
  response.status(404).json({
    error: "NOT_FOUND",
    path: request.path
  });
});

app.use((error, _request, response, _next) => {
  if (error?.type === "entity.too.large") {
    response.status(413).json({
      error: "REQUEST_TOO_LARGE",
      message: "リクエストが大きすぎます。"
    });
    return;
  }

  response.status(400).json({
    error: "INVALID_REQUEST",
    message: "リクエスト形式が正しくありません。"
  });
});

const httpServer = createServer(app);
const webSocketServer = new WebSocketServer({
  noServer: true,
  maxPayload: 8 * 1024,
  perMessageDeflate: false
});

function sendJson(socket, payload) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(payload));
  }
}

function sendError(socket, code, message) {
  sendJson(socket, {
    type: "server:error",
    code,
    message
  });
}

function broadcast(payload) {
  const serialized = JSON.stringify(payload);

  for (const client of webSocketServer.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(serialized);
    }
  }
}

function rejectUpgrade(socket, statusCode, reason) {
  socket.write(
    `HTTP/1.1 ${statusCode} ${reason}\r\nConnection: close\r\n\r\n`
  );
  socket.destroy();
}

httpServer.on("upgrade", async (request, socket, head) => {
  let pathname = "";
  try {
    const requestUrl = new URL(
      request.url ?? "/",
      `http://${request.headers.host ?? "localhost"}`
    );
    pathname = requestUrl.pathname;
  } catch {
    rejectUpgrade(socket, 400, "Bad Request");
    return;
  }

  let sameOrigin = false;
  try {
    const origin = request.headers.origin;
    const host = request.headers.host;
    const parsedOrigin = new URL(origin);
    sameOrigin = Boolean(
      host &&
      parsedOrigin.host.toLowerCase() === host.toLowerCase() &&
      (IS_PRODUCTION
        ? parsedOrigin.protocol === "https:"
        : parsedOrigin.protocol === "http:")
    );
  } catch {
    sameOrigin = false;
  }

  if (pathname !== "/ws" || !sameOrigin) {
    rejectUpgrade(socket, 403, "Forbidden");
    return;
  }

  try {
    const token = readSessionToken(request.headers.cookie, IS_PRODUCTION);
    const session = await findDatabaseSession(pool, token);

    if (!session) {
      rejectUpgrade(socket, 401, "Unauthorized");
      return;
    }

    const tokenHash = hashSessionToken(token);
    webSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
      webSocketServer.emit("connection", webSocket, request, session, tokenHash);
    });
  } catch {
    rejectUpgrade(socket, 503, "Service Unavailable");
  }
});

webSocketServer.on("connection", (socket, _request, session, tokenHash) => {
  socket.sessionTokenHash = tokenHash;
  const expiresAt = new Date(session.expires_at).getTime();
  const expiryTimer = setTimeout(() => socket.close(4001, "Session expired"), Math.max(0, expiresAt - Date.now()));
  socket.once("close", () => clearTimeout(expiryTimer));

  const connectionId = randomUUID();
  const rateState = {
    windowStartedAt: Date.now(),
    messageCount: 0
  };

  sendJson(socket, {
    type: "server:hello",
    clientId: connectionId,
    userId: session.user_id,
    serverTime: new Date().toISOString()
  });

  socket.on("message", (rawData, isBinary) => {
    if (isBinary) {
      sendError(socket, "BINARY_NOT_SUPPORTED", "現在はテキストメッセージのみ利用できます。");
      return;
    }

    let payload;
    try {
      payload = JSON.parse(rawData.toString("utf8"));
    } catch {
      sendError(socket, "INVALID_JSON", "メッセージ形式を読み取れませんでした。");
      return;
    }

    if (
      !payload ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      payload.type !== "chat:send"
    ) {
      sendError(socket, "INVALID_MESSAGE", "未対応のメッセージ形式です。");
      return;
    }

    if (typeof payload.text !== "string") {
      sendError(socket, "INVALID_TEXT", "メッセージ本文が正しくありません。");
      return;
    }

    const text = payload.text.trim();
    if (!text) return;

    if (Array.from(text).length > MAX_MESSAGE_LENGTH) {
      sendError(
        socket,
        "MESSAGE_TOO_LONG",
        `メッセージは${MAX_MESSAGE_LENGTH.toLocaleString("ja-JP")}文字以内にしてください。`
      );
      return;
    }

    const now = Date.now();
    if (now - rateState.windowStartedAt >= RATE_WINDOW_MS) {
      rateState.windowStartedAt = now;
      rateState.messageCount = 0;
    }

    rateState.messageCount += 1;
    if (rateState.messageCount > CHAT_RATE_LIMIT) {
      sendError(socket, "RATE_LIMITED", "送信が速すぎます。少し待ってから再送してください。");
      return;
    }

    const message = {
      type: "chat:message",
      id: randomUUID(),
      sender: {
        id: connectionId,
        userId: session.user_id
      },
      text,
      sentAt: new Date().toISOString()
    };

    // Prototype only: plaintext is still relayed to every authenticated
    // connection. The server can read it. This is not E2EE.
    broadcast(message);
  });

  socket.on("error", (error) => {
    console.error("WebSocket connection error:", error.message);
  });
});

httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`SecureChat authenticated prototype listening on port ${PORT}`);
});

async function shutdown() {
  console.log("Shutting down SecureChat...");
  for (const client of webSocketServer.clients) {
    client.close(1001, "Server shutting down");
  }

  webSocketServer.close();
  httpServer.close(async () => {
    await pool.end().catch(() => {});
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
