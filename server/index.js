import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { WebSocket, WebSocketServer } from "ws";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDirectory = path.resolve(__dirname, "../public");

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const NODE_ENV = process.env.NODE_ENV ?? "development";
const MAX_MESSAGE_LENGTH = 2_000;
const MAX_NAME_LENGTH = 24;
const RATE_WINDOW_MS = 10_000;
const RATE_LIMIT = 12;

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
  response.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self' ws: wss:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'"
    ].join("; ")
  );

  if (NODE_ENV === "production") {
    response.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }

  next();
});

app.get("/api/health", (_request, response) => {
  response.json({
    status: "ok",
    mode: "prototype",
    authentication: false,
    endToEndEncryption: false,
    messagePersistence: false
  });
});

app.use(
  express.static(publicDirectory, {
    index: "index.html",
    etag: true,
    maxAge: NODE_ENV === "production" ? "1h" : 0
  })
);

app.use((request, response) => {
  response.status(404).json({
    error: "NOT_FOUND",
    path: request.path
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

function cleanDisplayName(value) {
  if (typeof value !== "string") return "ゲスト";

  const cleaned = value
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, MAX_NAME_LENGTH);

  return cleaned || "ゲスト";
}

function broadcast(payload) {
  const serialized = JSON.stringify(payload);

  for (const client of webSocketServer.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(serialized);
    }
  }
}

httpServer.on("upgrade", (request, socket, head) => {
  let pathname = "";

  try {
    const requestUrl = new URL(
      request.url ?? "/",
      `http://${request.headers.host ?? "localhost"}`
    );
    pathname = requestUrl.pathname;
  } catch {
    socket.destroy();
    return;
  }

  // Only accept same-origin browser connections to the chat endpoint.
  let sameOrigin = false;
  try {
    const origin = request.headers.origin;
    const host = request.headers.host;
    sameOrigin = Boolean(
      origin &&
      host &&
      new URL(origin).host.toLowerCase() === host.toLowerCase()
    );
  } catch {
    sameOrigin = false;
  }

  if (pathname !== "/ws" || !sameOrigin) {
    socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }

  webSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
    webSocketServer.emit("connection", webSocket, request);
  });
});

webSocketServer.on("connection", (socket) => {
  const clientId = randomUUID();
  const rateState = {
    windowStartedAt: Date.now(),
    messageCount: 0
  };

  sendJson(socket, {
    type: "server:hello",
    clientId,
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
    if (rateState.messageCount > RATE_LIMIT) {
      sendError(socket, "RATE_LIMITED", "送信が速すぎます。少し待ってから再送してください。");
      return;
    }

    const message = {
      type: "chat:message",
      id: randomUUID(),
      sender: {
        id: clientId,
        name: cleanDisplayName(payload.name)
      },
      text,
      sentAt: new Date().toISOString()
    };

    // Prototype only: this relays plaintext to every connected browser.
    // Messages are not persisted, and this is not an E2EE implementation.
    broadcast(message);
  });

  socket.on("error", (error) => {
    console.error("WebSocket connection error:", error.message);
  });
});

httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`SecureChat prototype listening on port ${PORT}`);
});

function shutdown() {
  console.log("Shutting down SecureChat...");
  for (const client of webSocketServer.clients) {
    client.close(1001, "Server shutting down");
  }

  httpServer.close(() => {
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
