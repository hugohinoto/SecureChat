const connectionPill = document.querySelector("#connection-pill");
const connectionLabel = document.querySelector("#connection-label");
const messageList = document.querySelector("#message-list");
const messageInput = document.querySelector("#message-input");
const sendButton = document.querySelector("#send-button");
const characterCount = document.querySelector("#character-count");
const nameButton = document.querySelector("#name-button");
const profileName = document.querySelector("#profile-name");
const toast = document.querySelector("#toast");

const MAX_MESSAGE_LENGTH = 2_000;
const NAME_STORAGE_KEY = "securechat.displayName";

let socket = null;
let clientId = null;
let reconnectDelay = 1_000;
let reconnectTimer = null;
let toastTimer = null;
let displayName = loadDisplayName();

function loadDisplayName() {
  try {
    const saved = localStorage.getItem(NAME_STORAGE_KEY);
    return saved?.trim().slice(0, 24) || "ゲスト";
  } catch {
    return "ゲスト";
  }
}

function setDisplayName(value) {
  const cleaned = value
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, 24);

  if (!cleaned) {
    showToast("表示名を入力してください。");
    return;
  }

  displayName = cleaned;
  profileName.textContent = displayName;
  document.querySelector(".profile-avatar").textContent = Array.from(displayName)[0] ?? "G";

  try {
    localStorage.setItem(NAME_STORAGE_KEY, displayName);
  } catch {
    showToast("このブラウザーでは表示名を保存できませんでした。");
  }
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 3_200);
}

function setConnectionState(state, label) {
  connectionPill.dataset.state = state;
  connectionLabel.textContent = label;
  const connected = state === "connected";
  messageInput.disabled = !connected;
  updateSendState();
}

function updateSendState() {
  const hasText = messageInput.value.trim().length > 0;
  sendButton.disabled = !hasText || !socket || socket.readyState !== WebSocket.OPEN;
  characterCount.textContent = `${Array.from(messageInput.value).length} / ${MAX_MESSAGE_LENGTH}`;
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("ja-JP", {
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function appendMessage(message) {
  const wasNearBottom =
    messageList.scrollHeight - messageList.scrollTop - messageList.clientHeight < 110;

  const row = document.createElement("article");
  const isOwnMessage = message.sender?.id === clientId;
  row.className = isOwnMessage ? "message-row own" : "message-row";

  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.textContent = Array.from(message.sender?.name ?? "G")[0] ?? "G";

  const content = document.createElement("div");
  content.className = "message-content";

  const meta = document.createElement("div");
  meta.className = "message-meta";

  const name = document.createElement("span");
  name.className = "message-name";
  name.textContent = isOwnMessage ? "あなた" : (message.sender?.name ?? "ゲスト");

  const time = document.createElement("time");
  time.className = "message-time";
  time.dateTime = message.sentAt ?? "";
  time.textContent = formatTime(message.sentAt);

  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  // Never interpret a message as HTML. User-controlled content is text only.
  bubble.textContent = message.text ?? "";

  meta.append(name, time);
  content.append(meta, bubble);
  row.append(avatar, content);
  messageList.append(row);

  if (wasNearBottom || isOwnMessage) {
    messageList.scrollTop = messageList.scrollHeight;
  }
}

function appendServerError(message) {
  const error = document.createElement("div");
  error.className = "server-error";
  error.textContent = message;
  messageList.append(error);
  messageList.scrollTop = messageList.scrollHeight;
}

function connect() {
  window.clearTimeout(reconnectTimer);
  setConnectionState("connecting", "接続中");

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const endpoint = `${protocol}//${window.location.host}/ws`;

  try {
    socket = new WebSocket(endpoint);
  } catch {
    setConnectionState("disconnected", "接続できません");
    scheduleReconnect();
    return;
  }

  socket.addEventListener("open", () => {
    reconnectDelay = 1_000;
    setConnectionState("connected", "接続中");
    messageInput.focus({ preventScroll: true });
  });

  socket.addEventListener("message", (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }

    if (payload.type === "server:hello") {
      clientId = payload.clientId;
      return;
    }

    if (payload.type === "chat:message") {
      appendMessage(payload);
      return;
    }

    if (payload.type === "server:error") {
      appendServerError(payload.message ?? "メッセージを送信できませんでした。");
    }
  });

  socket.addEventListener("close", () => {
    clientId = null;
    setConnectionState("disconnected", "再接続待ち");
    scheduleReconnect();
  });

  socket.addEventListener("error", () => {
    setConnectionState("disconnected", "通信エラー");
  });
}

function scheduleReconnect() {
  window.clearTimeout(reconnectTimer);
  reconnectTimer = window.setTimeout(connect, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, 15_000);
}

function sendMessage() {
  const text = messageInput.value.trim();
  if (!text) return;

  if (Array.from(text).length > MAX_MESSAGE_LENGTH) {
    showToast(`メッセージは${MAX_MESSAGE_LENGTH}文字以内にしてください。`);
    return;
  }

  if (!socket || socket.readyState !== WebSocket.OPEN) {
    showToast("サーバーに接続されていません。");
    return;
  }

  socket.send(JSON.stringify({
    type: "chat:send",
    name: displayName,
    text
  }));

  messageInput.value = "";
  messageInput.style.height = "auto";
  updateSendState();
  messageInput.focus();
}

nameButton.addEventListener("click", () => {
  const nextName = window.prompt("チャットで表示する名前を入力してください。", displayName);
  if (nextName !== null) setDisplayName(nextName);
});

messageInput.addEventListener("input", () => {
  messageInput.style.height = "auto";
  messageInput.style.height = `${Math.min(messageInput.scrollHeight, 125)}px`;
  updateSendState();
});

messageInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    sendMessage();
  }
});

sendButton.addEventListener("click", sendMessage);

setDisplayName(displayName);
connect();
