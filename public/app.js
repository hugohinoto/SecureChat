const connectionPill = document.querySelector("#connection-pill");
const connectionLabel = document.querySelector("#connection-label");
const messageList = document.querySelector("#message-list");
const messageInput = document.querySelector("#message-input");
const sendButton = document.querySelector("#send-button");
const characterCount = document.querySelector("#character-count");
const profileName = document.querySelector("#profile-name");
const profileAvatar = document.querySelector("#profile-avatar");
const logoutButton = document.querySelector("#logout-button");
const toast = document.querySelector("#toast");

const authGate = document.querySelector("#auth-gate");
const authForm = document.querySelector("#auth-form");
const authTitle = document.querySelector("#auth-title");
const authDescription = document.querySelector("#auth-description");
const authError = document.querySelector("#auth-error");
const authSubmit = document.querySelector("#auth-submit");
const authUserId = document.querySelector("#auth-user-id");
const authPassword = document.querySelector("#auth-password");
const passwordHint = document.querySelector("#password-hint");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");

const MAX_MESSAGE_LENGTH = 2_000;
const USER_ID_STORAGE_NOTICE = "アカウントIDとパスワードはサーバーで認証されます。";
let socket = null;
let clientId = null;
let currentUser = null;
let authMode = "login";
let reconnectDelay = 1_000;
let reconnectTimer = null;
let toastTimer = null;
let shouldReconnect = false;
let authCheckTimer = null;

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
  messageInput.disabled = !connected || !currentUser;
  updateSendState();
}

function updateSendState() {
  const hasText = messageInput.value.trim().length > 0;
  sendButton.disabled =
    !hasText ||
    !currentUser ||
    !socket ||
    socket.readyState !== WebSocket.OPEN;
  characterCount.textContent =
    `${Array.from(messageInput.value).length} / ${MAX_MESSAGE_LENGTH}`;
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
  messageList.querySelector(".welcome-card")?.remove();

  const wasNearBottom =
    messageList.scrollHeight - messageList.scrollTop - messageList.clientHeight < 110;

  const row = document.createElement("article");
  const isOwnMessage = message.sender?.id === clientId;
  row.className = isOwnMessage ? "message-row own" : "message-row";

  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.textContent = Array.from(message.sender?.userId ?? "U")[0] ?? "U";

  const content = document.createElement("div");
  content.className = "message-content";

  const meta = document.createElement("div");
  meta.className = "message-meta";

  const name = document.createElement("span");
  name.className = "message-name";
  name.textContent =
    isOwnMessage ? "あなた" : (message.sender?.userId ?? "ユーザー");

  const time = document.createElement("time");
  time.className = "message-time";
  time.dateTime = message.sentAt ?? "";
  time.textContent = formatTime(message.sentAt);

  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  // Treat all message content as text. Never inject user-controlled HTML.
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

function setAuthMode(mode) {
  authMode = mode;
  const registering = mode === "register";

  loginTab.classList.toggle("active", !registering);
  registerTab.classList.toggle("active", registering);
  loginTab.setAttribute("aria-selected", String(!registering));
  registerTab.setAttribute("aria-selected", String(registering));

  authTitle.textContent = registering ? "アカウントを作成" : "SecureChatへようこそ";
  authDescription.textContent = registering
    ? "新しいユーザーIDとパスワードを設定してください。"
    : "アカウントにログインしてください。";
  authSubmit.textContent = registering ? "アカウントを作成" : "ログイン";
  authPassword.autocomplete = registering ? "new-password" : "current-password";
  authPassword.minLength = registering ? 12 : 0;
  authPassword.placeholder = registering
    ? "12文字以上のパスワード"
    : "パスワードを入力";
  passwordHint.textContent = registering
    ? "12〜128文字。長くて推測されにくいパスワードを使ってください。"
    : "パスワードは大文字・小文字を区別します。";
  authError.textContent = "";
}

function showAuth(message = "") {
  authGate.hidden = false;
  authError.textContent = message;
  setConnectionState("disconnected", "ログインが必要です");
  authUserId.focus({ preventScroll: true });
}

function setSignedInUser(user) {
  currentUser = user;
  profileName.textContent = user.userId;
  profileAvatar.textContent = Array.from(user.userId)[0] ?? "U";
  authGate.hidden = true;
  authForm.reset();
  authError.textContent = "";
  shouldReconnect = true;
  connect();
  startAuthCheck();
}

function stopConnection() {
  shouldReconnect = false;
  window.clearTimeout(reconnectTimer);
  if (socket) {
    const activeSocket = socket;
    socket = null;
    activeSocket.close(1000, "Signed out");
  }
  clientId = null;
  setConnectionState("disconnected", "未接続");
}

async function checkCurrentSession() {
  const response = await fetch("/api/auth/me", {
    method: "GET",
    credentials: "same-origin",
    headers: { "Accept": "application/json" },
    cache: "no-store"
  });

  if (!response.ok) throw new Error("認証状態を確認できませんでした。");
  return response.json();
}

function startAuthCheck() {
  window.clearInterval(authCheckTimer);
  authCheckTimer = window.setInterval(async () => {
    if (!currentUser) return;

    try {
      const session = await checkCurrentSession();
      if (!session.authenticated) {
        currentUser = null;
        stopConnection();
        showAuth("セッションの有効期限が切れました。もう一度ログインしてください。");
      }
    } catch {
      showToast("認証サーバーに接続できません。");
    }
  }, 5 * 60 * 1000);
}

async function submitAuth(event) {
  event.preventDefault();
  const userId = authUserId.value.trim();
  const password = authPassword.value;
  const registering = authMode === "register";

  authError.textContent = "";

  if (!/^[a-zA-Z0-9_]{3,32}$/.test(userId)) {
    authError.textContent = "ユーザーIDは半角英数字・アンダースコアの3〜32文字にしてください。";
    return;
  }

  if (registering && Array.from(password).length < 12) {
    authError.textContent = "パスワードは12文字以上にしてください。";
    return;
  }

  if (!password || Array.from(password).length > 128) {
    authError.textContent = "パスワードを確認してください。";
    return;
  }

  authSubmit.disabled = true;
  authSubmit.textContent = registering ? "作成中…" : "ログイン中…";

  try {
    const response = await fetch(
      registering ? "/api/auth/register" : "/api/auth/login",
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({ userId, password })
      }
    );

    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(result.message ?? "認証に失敗しました。");
    }

    setSignedInUser(result.user);
    showToast(registering ? "アカウントを作成しました。" : "ログインしました。");
  } catch (error) {
    authError.textContent =
      error instanceof TypeError
        ? "サーバーに接続できません。時間をおいて再試行してください。"
        : error.message;
  } finally {
    authSubmit.disabled = false;
    authSubmit.textContent = authMode === "register" ? "アカウントを作成" : "ログイン";
  }
}

async function logout() {
  logoutButton.disabled = true;

  try {
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    });

    if (!response.ok) {
      throw new Error("ログアウトできませんでした。");
    }

    currentUser = null;
    window.clearInterval(authCheckTimer);
    stopConnection();
    messageInput.value = "";
    updateSendState();
    setAuthMode("login");
    showAuth();
    showToast("ログアウトしました。");
  } catch (error) {
    showToast(error.message);
  } finally {
    logoutButton.disabled = false;
  }
}

function connect() {
  if (!currentUser || !shouldReconnect) return;

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

  const activeSocket = socket;

  activeSocket.addEventListener("open", () => {
    reconnectDelay = 1_000;
    setConnectionState("connected", "接続中");
  });

  activeSocket.addEventListener("message", (event) => {
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

  activeSocket.addEventListener("close", () => {
    if (socket === activeSocket) socket = null;
    clientId = null;

    if (shouldReconnect && currentUser) {
      setConnectionState("disconnected", "再接続待ち");
      scheduleReconnect();
    } else {
      setConnectionState("disconnected", "未接続");
    }
  });

  activeSocket.addEventListener("error", () => {
    setConnectionState("disconnected", "通信エラー");
  });
}

function scheduleReconnect() {
  if (!shouldReconnect || !currentUser) return;
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
    text
  }));

  messageInput.value = "";
  messageInput.style.height = "auto";
  updateSendState();
  messageInput.focus();
}

loginTab.addEventListener("click", () => setAuthMode("login"));
registerTab.addEventListener("click", () => setAuthMode("register"));
authForm.addEventListener("submit", submitAuth);
logoutButton.addEventListener("click", logout);

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

async function bootstrap() {
  setAuthMode("login");
  setConnectionState("connecting", "認証確認中");

  try {
    const session = await checkCurrentSession();
    if (session.authenticated && session.user) {
      setSignedInUser(session.user);
    } else {
      showAuth();
    }
  } catch {
    showAuth("サーバーに接続できません。サーバーとデータベースの状態を確認してください。");
  }
}

bootstrap();
