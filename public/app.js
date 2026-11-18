const $ = (s) => document.querySelector(s);
const el = {
  connection: $("#connection-pill"), connectionLabel: $("#connection-label"),
  list: $("#message-list"), input: $("#message-input"), send: $("#send-button"),
  count: $("#character-count"), profile: $("#profile-name"), avatar: $("#profile-avatar"),
  logout: $("#logout-button"), toast: $("#toast"), gate: $("#auth-gate"),
  form: $("#auth-form"), title: $("#auth-title"), description: $("#auth-description"),
  error: $("#auth-error"), submit: $("#auth-submit"), user: $("#auth-user-id"),
  password: $("#auth-password"), passwordHint: $("#password-hint"),
  loginTab: $("#login-tab"), registerTab: $("#register-tab"),
  search: $("#user-search-input"), searchButton: $("#user-search-button"),
  results: $("#user-search-results"), contacts: $("#contact-list"),
  conversations: $("#conversation-list"), contactCount: $("#contact-count"),
  conversationCount: $("#conversation-count"), chatTitle: $("#chat-title"),
  chatSubtitle: $("#chat-subtitle"), securityTitle: $("#security-title"),
  securityDescription: $("#security-description"), securityTag: $("#security-tag"),
  composerHint: $("#composer-hint")
};
const MAX_MESSAGE_LENGTH = 2000;
const DB_NAME = "securechat-local-keys";
const STORE = "identity";
let currentUser = null, authMode = "login", toastTimer = null, authTimer = null;
let identityPrivateKey = null, identityPublicKey = null;
let activeConversation = null, activeKey = null, busy = false, refreshTimer = null;

function toast(message) {
  el.toast.textContent = message;
  el.toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.toast.classList.remove("visible"), 3200);
}
function state(value, label) {
  el.connection.dataset.state = value;
  el.connectionLabel.textContent = label;
  updateSend();
}
function updateSend() {
  el.count.textContent = Array.from(el.input.value).length + " / " + MAX_MESSAGE_LENGTH;
  el.input.disabled = !currentUser || !activeConversation || busy;
  el.send.disabled = !currentUser || !activeConversation || busy || !el.input.value.trim();
}
function time(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : new Intl.DateTimeFormat("ja-JP", {hour:"2-digit",minute:"2-digit"}).format(date);
}
function openKeyDb() {
  return new Promise((resolve,reject) => {
    const req = indexedDB.open(DB_NAME,1);
    req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE,{keyPath:"userId"}); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function storedIdentity(userId) {
  const db=await openKeyDb();
  return new Promise((resolve,reject)=>{
    const req=db.transaction(STORE,"readonly").objectStore(STORE).get(userId);
    req.onsuccess=()=>{db.close();resolve(req.result||null);};
    req.onerror=()=>{db.close();reject(req.error);};
  });
}
async function saveIdentity(userId,record) {
  const db=await openKeyDb();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).put(Object.assign({userId},record));
    tx.oncomplete=()=>{db.close();resolve();};
    tx.onerror=()=>{db.close();reject(tx.error);};
  });
}
function toB64(bytes) {
  let s=""; for(const b of bytes)s+=String.fromCharCode(b); return btoa(s);
}
function fromB64(s) { return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }

async function api(path, options={}) {
  const response=await fetch(path,{
    method:options.method||"GET",credentials:"same-origin",cache:"no-store",
    headers:Object.assign({Accept:"application/json"},options.body?{"Content-Type":"application/json"}:{}),
    ...(options.body?{body:JSON.stringify(options.body)}:{})
  });
  const data=response.status===204?{}:await response.json().catch(()=>({}));
  if(!response.ok) {
    const known={
      USER_NOT_FOUND:"そのユーザーIDは見つかりません。",
      RECIPIENT_KEY_MISSING:"相手がまだ公開鍵を登録していません。相手に一度ログインしてもらってください。",
      CONVERSATION_NOT_FOUND:"チャットが見つかりません。"
    };
    throw new Error(known[data.error]||data.message||("通信エラー ("+response.status+")"));
  }
  return data;
}
async function ensureIdentity() {
  const saved=await storedIdentity(currentUser.userId);
  if(saved && saved.privateKey && saved.publicKey) {
    identityPrivateKey=saved.privateKey;
    identityPublicKey=saved.publicKey;
  } else {
    const pair=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
    const raw=await crypto.subtle.exportKey("raw",pair.publicKey);
    identityPrivateKey=pair.privateKey;
    identityPublicKey=toB64(new Uint8Array(raw));
    await saveIdentity(currentUser.userId,{privateKey:identityPrivateKey,publicKey:identityPublicKey});
  }
  await api("/api/keys",{method:"PUT",body:{identityPublicKey}});
}
async function deriveKey(conversationId,peerUserId) {
  if(activeKey && activeConversation && activeConversation.id===conversationId)return activeKey;
  const peer=await api("/api/keys/"+encodeURIComponent(peerUserId));
  const pub=await crypto.subtle.importKey("raw",fromB64(peer.identityPublicKey),{name:"ECDH",namedCurve:"P-256"},false,[]);
  const bits=await crypto.subtle.deriveBits({name:"ECDH",public:pub},identityPrivateKey,256);
  const material=await crypto.subtle.importKey("raw",bits,"HKDF",false,["deriveKey"]);
  const salt=await crypto.subtle.digest("SHA-256",new TextEncoder().encode("SecureChat salt:"+conversationId));
  activeKey=await crypto.subtle.deriveKey({
    name:"HKDF",hash:"SHA-256",salt,
    info:new TextEncoder().encode("SecureChat E2EE prototype v1:"+conversationId)
  },material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  return activeKey;
}
async function encryptText(text,key) {
  const nonce=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce},key,new TextEncoder().encode(text));
  return {ciphertext:toB64(new Uint8Array(cipher)),nonce:toB64(nonce),algorithm:"AES-GCM-256"};
}
async function decryptText(message,key) {
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:fromB64(message.nonce)},key,fromB64(message.ciphertext));
  return new TextDecoder().decode(plain);
}
function welcome(title,description) {
  el.list.replaceChildren();
  const card=document.createElement("div"); card.className="welcome-card";
  const h=document.createElement("h2"); h.textContent=title;
  const p=document.createElement("p"); p.textContent=description;
  card.append(h,p); el.list.append(card);
}
function appendMessage(text,senderId,createdAt,expiresAt) {
  el.list.querySelector(".welcome-card")?.remove();
  const own=senderId===currentUser.id;
  const row=document.createElement("article"); row.className=own?"message-row own":"message-row";
  const avatar=document.createElement("div"); avatar.className="message-avatar";
  avatar.textContent=Array.from(own?currentUser.userId:activeConversation.peerUserId)[0]||"U";
  const content=document.createElement("div"); content.className="message-content";
  const meta=document.createElement("div"); meta.className="message-meta";
  const name=document.createElement("span"); name.className="message-name";
  name.textContent=own?"あなた":activeConversation.peerUserId;
  const stamp=document.createElement("time"); stamp.className="message-time";
  stamp.textContent=time(createdAt)+" · "+Math.max(0,Math.ceil((expiresAt-Date.now())/60000))+"分後に削除";
  const bubble=document.createElement("div"); bubble.className="message-bubble"; bubble.textContent=text;
  meta.append(name,stamp); content.append(meta,bubble); row.append(avatar,content); el.list.append(row);
}
function setAuthMode(mode) {
  authMode=mode; const registering=mode==="register";
  el.loginTab.classList.toggle("active",!registering); el.registerTab.classList.toggle("active",registering);
  el.loginTab.setAttribute("aria-selected",String(!registering));
  el.registerTab.setAttribute("aria-selected",String(registering));
  el.title.textContent=registering?"アカウントを作成":"SecureChatへようこそ";
  el.description.textContent=registering?"新しいユーザーIDとパスワードを設定してください。":"アカウントにログインしてください。";
  el.submit.textContent=registering?"アカウントを作成":"ログイン";
  el.password.autocomplete=registering?"new-password":"current-password";
  el.password.minLength=registering?12:0;
  el.passwordHint.textContent=registering?"12〜128文字。長くて推測されにくいパスワードを使ってください。":"パスワードは大文字・小文字を区別します。";
  el.error.textContent="";
}
function showAuth(message="") { el.gate.hidden=false; el.error.textContent=message; state("disconnected","ログインが必要です"); }
async function checkSession() {
  const r=await fetch("/api/auth/me",{credentials:"same-origin",cache:"no-store",headers:{Accept:"application/json"}});
  if(!r.ok)throw new Error("認証状態を確認できませんでした。");
  return r.json();
}
async function signIn(user) {
  currentUser=user; el.profile.textContent=user.userId; el.avatar.textContent=Array.from(user.userId)[0]||"U";
  el.gate.hidden=true; el.form.reset();
  await ensureIdentity(); await refreshSidebar();
  state("connected","準備完了");
  startAuthCheck();
  clearInterval(refreshTimer);
  refreshTimer=setInterval(()=>{if(activeConversation)loadMessages().catch(()=>{});refreshSidebar().catch(()=>{});},15000);
}
function startAuthCheck() {
  clearInterval(authTimer);
  authTimer=setInterval(async()=>{
    try { const s=await checkSession(); if(!s.authenticated){currentUser=null;showAuth("セッションの有効期限が切れました。再ログインしてください。");} }
    catch {toast("認証サーバーに接続できません。");}
  },300000);
}
async function submitAuth(event) {
  event.preventDefault();
  const userId=el.user.value.trim(),password=el.password.value,registering=authMode==="register";
  el.error.textContent="";
  if(!/^[a-zA-Z0-9_]{3,32}$/.test(userId)){el.error.textContent="ユーザーIDは半角英数字・アンダースコアの3〜32文字にしてください。";return;}
  if(registering&&Array.from(password).length<12){el.error.textContent="パスワードは12文字以上にしてください。";return;}
  if(!password||Array.from(password).length>128){el.error.textContent="パスワードを確認してください。";return;}
  el.submit.disabled=true;
  try {
    const data=await api(registering?"/api/auth/register":"/api/auth/login",{method:"POST",body:{userId,password}});
    await signIn(data.user); toast(registering?"アカウントを作成しました。":"ログインしました。");
  } catch(e) {el.error.textContent=e.message;}
  finally {el.submit.disabled=false;el.submit.textContent=authMode==="register"?"アカウントを作成":"ログイン";}
}
async function logout() {
  el.logout.disabled=true;
  try {
    await api("/api/auth/logout",{method:"POST"});
    currentUser=null;identityPrivateKey=null;identityPublicKey=null;activeConversation=null;activeKey=null;
    clearInterval(authTimer);clearInterval(refreshTimer);setAuthMode("login");showAuth();toast("ログアウトしました。");
  } catch(e) {toast(e.message);}
  finally {el.logout.disabled=false;}
}
function userAction(userId,label,fn) {
  const row=document.createElement("div");row.className="user-result";
  const name=document.createElement("span");name.textContent=userId;
  const button=document.createElement("button");button.type="button";button.textContent=label;button.addEventListener("click",fn);
  row.append(name,button);return row;
}
async function searchUsers() {
  const q=el.search.value.trim().toLowerCase();el.results.replaceChildren();
  if(!/^[a-z0-9_]{1,32}$/.test(q)){el.results.textContent="1文字以上のユーザーIDを入力してください。";return;}
  try {
    const data=await api("/api/users/search?q="+encodeURIComponent(q));
    if(!data.users.length){el.results.textContent="ユーザーが見つかりませんでした。";return;}
    for(const user of data.users)el.results.append(userAction(user.userId,"追加",async()=>{
      try {await api("/api/contacts/add",{method:"POST",body:{userId:user.userId}});toast(user.userId+"を連絡先に追加しました。");await refreshSidebar();el.results.replaceChildren();}
      catch(e){toast(e.message);}
    }));
  } catch(e){el.results.textContent=e.message;}
}
async function refreshSidebar() {
  const data=await Promise.all([api("/api/contacts"),api("/api/conversations")]);
  const contacts=data[0].contacts||[],conversations=data[1].conversations||[];
  el.contactCount.textContent=String(contacts.length);el.conversationCount.textContent=String(conversations.length);
  el.contacts.replaceChildren();el.conversations.replaceChildren();
  if(!contacts.length){const p=document.createElement("p");p.className="sidebar-empty";p.textContent="連絡先はまだありません。";el.contacts.append(p);}
  for(const c of contacts){
    const b=document.createElement("button");b.type="button";b.className="sidebar-user-button";b.textContent=c.userId;
    b.addEventListener("click",()=>openConversation(c.userId));el.contacts.append(b);
  }
  if(!conversations.length){const p=document.createElement("p");p.className="sidebar-empty";p.textContent="チャットはまだありません。";el.conversations.append(p);}
  for(const c of conversations){
    const b=document.createElement("button");b.type="button";b.className="sidebar-user-button";b.textContent=c.peer_user_id;
    b.classList.toggle("active",activeConversation?.id===c.id);b.addEventListener("click",()=>selectConversation(c));el.conversations.append(b);
  }
}
async function openConversation(peerUserId) {
  try {
    const result=await api("/api/conversations",{method:"POST",body:{recipientUserId:peerUserId}});
    await refreshSidebar();
    await selectConversation({id:result.conversationId,peer_user_id:peerUserId});
  } catch(e){toast(e.message);}
}
async function selectConversation(c) {
  activeConversation={id:c.id,peerUserId:c.peer_user_id};activeKey=null;
  el.chatTitle.textContent=c.peer_user_id;el.chatSubtitle.textContent="@"+c.peer_user_id+" · 1対1の個別チャット";
  el.securityTitle.textContent="暗号化チャット（試作）";
  el.securityDescription.textContent="ECDH P-256 + HKDF + AES-GCM。公開鍵の本人確認と前方秘匿性は未実装です。";
  el.securityTag.textContent="E2EE PROTOTYPE";
  el.composerHint.textContent="端末内で暗号化 · メッセージは1時間後に削除";
  welcome("暗号化チャット","このブラウザーで暗号化してから送信します。");
  updateSend();
  try {await deriveKey(c.id,c.peer_user_id);await loadMessages();updateSend();}
  catch(e){toast("暗号鍵を準備できません: "+e.message);el.input.disabled=true;}
  await refreshSidebar();
}
async function loadMessages() {
  if(!activeConversation)return;
  const id=activeConversation.id,peer=activeConversation.peerUserId,key=await deriveKey(id,peer);
  const data=await api("/api/conversations/"+id+"/messages");
  if(!activeConversation||activeConversation.id!==id)return;
  el.list.replaceChildren();
  if(!data.messages.length){welcome("最初のメッセージを送ろう","メッセージは送信から1時間で削除されます。");return;}
  for(const m of data.messages){
    try {appendMessage(await decryptText(m,key),m.sender_user_id,m.created_at,m.expires_at);}
    catch {appendMessage("復号できません（鍵が一致しない可能性があります）。",m.sender_user_id,m.created_at,m.expires_at);}
  }
  el.list.scrollTop=el.list.scrollHeight;
}
async function sendMessage() {
  if(busy||!activeConversation)return;
  const text=el.input.value.trim();if(!text)return;
  if(Array.from(text).length>MAX_MESSAGE_LENGTH){toast("メッセージは2000文字以内にしてください。");return;}
  busy=true;updateSend();
  try {
    const key=await deriveKey(activeConversation.id,activeConversation.peerUserId);
    const encrypted=await encryptText(text,key);
    await api("/api/conversations/"+activeConversation.id+"/messages",{method:"POST",body:encrypted});
    el.input.value="";el.input.style.height="auto";await loadMessages();
  } catch(e){toast(e.message);}
  finally {busy=false;updateSend();el.input.focus();}
}
el.loginTab.addEventListener("click",()=>setAuthMode("login"));
el.registerTab.addEventListener("click",()=>setAuthMode("register"));
el.form.addEventListener("submit",submitAuth);
el.logout.addEventListener("click",logout);
el.searchButton.addEventListener("click",searchUsers);
el.search.addEventListener("keydown",e=>{if(e.key==="Enter")searchUsers();});
el.input.addEventListener("input",()=>{el.input.style.height="auto";el.input.style.height=Math.min(el.input.scrollHeight,125)+"px";updateSend();});
el.input.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey&&!e.isComposing){e.preventDefault();sendMessage();}});
el.send.addEventListener("click",sendMessage);

async function bootstrap() {
  setAuthMode("login");state("connecting","認証確認中");
  try {
    const session=await checkSession();
    if(!session.authenticated||!session.user){showAuth();return;}
    await signIn(session.user);
  } catch(e){showAuth("初期化できませんでした: "+e.message);}
}
bootstrap();
