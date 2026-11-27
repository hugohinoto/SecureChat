import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const refreshCss = readFileSync(new URL("../public/ui-refresh.css", import.meta.url), "utf8");

test("refreshed UI stylesheet is loaded after the legacy stylesheet", () => {
  const legacy = html.indexOf('href="/styles.css"');
  const refreshed = html.indexOf('href="/ui-refresh.css"');
  assert.notEqual(legacy, -1);
  assert.notEqual(refreshed, -1);
  assert.ok(refreshed > legacy);
});

test("all static DOM IDs referenced by the application remain present", () => {
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
  const selectors = [...app.matchAll(/\$\("#([^"]+)"\)/g)].map(match => match[1]);
  assert.ok(selectors.length > 0, "expected to find application DOM selectors");
  const missing = [...new Set(selectors)].filter(id => !ids.has(id));
  assert.deepEqual(missing, []);
});

test("refreshed UI includes keyboard focus, reduced-motion, and mobile navigation styles", () => {
  assert.match(refreshCss, /:focus-visible/);
  assert.match(refreshCss, /prefers-reduced-motion/);
  assert.match(refreshCss, /body\.mobile-chat/);
  assert.match(refreshCss, /body\.mobile-list/);
});

test("UI labels legacy v1 history honestly and blocks new sends during migration", () => {
  const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(html, /暗号化方式は会話ごとに異なります/);
  assert.match(html, /暗号実装は未監査のため/);
  assert.match(app, /旧方式 v1 — 履歴の復号専用/);
  assert.match(app, /v1は会話単位の長期鍵を使用し、前方秘匿性はありません/);
  assert.match(app, /この会話から新規送信はできません/);
  assert.match(app, /前方秘匿性v2 — 端末別暗号化/);
});

test("device-scoped crypto vault uses a single IndexedDB readwrite transaction", () => {
  const cryptoClient = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");
  const creation = cryptoClient.slice(
    cryptoClient.indexOf("async function createDeviceVault"),
    cryptoClient.indexOf("async function api(")
  );
  assert.ok(creation.includes('db.transaction(VAULT_STORE, "readwrite")'));
  assert.ok(creation.includes("store.get(userId)"));
  assert.ok(creation.includes("store.add(candidate)"));
  assert.equal(creation.includes("await readVault(userId)"), false);
});

test("device revocation controls are present and the current device cannot be revoked", () => {
  const cryptoClient = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");
  assert.match(html, /id="device-manage-sidebar-button"/);
  assert.match(html, /id="crypto-v2-device-list"/);
  assert.match(cryptoClient, /CRYPTO_CANNOT_REVOKE_CURRENT_DEVICE/);
  assert.ok(cryptoClient.includes("org.securechat.device_revoked"));
});

test("crypto v2 requires an exclusive Web Lock for each browser-profile device", () => {
  const cryptoClient = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");
  assert.ok(cryptoClient.includes("globalThis.navigator?.locks"));
  assert.ok(cryptoClient.includes('mode: "exclusive", ifAvailable: true'));
  assert.ok(cryptoClient.includes("CRYPTO_DEVICE_ALREADY_OPEN_IN_ANOTHER_TAB"));
  assert.ok(cryptoClient.includes("CRYPTO_CROSS_TAB_LOCK_UNAVAILABLE"));
});

test("v2 conversations cannot silently fall back to v1 in a tab without device ownership", () => {
  assert.ok(app.includes('/api/crypto/conversations/"+encodeURIComponent(activeConversation.id)+"/mode'));
  assert.ok(app.includes("このタブでは端末鍵を開けていないため送信・復号できません"));
  assert.ok(app.includes("await closeCryptoV2Session()"));
});


test("chat login form stays hidden while the existing session and chat state initialize", () => {
  assert.match(html, /id="auth-loading"[^>]*role="status"/);
  assert.match(html, /id="auth-gate"[^>]*hidden>/);
  assert.match(app, /authLoading: \$\("#auth-loading"\)/);
  assert.match(app, /el\.authLoading\.hidden=true;\s*showAuth\(\);/);
  assert.match(app, /await signIn\(session\.user\);\s*el\.authLoading\.hidden=true;/);
  assert.match(refreshCss, /\.auth-loading\[hidden\] \{ display: none; \}/);
});


test("device registration and account-wide sync run automatically after login", () => {
  assert.match(html, /id="device-manage-sidebar-button"/);
  assert.doesNotMatch(html, /device-register-all-button|crypto-v2-devices-toggle|sidebar-device-status|全チャットを今すぐ同期/);
  assert.match(app, /runAutomaticCryptoMaintenance\(\{force:true\}\)/);
  assert.doesNotMatch(app, /registerDeviceAcrossAllChats|deviceRegisterAll/);
});

test("automatic account-wide key exchange can run when V2 enforcement is optional", () => {
  assert.match(app, /async function runAutomaticCryptoMaintenance\(\{ force = false \} = \{\}\)/);
  assert.match(app, /\(!cryptoV2Required && !force\)/);
});


test("connection status reflects a real health check instead of a placeholder ready label", () => {
  assert.match(app, /async function refreshConnectionStatus\(\)/);
  assert.match(app, /api\("\/api\/health"\)/);
  assert.match(app, /state\("connected", "オンライン"\)/);
  assert.match(app, /state\("offline", "オフライン・ローカル表示"\)/);
  assert.match(app, /el\.connection\.dataset\.state !== "connected"/);
  assert.doesNotMatch(app, /準備完了/);
  assert.match(readFileSync(new URL("../public/styles.css", import.meta.url), "utf8"), /data-state="offline"/);
});

test("an already loaded chat remains available offline without polling or discarding its current view", () => {
  assert.match(app, /window\.addEventListener\("offline"/);
  assert.match(app, /window\.addEventListener\("online"/);
  assert.match(app, /if\(!navigator\.onLine \|\| !activeConversation \|\| messageLoadBusy\)return/);
  assert.match(app, /if\(!navigator\.onLine\) \{/);
  assert.match(app, /オフライン中です。下書きはこの画面に残ります/);
});

test("sidebar is not rebuilt when switching conversations or browser tabs", () => {
  assert.doesNotMatch(app, /sidebarRefreshTick/);
  const selectStart = app.indexOf("async function selectConversation(c)");
  const selectEnd = app.indexOf("async function loadMessages", selectStart);
  assert.ok(selectStart >= 0 && selectEnd > selectStart);
  assert.doesNotMatch(app.slice(selectStart, selectEnd), /refreshSidebar\(\)/);
  assert.match(app, /b\.dataset\.conversationId=String\(c\.id\)/);
  assert.match(app, /button\.classList\.toggle\("active", button\.dataset\.conversationId === String\(c\.id\)\)/);
  const focusStart = app.indexOf('window.addEventListener("focus",()=>');
  const focusEnd = app.indexOf('document.addEventListener("visibilitychange",()=>', focusStart);
  assert.ok(focusStart >= 0 && focusEnd > focusStart);
  assert.doesNotMatch(app.slice(focusStart, focusEnd), /refreshSidebar\(\)/);
  assert.match(app, /window\.addEventListener\("online"[\s\S]*?refreshSidebar\(\)/);
});


test("a valid account login is not rolled back when this device cannot restore its identity key", () => {
  const signInStart=app.indexOf("async function signIn(user,password=null)");
  const signInEnd=app.indexOf("function startAuthCheck()",signInStart);
  const signIn=app.slice(signInStart,signInEnd);
  assert.match(signIn,/let identitySetupFailure=null/);
  assert.match(signIn,/await ensureIdentity\(password\)/);
  assert.match(signIn,/identitySetupFailure=error/);
  assert.match(signIn,/await refreshSidebar\(\)/);
  assert.doesNotMatch(signIn,/currentUser=null/);
  assert.match(signIn,/identitySetupPanel/);
});

test("missing identity keys lock sending instead of allowing plaintext or legacy fallback", () => {
  assert.match(app,/el\.input\.disabled = !currentUser \|\| !identityPrivateKey/);
  assert.match(app,/!identityPrivateKey \|\| \(activeProtocolVersion===2 && !cryptoV2Ready\)/);
});

test("identity recovery requires the account password and retries automatic device registration", () => {
  assert.match(html,/id="identity-setup-panel"/);
  assert.match(html,/id="identity-retry-password"/);
  assert.match(app,/async function retryIdentitySetup\(\)/);
  assert.match(app,/await ensureIdentity\(password\)/);
  assert.match(app,/await runAutomaticCryptoMaintenance\(\{force:true\}\)/);
  assert.match(app,/async function retryCryptoDeviceInitialization\(\)/);
  assert.match(app,/window\.addEventListener\("online",[\s\S]*?await retryCryptoDeviceInitialization\(\)/);
});

test("desktop sidebar stays pinned while the document scrolls, without changing mobile navigation", () => {
  const css=readFileSync(new URL("../public/styles.css",import.meta.url),"utf8");
  assert.match(css,/@media\s*\(min-width:\s*681px\)[\s\S]*?\.sidebar\s*\{[^}]*position:\s*sticky;[^}]*top:\s*21px/);
  assert.match(css,/body\.mobile-chat \.sidebar \{ display: none !important; \}/);
});

test("sidebar DOM is not rebuilt on tab focus or visibility changes", () => {
  const focusStart=app.indexOf('window.addEventListener("focus",()=>');
  const focusEnd=app.indexOf('document.addEventListener("visibilitychange"',focusStart);
  assert.doesNotMatch(app.slice(focusStart,focusEnd),/refreshSidebar\(\)/);
  const visibilityStart=app.indexOf('document.addEventListener("visibilitychange",()=>');
  const visibilityEnd=app.indexOf('async function bootstrap()',visibilityStart);
  assert.doesNotMatch(app.slice(visibilityStart,visibilityEnd),/refreshSidebar\(\)/);
});
