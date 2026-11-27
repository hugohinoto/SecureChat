import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Japanese is the default and English is an available persisted locale", async () => {
  const source = await readFile(new URL("../public/i18n.js", import.meta.url), "utf8");
  assert.match(source, /I18N_STORAGE_KEY\s*=\s*"securechat-language"/);
  assert.match(source, /SUPPORTED_LOCALES\s*=\s*\["ja", "en", "zh", "ko", "es"\]/);
  assert.match(source, /return "ja";/);
  assert.match(source, /localStorage\.setItem\(I18N_STORAGE_KEY, next\)/);
});

test("All four UI surfaces include a language selector and set document language", async () => {
  for (const file of ["index.html", "secure-drop.html", "admin.html", "bug-report.html"]) {
    const html = await readFile(new URL("../public/" + file, import.meta.url), "utf8");
    assert.match(html, /<html lang="ja">/);
    assert.match(html, /data-language-selector/);
    assert.match(html, /<option value="ja">日本語<\/option>/);
    assert.match(html, /<option value="en">English<\/option>/);
    assert.match(html, /<option value="zh">简体中文<\/option>/);
    assert.match(html, /<option value="ko">한국어<\/option>/);
    assert.match(html, /<option value="es">Español<\/option>/);
  }
  const source = await readFile(new URL("../public/i18n.js", import.meta.url), "utf8");
  assert.match(source, /document\.documentElement\.lang\s*=\s*next/);
});

test("Static and dynamic surfaces reference shared translations", async () => {
  for (const file of ["app.js", "secure-drop-app.js", "admin.js", "bug-report.js"]) {
    const source = await readFile(new URL("../public/" + file, import.meta.url), "utf8");
    assert.match(source, /i18n\.js/);
  }
  const i18n = await readFile(new URL("../public/i18n.js", import.meta.url), "utf8");
  assert.match(i18n, /"title\.chat"/);
  assert.match(i18n, /"title\.secureDrop"/);
  assert.match(i18n, /"title\.admin"/);
  assert.match(i18n, /"title\.bugReport"/);
  assert.match(i18n, /securechat:localechange/);
});

test("Dynamic crypto, admin, and SecureDrop messages switch ja → en → ja", async () => {
  const saved = new Map();
  const previous = {
    localStorage: Object.getOwnPropertyDescriptor(globalThis, "localStorage"),
    document: Object.getOwnPropertyDescriptor(globalThis, "document"),
    NodeFilter: Object.getOwnPropertyDescriptor(globalThis, "NodeFilter"),
    CustomEvent: Object.getOwnPropertyDescriptor(globalThis, "CustomEvent")
  };
  globalThis.localStorage = {
    getItem: key => saved.get(key) ?? null,
    setItem: (key, value) => saved.set(key, value)
  };
  globalThis.document = {
    documentElement: { lang:"ja" },
    querySelectorAll: () => [],
    createTreeWalker: () => ({ nextNode: () => false }),
    dispatchEvent: () => true
  };
  globalThis.NodeFilter = { SHOW_TEXT:4 };
  globalThis.CustomEvent = class { constructor(type, options) { this.type=type;this.detail=options.detail; } };
  try {
    const i18n = await import("../public/i18n.js?dynamic-locale-test");
    const samples = [
      ["前方秘匿性v2有効 — Olm Double Ratchetで鍵配送、Megolm鍵は1メッセージごとに更新",
        "Forward secrecy v2 enabled — keys delivered with Olm Double Ratchet; Megolm keys rotate for every message"],
      ["お知らせを削除しました。", "Announcement deleted."],
      ["保存ファイルの整合性を確認できませんでした。", "Could not verify the stored file's integrity."],
      ["報告を暗号化して送信しました。ご協力ありがとうございます。",
        "The report was encrypted and submitted. Thank you."]
    ];
    assert.equal(i18n.getLocale(), "ja");
    i18n.setLocale("en");
    assert.equal(saved.get("securechat-language"), "en");
    assert.equal(document.documentElement.lang, "en");
    for (const [japanese, english] of samples) {
      assert.equal(i18n.translateText(japanese), english);
      assert.equal(i18n.translateText(japanese, "ja"), japanese);
    }
    i18n.setLocale("ja");
    assert.equal(saved.get("securechat-language"), "ja");
    assert.equal(document.documentElement.lang, "ja");
    assert.equal(i18n.getLocale(), "ja");
    assert.equal(i18n.translateText(samples[0][1]), samples[0][0]);

    // Korean must not inherit the English fallback, and switching from an
    // already translated DOM value must restore the original source first.
    i18n.setLocale("ko");
    assert.equal(i18n.translateText("チャット"), "채팅");
    assert.equal(i18n.translateText("Chat"), "채팅");
    assert.equal(i18n.translateText("채팅", "ja"), "チャット");
    assert.equal(i18n.translateText("未ログイン"), "未ログイン");
    assert.equal(i18n.translateText("채팅", "en"), "Chat");
    i18n.setLocale("en");
    assert.equal(i18n.translateText("채팅"), "Chat");
    i18n.setLocale("ja");
    assert.equal(i18n.translateText("Chat"), "チャット");
  } finally {
    for (const [key, descriptor] of Object.entries(previous)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
});


test("MutationObserver translation cannot observe its own attribute writes", async () => {
  const source = await readFile(new URL("../public/i18n.js", import.meta.url), "utf8");
  assert.match(source, /if \(translated !== value\) element\.setAttribute\(attribute, translated\)/);
  assert.match(source, /observer\.observe\(document\.documentElement, \{ childList:true, characterData:true, subtree:true \}\)/);
  assert.doesNotMatch(source, /observer\.observe\(document\.documentElement, \{[^}]*attributes:true/);
});
