import test from "node:test";
import assert from "node:assert/strict";
import {
  clearSessionCookie,
  createPasswordRecord,
  createSessionToken,
  hashSessionToken,
  normalizeUserId,
  readSessionToken,
  sessionCookieName,
  setSessionCookie,
  validatePassword,
  verifyPassword
} from "../server/auth.js";

test("normalizes valid user IDs", () => {
  assert.equal(normalizeUserId("Hugo_01"), "hugo_01");
  assert.equal(normalizeUserId("abc123"), "abc123");
});

test("rejects invalid user IDs", () => {
  for (const value of ["ab", "has space", "name@example.com", "日本語", "a".repeat(33), null]) {
    assert.equal(normalizeUserId(value), null);
  }
});

test("enforces password length and byte constraints", () => {
  assert.equal(validatePassword("short"), false);
  assert.equal(validatePassword("correct horse battery staple"), true);
  assert.equal(validatePassword("あ".repeat(129)), false);
  assert.equal(validatePassword(""), false);
});

test("uses unique salts and verifies only the matching password", async () => {
  const password = "correct horse battery staple 2026";
  const first = await createPasswordRecord(password);
  const second = await createPasswordRecord(password);

  assert.match(first.salt, /^[a-f0-9]{32}$/);
  assert.match(first.hash, /^[a-f0-9]{128}$/);
  assert.notEqual(first.salt, second.salt);
  assert.notEqual(first.hash, second.hash);

  assert.equal(await verifyPassword(password, first.salt, first.hash), true);
  assert.equal(await verifyPassword("wrong password", first.salt, first.hash), false);
  assert.equal(await verifyPassword(password, undefined, undefined), false);
});

test("stores only a digest of an opaque session token", () => {
  const first = createSessionToken();
  const second = createSessionToken();

  assert.match(first, /^[A-Za-z0-9_-]{40,60}$/);
  assert.notEqual(first, second);
  assert.match(hashSessionToken(first), /^[a-f0-9]{64}$/);
  assert.notEqual(hashSessionToken(first), first);
});

test("sets secure session-cookie attributes and parses the token", () => {
  const response = {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; }
  };
  const token = createSessionToken();

  setSessionCookie(response, token, true);
  const cookie = response.headers["Set-Cookie"];

  assert.match(cookie, new RegExp(`^${sessionCookieName(true)}=${token};`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Secure/);
  assert.ok(cookie.includes("; Path=/;"));
  assert.equal(readSessionToken(cookie.split(";")[0], true), token);

  clearSessionCookie(response, true);
  assert.match(response.headers["Set-Cookie"], /Max-Age=0/);
});
