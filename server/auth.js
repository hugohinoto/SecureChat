import {
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
export const USER_ID_PATTERN = /^[a-z0-9_]{3,32}$/;
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

const PASSWORD_KEY_LENGTH = 64;
const SCRYPT_OPTIONS = {
  N: 32_768,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024
};
const DUMMY_SALT = Buffer.from("c2VjdXJlY2hhdC1kdW1teS1zYWx0LTAx", "base64");
const DUMMY_HASH = Buffer.alloc(PASSWORD_KEY_LENGTH, 0);

export function normalizeUserId(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return USER_ID_PATTERN.test(normalized) ? normalized : null;
}

export function validatePassword(value) {
  if (typeof value !== "string") return false;
  const length = Array.from(value).length;
  return (
    length >= PASSWORD_MIN_LENGTH &&
    length <= PASSWORD_MAX_LENGTH &&
    Buffer.byteLength(value, "utf8") <= 512
  );
}

export async function derivePasswordHash(password, salt) {
  return scrypt(
    Buffer.from(password, "utf8"),
    salt,
    PASSWORD_KEY_LENGTH,
    SCRYPT_OPTIONS
  );
}

export async function createPasswordRecord(password) {
  const salt = randomBytes(16);
  const hash = await derivePasswordHash(password, salt);

  return {
    salt: salt.toString("hex"),
    hash: hash.toString("hex")
  };
}

export async function verifyPassword(password, saltHex, hashHex) {
  let salt = DUMMY_SALT;
  let expectedHash = DUMMY_HASH;

  if (
    typeof saltHex === "string" &&
    /^[a-f0-9]{32}$/i.test(saltHex) &&
    typeof hashHex === "string" &&
    /^[a-f0-9]{128}$/i.test(hashHex)
  ) {
    salt = Buffer.from(saltHex, "hex");
    expectedHash = Buffer.from(hashHex, "hex");
  }

  const actualHash = await derivePasswordHash(password, salt);
  const matches = timingSafeEqual(actualHash, expectedHash);

  return Boolean(
    matches &&
    typeof saltHex === "string" &&
    typeof hashHex === "string"
  );
}

export function createSessionToken() {
  return randomBytes(32).toString("base64url");
}

export function hashSessionToken(token) {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function sessionCookieName(isProduction = process.env.NODE_ENV === "production") {
  return isProduction ? "__Host-sc_session" : "sc_session";
}

export function readSessionToken(cookieHeader, isProduction = process.env.NODE_ENV === "production") {
  if (typeof cookieHeader !== "string") return null;

  const cookieName = sessionCookieName(isProduction);
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;

    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (name === cookieName && /^[A-Za-z0-9_-]{40,60}$/.test(value)) {
      return value;
    }
  }

  return null;
}

export function setSessionCookie(response, token, isProduction = process.env.NODE_ENV === "production") {
  const secure = isProduction ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `${sessionCookieName(isProduction)}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secure}`
  );
}

export function clearSessionCookie(response, isProduction = process.env.NODE_ENV === "production") {
  const secure = isProduction ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `${sessionCookieName(isProduction)}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`
  );
}

export async function createDatabaseSession(database, userId) {
  const token = createSessionToken();
  const tokenHash = hashSessionToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);

  await database.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, $3)`,
    [tokenHash, userId, expiresAt]
  );

  return token;
}

export async function findDatabaseSession(database, token) {
  if (!token) return null;

  const tokenHash = hashSessionToken(token);
  const result = await database.query(
    `SELECT users.id, users.user_id, sessions.expires_at
       FROM sessions
       JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = $1
        AND sessions.expires_at > NOW()
      LIMIT 1`,
    [tokenHash]
  );

  return result.rows[0] ?? null;
}

export async function deleteDatabaseSession(database, token) {
  if (!token) return;

  await database.query(
    "DELETE FROM sessions WHERE token_hash = $1",
    [hashSessionToken(token)]
  );
}
