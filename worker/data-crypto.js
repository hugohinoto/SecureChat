const encoder = new TextEncoder();
const MIN_KEY_BYTES = 32;
const DEFAULT_NOTICE_HOURS = 48;

function encode64(bytes) {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function decode64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
async function importDataKey(env) {
  const secret = env.APP_DATA_ENCRYPTION_KEY;
  if (typeof secret !== "string" || encoder.encode(secret).byteLength < MIN_KEY_BYTES) {
    throw new Error("APP_DATA_ENCRYPTION_KEY_NOT_CONFIGURED");
  }
  const material = await crypto.subtle.digest("SHA-256", encoder.encode("SecureChat/application-data/v1\0" + secret));
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
export async function encryptStored(env, context, plaintext) {
  const key = await importDataKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("securechat:v1:" + context), tagLength: 128 },
    key,
    encoder.encode(plaintext)
  );
  return "enc:v1:" + encode64(iv) + ":" + encode64(new Uint8Array(ciphertext));
}
export async function decryptStored(env, context, value) {
  if (typeof value !== "string" || !value.startsWith("enc:v1:")) return value ?? "";
  const parts = value.split(":");
  if (parts.length !== 4) throw new Error("ENCRYPTED_DATA_FORMAT_INVALID");
  const key = await importDataKey(env);
  const iv = decode64(parts[2]), ciphertext = decode64(parts[3]);
  if (iv.length !== 12 || ciphertext.length < 16) throw new Error("ENCRYPTED_DATA_FORMAT_INVALID");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("securechat:v1:" + context), tagLength: 128 },
    key,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}
export async function encryptAnnouncement(env, id, title, body) {
  const [titleCiphertext, bodyCiphertext] = await Promise.all([
    encryptStored(env, "announcement:" + id + ":title", title),
    encryptStored(env, "announcement:" + id + ":body", body)
  ]);
  return { titleCiphertext, bodyCiphertext };
}
export async function decodeAnnouncement(env, row) {
  const encrypted = Number(row.encryption_version) === 1;
  return {
    id: row.id,
    title: encrypted ? await decryptStored(env, "announcement:" + row.id + ":title", row.title_ciphertext) : row.title,
    body: encrypted ? await decryptStored(env, "announcement:" + row.id + ":body", row.body_ciphertext) : row.body,
    published: Number(row.published),
    created_at: row.created_at,
    updated_at: row.updated_at,
    published_at: row.published_at,
    expires_at: row.expires_at ?? (Number(row.published) === 1 && row.published_at ? Number(row.published_at) + DEFAULT_NOTICE_HOURS * 3600000 : null),
    encryption_version: encrypted ? 1 : 0
  };
}
export async function migrateSensitiveRows(env, now = Date.now()) {
  if (typeof env.APP_DATA_ENCRYPTION_KEY !== "string" || encoder.encode(env.APP_DATA_ENCRYPTION_KEY).byteLength < MIN_KEY_BYTES) return { skipped: true };
  let announcements = 0, auditLogs = 0;
  try {
    const notices = await env.DB.prepare(
      "SELECT id, title, body, published_at, published FROM announcements WHERE encryption_version=0 OR title_ciphertext IS NULL OR body_ciphertext IS NULL LIMIT 10"
    ).all();
    for (const row of notices.results || []) {
      const encrypted = await encryptAnnouncement(env, row.id, row.title, row.body);
      const expiresAt = Number(row.published) === 1 && row.published_at ? Number(row.published_at) + DEFAULT_NOTICE_HOURS * 3600000 : null;
      await env.DB.prepare(
        "UPDATE announcements SET title='[暗号化済み]', body='[暗号化済み]', title_ciphertext=?, body_ciphertext=?, encryption_version=1, expires_at=COALESCE(expires_at, ?) WHERE id=? AND (encryption_version=0 OR title_ciphertext IS NULL OR body_ciphertext IS NULL)"
      ).bind(encrypted.titleCiphertext, encrypted.bodyCiphertext, expiresAt, row.id).run();
      announcements += 1;
    }
    const logs = await env.DB.prepare("SELECT id, details_json FROM admin_audit_logs WHERE details_json NOT LIKE 'enc:v1:%' LIMIT 20").all();
    for (const row of logs.results || []) {
      const encrypted = await encryptStored(env, "admin-audit:" + row.id, row.details_json || "{}");
      await env.DB.prepare("UPDATE admin_audit_logs SET details_json=? WHERE id=? AND details_json=?")
        .bind(encrypted, row.id, row.details_json).run();
      auditLogs += 1;
    }
    await env.DB.prepare("DELETE FROM announcements WHERE published=1 AND expires_at IS NOT NULL AND expires_at<=?").bind(now).run();
    return { skipped: false, announcements, auditLogs };
  } catch {
    return { skipped: false, error: true };
  }
}
