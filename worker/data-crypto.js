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
function configuredSecret(env, version) {
  const named = env["APP_DATA_ENCRYPTION_KEY_V" + version];
  if (typeof named === "string" && encoder.encode(named).byteLength >= MIN_KEY_BYTES) return named;
  if (version === 1 && typeof env.APP_DATA_ENCRYPTION_KEY === "string" && encoder.encode(env.APP_DATA_ENCRYPTION_KEY).byteLength >= MIN_KEY_BYTES) return env.APP_DATA_ENCRYPTION_KEY;
  return null;
}
export function activeDataKeyVersion(env) {
  const raw = env.APP_DATA_ENCRYPTION_ACTIVE_VERSION;
  const version = raw === undefined || raw === null || raw === "" ? 1 : Number(raw);
  if (!Number.isSafeInteger(version) || version < 1 || version > 99) throw new Error("APP_DATA_ENCRYPTION_ACTIVE_VERSION_INVALID");
  return version;
}
export function dataKeyStatus(env) {
  const activeVersion = activeDataKeyVersion(env);
  const configuredVersions = [];
  for (let version = 1; version <= 99; version += 1) {
    if (configuredSecret(env, version)) configuredVersions.push(version);
  }
  return { activeVersion, configuredVersions, activeKeyReady: configuredVersions.includes(activeVersion) };
}
async function importDataKey(env, version) {
  const secret = configuredSecret(env, version);
  if (!secret) throw new Error(version === 1 ? "APP_DATA_ENCRYPTION_KEY_NOT_CONFIGURED" : "APP_DATA_ENCRYPTION_KEY_V" + version + "_NOT_CONFIGURED");
  const material = await crypto.subtle.digest("SHA-256", encoder.encode("SecureChat/application-data/v" + version + "\0" + secret));
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
export function storedKeyVersion(value) {
  const match = typeof value === "string" && value.match(/^enc:v(\d+):/);
  return match ? Number(match[1]) : 0;
}
export async function encryptStored(env, context, plaintext) {
  const version = activeDataKeyVersion(env);
  const key = await importDataKey(env, version);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("securechat:v" + version + ":" + context), tagLength: 128 },
    key,
    encoder.encode(plaintext)
  );
  return "enc:v" + version + ":" + encode64(iv) + ":" + encode64(new Uint8Array(ciphertext));
}
export async function decryptStored(env, context, value) {
  if (typeof value !== "string" || !value.startsWith("enc:v")) return value ?? "";
  const parts = value.split(":");
  const version = storedKeyVersion(value);
  if (!Number.isSafeInteger(version) || version < 1 || parts.length !== 4) throw new Error("ENCRYPTED_DATA_FORMAT_INVALID");
  const key = await importDataKey(env, version);
  const iv = decode64(parts[2]), ciphertext = decode64(parts[3]);
  if (iv.length !== 12 || ciphertext.length < 16) throw new Error("ENCRYPTED_DATA_FORMAT_INVALID");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("securechat:v" + version + ":" + context), tagLength: 128 },
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
  try {
    await env.DB.prepare("DELETE FROM announcements WHERE published=1 AND ((expires_at IS NOT NULL AND expires_at<=?) OR (expires_at IS NULL AND published_at IS NOT NULL AND published_at<=?))")
      .bind(now, now - DEFAULT_NOTICE_HOURS * 3600000).run();
  } catch {
    // The expiry columns are added by migration 0008; older deployments may not have them yet.
  }
  let activeVersion;
  try { activeVersion = activeDataKeyVersion(env); await importDataKey(env, activeVersion); }
  catch { return { skipped: true }; }
  let announcements = 0, auditLogs = 0, bugReports = 0;
  try {
    const notices = await env.DB.prepare(
      "SELECT id,title,body,title_ciphertext,body_ciphertext,encryption_version,published_at,published FROM announcements WHERE encryption_version=0 OR title_ciphertext IS NULL OR body_ciphertext IS NULL OR title_ciphertext NOT LIKE ? OR body_ciphertext NOT LIKE ? LIMIT 10"
    ).bind("enc:v" + activeVersion + ":%", "enc:v" + activeVersion + ":%").all();
    for (const row of notices.results || []) {
      const current = Number(row.encryption_version) === 1 && row.title_ciphertext && row.body_ciphertext
        ? await decodeAnnouncement(env, row)
        : { title: row.title, body: row.body };
      const encrypted = await encryptAnnouncement(env, row.id, current.title, current.body);
      const expiresAt = Number(row.published) === 1 && row.published_at ? Number(row.published_at) + DEFAULT_NOTICE_HOURS * 3600000 : null;
      await env.DB.prepare(
        "UPDATE announcements SET title='[暗号化済み]', body='[暗号化済み]', title_ciphertext=?, body_ciphertext=?, encryption_version=1, expires_at=COALESCE(expires_at, ?) WHERE id=?"
      ).bind(encrypted.titleCiphertext, encrypted.bodyCiphertext, expiresAt, row.id).run();
      announcements += 1;
    }
    const logs = await env.DB.prepare("SELECT id, details_json FROM admin_audit_logs WHERE details_json NOT LIKE ? LIMIT 20").bind("enc:v" + activeVersion + ":%").all();
    for (const row of logs.results || []) {
      const plaintext = await decryptStored(env, "admin-audit:" + row.id, row.details_json || "{}");
      const encrypted = await encryptStored(env, "admin-audit:" + row.id, plaintext);
      await env.DB.prepare("UPDATE admin_audit_logs SET details_json=? WHERE id=? AND details_json=?")
        .bind(encrypted, row.id, row.details_json).run();
      auditLogs += 1;
    }
    const reports = await env.DB.prepare("SELECT id, encrypted_payload FROM bug_reports WHERE encrypted_payload NOT LIKE ? LIMIT 20").bind("enc:v" + activeVersion + ":%").all();
    for (const row of reports.results || []) {
      const plaintext = await decryptStored(env, "bug-report:" + row.id, row.encrypted_payload);
      const encrypted = await encryptStored(env, "bug-report:" + row.id, plaintext);
      await env.DB.prepare("UPDATE bug_reports SET encrypted_payload=?, updated_at=? WHERE id=? AND encrypted_payload=?")
        .bind(encrypted, now, row.id, row.encrypted_payload).run();
      bugReports += 1;
    }
    await env.DB.prepare("DELETE FROM announcements WHERE published=1 AND expires_at IS NOT NULL AND expires_at<=?").bind(now).run();
    return { skipped: false, activeVersion, announcements, auditLogs, bugReports };
  } catch {
    return { skipped: false, activeVersion, announcements, auditLogs, bugReports, error: true };
  }
}
