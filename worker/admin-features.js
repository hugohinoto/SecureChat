import { encryptStored, decryptStored, encryptAnnouncement, decodeAnnouncement } from "./data-crypto.js";
import { summarizeSecurityDiagnostics } from "./security-diagnostics.js";
const DEFAULT_NOTICE_HOURS = 48, MAX_NOTICE_HOURS = 720, encoder = new TextEncoder();
function json(data, status = 200) { return Response.json(data, { status, headers: { "Cache-Control": "no-store" } }); }
function expiryHours(value, fallback = DEFAULT_NOTICE_HOURS) {
  if (value === undefined || value === null || value === "") return fallback;
  const n = Number(value); return Number.isInteger(n) && n >= 1 && n <= MAX_NOTICE_HOURS ? n : null;
}
async function adminAuth(request, env, deps) {
  if (request.method !== "GET" && !deps.sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
  let admin; try { admin = await deps.getSession(env, deps.readCookie(request)); } catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
  if (!admin) return json({ error: "UNAUTHENTICATED" }, 401);
  if (Number(admin.is_admin) !== 1) return json({ error: "ADMIN_REQUIRED" }, 403);
  if (!admin.password_changed_at || Date.now() - Number(admin.password_changed_at) >= 90 * 86400000) return json({ error: "PASSWORD_CHANGE_REQUIRED" }, 428);
  if (Date.now() - Number(admin.created_at) > 15 * 60000) return json({ error: "ADMIN_REAUTH_REQUIRED" }, 428);
  if (request.method !== "GET" && !await deps.checkRateLimit(env, request, "admin-write", 30)) return json({ error: "RATE_LIMITED" }, 429);
  return admin;
}
async function checkSecurity(env) {
  return summarizeSecurityDiagnostics(env);
}

export async function handleAdminFeatures(request, env, deps) {
  const url = deps.url || new URL(request.url), path = url.pathname, method = request.method;
  if (path === "/api/bug-reports" && method === "POST") {
    if (!deps.sameOrigin(request)) return json({ error: "ORIGIN_REJECTED" }, 403);
    let session; try { session = await deps.getSession(env, deps.readCookie(request)); } catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    if (!await deps.checkRateLimit(env, request, "bug-report", 3)) return json({ error: "RATE_LIMITED" }, 429);
    let body; try { body = await deps.readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
    const categories = ["bug", "security", "other"];
    if (!body || !categories.includes(body.category) || typeof body.title !== "string" || !body.title.trim() || body.title.length > 100 ||
        typeof body.description !== "string" || !body.description.trim() || body.description.length > 5000 ||
        (body.steps !== undefined && (typeof body.steps !== "string" || body.steps.length > 2500)) ||
        (body.expected !== undefined && (typeof body.expected !== "string" || body.expected.length > 1500)) ||
        (body.actual !== undefined && (typeof body.actual !== "string" || body.actual.length > 1500))) return json({ error: "INVALID_REPORT" }, 400);
    const report = { category: body.category, title: body.title.trim(), description: body.description.trim(), steps: (body.steps || "").trim(), expected: (body.expected || "").trim(), actual: (body.actual || "").trim() };
    if (JSON.stringify(report).length > 12000) return json({ error: "REPORT_TOO_LARGE" }, 413);
    try {
      const id = crypto.randomUUID(), now = Date.now(), encrypted = await encryptStored(env, "bug-report:" + id, JSON.stringify(report));
      await env.DB.prepare("INSERT INTO bug_reports (id,reporter_user_id,encrypted_payload,status,created_at,updated_at) VALUES (?, ?, ?, 'open', ?, ?)").bind(id, session.id, encrypted, now, now).run();
      return json({ submitted: true, id }, 201);
    } catch (error) { return json({ error: error?.message === "APP_DATA_ENCRYPTION_KEY_NOT_CONFIGURED" ? "DATA_ENCRYPTION_NOT_CONFIGURED" : "REPORT_UNAVAILABLE" }, 503); }
  }
  if (path === "/api/bug-reports" && method === "GET") {
    let session; try { session = await deps.getSession(env, deps.readCookie(request)); } catch { return json({ error: "AUTH_UNAVAILABLE" }, 503); }
    if (!session) return json({ error: "UNAUTHENTICATED" }, 401);
    try {
      const rows = await env.DB.prepare("SELECT id,encrypted_payload,status,created_at,updated_at,resolved_at FROM bug_reports WHERE reporter_user_id=? ORDER BY created_at DESC LIMIT 100").bind(session.id).all();
      const reports = [];
      for (const row of rows.results || []) {
        const report = JSON.parse(await decryptStored(env, "bug-report:" + row.id, row.encrypted_payload));
        const replyRows = await env.DB.prepare("SELECT id,encrypted_payload,created_at FROM bug_report_replies WHERE bug_report_id=? ORDER BY created_at ASC LIMIT 100").bind(row.id).all();
        const replies = [];
        for (const reply of replyRows.results || []) {
          replies.push({ id: reply.id, message: await decryptStored(env, "bug-report-reply:" + reply.id, reply.encrypted_payload), createdAt: reply.created_at });
        }
        reports.push({ id: row.id, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at, resolvedAt: row.resolved_at, report, replies });
      }
      return json({ reports });
    } catch (error) {
      return json({ error: error?.message === "APP_DATA_ENCRYPTION_KEY_NOT_CONFIGURED" ? "DATA_ENCRYPTION_NOT_CONFIGURED" : "REPORTS_UNAVAILABLE" }, 503);
    }
  }
  const noticeRoute = path === "/api/admin/announcements" || /^\/api\/admin\/announcements\/[a-f0-9-]+$/i.test(path);
  const usersRoute = path === "/api/admin/users" && method === "GET";
  const securityRoute = path === "/api/admin/security-check" && method === "GET";
  const reportsRoute = path === "/api/admin/bug-reports" || /^\/api\/admin\/bug-reports\/[a-f0-9-]+(?:\/replies)?$/i.test(path);
  const auditRoute = path === "/api/admin/audit-logs" && method === "GET";
  if (noticeRoute || usersRoute || securityRoute || reportsRoute || auditRoute) {
    const admin = await adminAuth(request, env, deps); if (admin instanceof Response) return admin;
    try {
      if (usersRoute) {
        const q = (url.searchParams.get("q") || "").trim().toLowerCase(), mode = url.searchParams.get("mode") || "prefix";
        const role = url.searchParams.get("role") || "all", sort = url.searchParams.get("sort") || "created_desc", pageRaw = url.searchParams.get("page") || "0";
        if (q.length > 64 || (q && !/^[a-z0-9_-]+$/.test(q))) return json({ error: "INVALID_SEARCH_QUERY" }, 400);
        if (!["prefix", "exact", "contains"].includes(mode) || !["all", "admin", "user"].includes(role)) return json({ error: "INVALID_SEARCH_FILTER" }, 400);
        const orderBy = { created_desc: "created_at DESC", created_asc: "created_at ASC", login_desc: "last_login_at DESC, created_at DESC", user_id_asc: "user_id ASC" }[sort];
        if (!orderBy || !/^\d{1,5}$/.test(pageRaw)) return json({ error: "INVALID_SEARCH_OPTIONS" }, 400);
        const page = Math.min(10000, Number(pageRaw)), clauses = [], binds = [];
        if (q) { if (mode === "exact") { clauses.push("(user_id=? OR id=?)"); binds.push(q, q); } else { const escaped = q.replace(/[_%]/g, (ch) => "!" + ch); clauses.push("user_id LIKE ? ESCAPE '!'"); binds.push(mode === "contains" ? "%" + escaped + "%" : escaped + "%"); } }
        if (role === "admin") clauses.push("is_admin=1"); if (role === "user") clauses.push("is_admin=0");
        const where = clauses.length ? " WHERE " + clauses.join(" AND ") : "";
        const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM users" + where).bind(...binds).first();
        const rows = await env.DB.prepare("SELECT id,user_id,is_admin,created_at,last_login_at FROM users" + where + " ORDER BY " + orderBy + " LIMIT 50 OFFSET ?").bind(...binds, page * 50).all();
        return json({ users: rows.results || [], total: Number(count?.count || 0), page, pageSize: 50, mode, role, sort });
      }
      if (path === "/api/admin/announcements" && method === "GET") {
        const now = Date.now();
        const rows = await env.DB.prepare("SELECT * FROM announcements WHERE published=0 OR (expires_at>? OR (expires_at IS NULL AND published_at>?)) ORDER BY created_at DESC LIMIT 100").bind(now, now - DEFAULT_NOTICE_HOURS * 3600000).all();
        const announcements = []; for (const row of rows.results || []) announcements.push(await decodeAnnouncement(env, row));
        return json({ announcements });
      }
      if (path === "/api/admin/announcements" && method === "POST") {
        let body; try { body = await deps.readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
        const title = typeof body?.title === "string" ? body.title.trim() : "", content = typeof body?.body === "string" ? body.body.trim() : "";
        const published = body?.published === true, hours = expiryHours(body?.expiryHours);
        if (!title || title.length > 100 || !content || content.length > 3000 || hours === null) return json({ error: "INVALID_ANNOUNCEMENT" }, 400);
        const id = crypto.randomUUID(), now = Date.now(), encrypted = await encryptAnnouncement(env, id, title, content);
        await env.DB.prepare("INSERT INTO announcements (id,title,body,published,created_by_user_id,created_at,updated_at,published_at,title_ciphertext,body_ciphertext,encryption_version,expires_at) VALUES (?, '[暗号化済み]', '[暗号化済み]', ?, ?, ?, ?, ?, ?, ?, 1, ?)").bind(id, published ? 1 : 0, admin.id, now, now, published ? now : null, encrypted.titleCiphertext, encrypted.bodyCiphertext, published ? now + hours * 3600000 : null).run();
        await deps.writeAdminAudit(env, admin, published ? "announcement.publish" : "announcement.create", id, { expiryHours: hours, encrypted: true });
        return json({ created: true, id, expiresAt: published ? now + hours * 3600000 : null }, 201);
      }
      const noticeMatch = path.match(/^\/api\/admin\/announcements\/([a-f0-9-]+)$/i);
      if (noticeMatch && ["PUT", "DELETE"].includes(method)) {
        const id = noticeMatch[1], existing = await env.DB.prepare("SELECT * FROM announcements WHERE id=?").bind(id).first();
        if (!existing) return json({ error: "ANNOUNCEMENT_NOT_FOUND" }, 404);
        if (method === "DELETE") { await env.DB.prepare("DELETE FROM announcements WHERE id=?").bind(id).run(); await deps.writeAdminAudit(env, admin, "announcement.delete", id, { encrypted: true }); return json({ deleted: true }); }
        let body; try { body = await deps.readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
        const decoded = await decodeAnnouncement(env, existing);
        const title = typeof body?.title === "string" ? body.title.trim() : decoded.title, content = typeof body?.body === "string" ? body.body.trim() : decoded.body;
        const published = body?.published === undefined ? Number(existing.published) === 1 : body.published === true;
        const explicitExpiry = Object.prototype.hasOwnProperty.call(body || {}, "expiryHours"), hours = explicitExpiry ? expiryHours(body.expiryHours) : null;
        if (!title || title.length > 100 || !content || content.length > 3000 || (explicitExpiry && hours === null)) return json({ error: "INVALID_ANNOUNCEMENT" }, 400);
        const wasPublished = Number(existing.published) === 1, now = Date.now(), publishedAt = published ? (wasPublished ? existing.published_at : now) : null;
        const expiresAt = !published ? null : explicitExpiry ? now + hours * 3600000 : wasPublished && existing.expires_at ? existing.expires_at : (publishedAt || now) + DEFAULT_NOTICE_HOURS * 3600000;
        const encrypted = await encryptAnnouncement(env, id, title, content);
        await env.DB.prepare("UPDATE announcements SET title='[暗号化済み]',body='[暗号化済み]',title_ciphertext=?,body_ciphertext=?,encryption_version=1,published=?,updated_at=?,published_at=?,expires_at=? WHERE id=?").bind(encrypted.titleCiphertext, encrypted.bodyCiphertext, published ? 1 : 0, now, publishedAt, expiresAt, id).run();
        await deps.writeAdminAudit(env, admin, "announcement.update", id, { published, expiryChanged: explicitExpiry, encrypted: true });
        return json({ updated: true, expiresAt });
      }
      if (securityRoute) {
        // Let each database check report its own failure; even when D1 is down,
        // secret checks and external scanner status must still be returned.
        return json(await checkSecurity(env));
      }
      if (path === "/api/admin/bug-reports" && method === "GET") {
        const rows = await env.DB.prepare("SELECT b.id,b.encrypted_payload,b.status,b.created_at,b.updated_at,b.resolved_at,u.user_id AS reporter FROM bug_reports b LEFT JOIN users u ON u.id=b.reporter_user_id ORDER BY b.created_at DESC LIMIT 100").all();
        const reports = [];
        for (const row of rows.results || []) {
          const report = JSON.parse(await decryptStored(env, "bug-report:" + row.id, row.encrypted_payload));
          const replyRows = await env.DB.prepare("SELECT id,encrypted_payload,created_at FROM bug_report_replies WHERE bug_report_id=? ORDER BY created_at ASC LIMIT 100").bind(row.id).all();
          const replies = [];
          for (const reply of replyRows.results || []) {
            replies.push({ id: reply.id, message: await decryptStored(env, "bug-report-reply:" + reply.id, reply.encrypted_payload), createdAt: reply.created_at });
          }
          reports.push({ id: row.id, reporter: row.reporter || "(削除済みユーザー)", status: row.status, createdAt: row.created_at, updatedAt: row.updated_at, resolvedAt: row.resolved_at, report, replies });
        }
        return json({ reports });
      }
      const replyMatch = path.match(/^\/api\/admin\/bug-reports\/([a-f0-9-]+)\/replies$/i);
      if (replyMatch && method === "POST") {
        let body; try { body = await deps.readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
        const message = typeof body?.message === "string" ? body.message.trim() : "";
        if (!message || message.length > 4000) return json({ error: "INVALID_REPLY" }, 400);
        const report = await env.DB.prepare("SELECT id FROM bug_reports WHERE id=?").bind(replyMatch[1]).first();
        if (!report) return json({ error: "BUG_REPORT_NOT_FOUND" }, 404);
        const id = crypto.randomUUID(), now = Date.now();
        const encrypted = await encryptStored(env, "bug-report-reply:" + id, message);
        await env.DB.prepare("INSERT INTO bug_report_replies (id,bug_report_id,admin_user_id,encrypted_payload,created_at) VALUES (?, ?, ?, ?, ?)").bind(id, report.id, admin.id, encrypted, now).run();
        await env.DB.prepare("UPDATE bug_reports SET updated_at=? WHERE id=?").bind(now, report.id).run();
        await deps.writeAdminAudit(env, admin, "bug-report.reply", report.id, { replyId: id, encrypted: true });
        return json({ sent: true, id, createdAt: now }, 201);
      }
      const reportMatch = path.match(/^\/api\/admin\/bug-reports\/([a-f0-9-]+)$/i);
      if (reportMatch && method === "DELETE") {
        const existing = await env.DB.prepare("SELECT id FROM bug_reports WHERE id=?").bind(reportMatch[1]).first();
        if (!existing) return json({ error: "BUG_REPORT_NOT_FOUND" }, 404);
        const result = await env.DB.prepare("DELETE FROM bug_reports WHERE id=?").bind(reportMatch[1]).run();
        if (!result.meta?.changes) return json({ error: "BUG_REPORT_NOT_FOUND" }, 404);
        await deps.writeAdminAudit(env, admin, "bug-report.delete", reportMatch[1], { repliesCascadeDeleted: true });
        return json({ deleted: true });
      }
      if (reportMatch && method === "PUT") {
        let body; try { body = await deps.readJson(request); } catch { return json({ error: "INVALID_JSON" }, 400); }
        if (!["open", "triaged", "resolved"].includes(body?.status)) return json({ error: "INVALID_STATUS" }, 400);
        const now = Date.now(), result = await env.DB.prepare("UPDATE bug_reports SET status=?,updated_at=?,resolved_at=? WHERE id=?").bind(body.status, now, body.status === "resolved" ? now : null, reportMatch[1]).run();
        if (!result.meta?.changes) return json({ error: "BUG_REPORT_NOT_FOUND" }, 404);
        await deps.writeAdminAudit(env, admin, "bug-report.status", reportMatch[1], { status: body.status });
        return json({ updated: true });
      }
      if (auditRoute) {
        const rows = await env.DB.prepare("SELECT l.id,l.action,l.target_user_id,l.details_json,l.created_at,u.user_id AS admin_user_id FROM admin_audit_logs l LEFT JOIN users u ON u.id=l.admin_user_id ORDER BY l.created_at DESC LIMIT 100").all();
        const logs = [];
        for (const row of rows.results || []) {
          let details; try { details = await decryptStored(env, "admin-audit:" + row.id, row.details_json || "{}"); } catch { details = "[復号できません。APP_DATA_ENCRYPTION_KEYを確認してください]"; }
          logs.push({ ...row, details_json: details });
        }
        return json({ logs });
      }
    } catch (error) {
      return json({ error: error?.message === "APP_DATA_ENCRYPTION_KEY_NOT_CONFIGURED" ? "DATA_ENCRYPTION_NOT_CONFIGURED" : "ADMIN_FEATURE_UNAVAILABLE" }, 503);
    }
  }
  if (path === "/api/announcements" && method === "GET") {
    try {
      const now = Date.now(), rows = await env.DB.prepare("SELECT id,title,body,title_ciphertext,body_ciphertext,encryption_version,published_at,expires_at FROM announcements WHERE published=1 AND (expires_at>? OR (expires_at IS NULL AND published_at>?)) ORDER BY published_at DESC LIMIT 20").bind(now, now - DEFAULT_NOTICE_HOURS * 3600000).all();
      const announcements = []; for (const row of rows.results || []) announcements.push(await decodeAnnouncement(env, { ...row, published: 1 }));
      return json({ announcements });
    } catch { return json({ error: "ANNOUNCEMENTS_UNAVAILABLE" }, 503); }
  }
  return null;
}
