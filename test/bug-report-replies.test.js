import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = path => readFile(new URL(path, import.meta.url), "utf8");

test("bug report replies are stored encrypted and linked to the original report", async () => {
  const worker = await read("../worker/admin-features.js");
  const migration = await read("../database/d1-migrations/0017_bug_report_replies.sql");
  assert.match(worker, /encryptStored\(env, "bug-report-reply:" \+ id, message\)/);
  assert.match(worker, /decryptStored\(env, "bug-report-reply:" \+ reply\.id, reply\.encrypted_payload\)/);
  assert.match(worker, /INSERT INTO bug_report_replies \(id,bug_report_id,admin_user_id,encrypted_payload,created_at\)/);
  assert.match(migration, /REFERENCES bug_reports\(id\) ON DELETE CASCADE/);
  assert.match(migration, /encrypted_payload TEXT NOT NULL/);
});

test("only an authenticated report owner can read their reports and replies", async () => {
  const worker = await read("../worker/admin-features.js");
  const start = worker.indexOf('if (path === "/api/bug-reports" && method === "GET")');
  const end = worker.indexOf('const noticeRoute', start);
  assert.ok(start >= 0 && end > start);
  const route = worker.slice(start, end);
  assert.match(route, /deps\.getSession\(env, deps\.readCookie\(request\)\)/);
  assert.match(route, /WHERE reporter_user_id=\?/);
  assert.match(route, /\.bind\(session\.id\)/);
});

test("admin replies require the existing administrator authorization gate and validate content", async () => {
  const worker = await read("../worker/admin-features.js");
  assert.match(worker, /const reportsRoute =[\s\S]*?bug-reports[\\/]\\/\[a-f0-9-\]\+\(\?:[\\/]\\/replies\)\?/);
  assert.match(worker, /if \(replyMatch && method === "POST"\)/);
  assert.match(worker, /message\.length > 4000/);
  assert.match(worker, /deps\.writeAdminAudit\(env, admin, "bug-report\.reply"/);
});

test("reporter page renders replies and admin console provides a reply composer", async () => {
  const reporter = await read("../public/bug-report.js");
  const admin = await read("../public/admin.js");
  const html = await read("../public/bug-report.html");
  assert.match(reporter, /api\("\/api\/bug-reports"\)/);
  assert.match(reporter, /text\.textContent=reply\.message/);
  assert.match(html, /id="my-reports"/);
  assert.match(admin, /\/replies/);
  assert.match(admin, /replyInput\.maxLength=4000/);
  assert.match(admin, /text\.textContent=reply\.message/);
});
