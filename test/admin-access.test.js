import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = path => readFile(new URL(path, import.meta.url), "utf8");

test("admin HTML is served only to an authenticated, recently reauthenticated administrator", async () => {
  const worker = await read("../worker/index.js");
  const config = JSON.parse(await read("../wrangler.jsonc"));
  const routes = config.assets?.run_worker_first || [];
  assert.ok(routes.includes("/admin"));
  assert.ok(routes.includes("/admin.html"));
  const start = worker.indexOf('if (url.pathname === "/admin"');
  const end = worker.indexOf('if (url.pathname === "/bug-report"', start);
  assert.ok(start >= 0 && end > start);
  const guard = worker.slice(start, end);
  assert.match(guard, /getSession\(env, readCookie\(request\)\)/);
  assert.match(guard, /Number\(adminSession\.is_admin\) !== 1/);
  assert.match(guard, /Date\.now\(\) - Number\(adminSession\.created_at\) > AUTH_WINDOW_MS/);
  assert.match(guard, /Date\.now\(\) - Number\(adminSession\.password_changed_at\) >= ADMIN_PASSWORD_MAX_AGE_MS/);
  assert.match(guard, /url\.pathname === "\/admin\.html"/);
  assert.match(guard, /headers\.set\("Cache-Control", "no-store"\)/);
});

test("admin console verifies role and recent authentication before revealing private data", async () => {
  const admin = await read("../public/admin.js");
  const initializer = admin.slice(admin.indexOf("async function initializeAdminConsole"));
  assert.match(initializer, /api\("\/api\/auth\/me"\)/);
  assert.match(initializer, /me\.user\.isAdmin !== true/);
  assert.match(initializer, /api\("\/api\/admin\/overview"\)/);
  assert.match(admin, /window\.addEventListener\("pagehide",clearSensitiveConsole\)/);
  assert.match(admin, /window\.addEventListener\("pageshow",event=>\s*\{\s*if\(event\.persisted\)initializeAdminConsole\(\)/);
  assert.match(admin, /function clearSensitiveConsole\(\)[\s\S]*?lastSecurityCheck=null/);
});

test("admin API remains independently protected on the server", async () => {
  const worker = await read("../worker/index.js");
  const start = worker.indexOf('if (path.startsWith("/api/admin/"))');
  const end = worker.indexOf("if (path === \"/api/admin/overview\"", start);
  assert.ok(start >= 0 && end > start);
  const guard = worker.slice(start, end);
  assert.match(guard, /Number\(admin\.is_admin\) !== 1/);
  assert.match(guard, /ADMIN_REAUTH_REQUIRED/);
});
