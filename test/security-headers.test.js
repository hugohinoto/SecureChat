import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("static assets publish the expected browser security headers", async () => {
  const headers = await read("../public/_headers");
  for (const header of [
    "Content-Security-Policy:",
    "X-Content-Type-Options: nosniff",
    "X-Frame-Options: DENY",
    "Referrer-Policy: no-referrer",
    "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "Cross-Origin-Opener-Policy: same-origin",
    "Cross-Origin-Resource-Policy: same-origin"
  ]) {
    assert.ok(headers.includes(header), `Missing static security header: ${header}`);
  }
  assert.match(headers, /frame-ancestors 'none'/);
  assert.match(headers, /upgrade-insecure-requests/);
});

test("HTML entrypoints run through the Worker for HTTPS redirects", async () => {
  const config = JSON.parse(await read("../wrangler.jsonc"));
  const routes = config.assets?.run_worker_first || [];
  assert.equal(config.assets?.html_handling, "none", "Worker rewrites /admin to /admin.html, so the asset router must not redirect .html back to /admin");
  for (const route of ["/", "/index.html", "/admin", "/admin/", "/admin.html", "/bug-report", "/bug-report/", "/bug-report.html"]) {
    assert.ok(routes.includes(route), `Missing Worker-first route: ${route}`);
  }
});

test("login screen warns users about impersonation messages", async () => {
  const html = await read("../public/index.html");
  assert.match(html, /メールやDMでパスワードやワンタイムコードを尋ねることはありません/);
});

test("Worker keeps security headers on redirects and blocks nested frames", async () => {
  const worker = await read("../worker/index.js");
  assert.match(worker, /securityHeaders\(Response\.redirect\(url\.toString\(\), 308\), request\)/);
  assert.match(worker, /frame-src 'none'/);
  assert.match(worker, /upgrade-insecure-requests/);
});
