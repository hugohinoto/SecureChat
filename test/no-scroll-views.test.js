import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = path => readFile(new URL(path, import.meta.url), "utf8");

test("admin workspace switches panels inside a fixed viewport", async () => {
  const [html, css, js] = await Promise.all([
    read("../public/admin.html"), read("../public/admin.css"), read("../public/admin.js")
  ]);
  for (const id of ["stats", "security-panel", "announcements-panel", "users-panel", "reports-panel", "audit-panel", "ops-panel"]) {
    assert.ok(html.includes('id="' + id + '"'), "missing admin view " + id);
    assert.ok(js.includes('"' + id + '"'), "admin navigation must support " + id);
  }
  assert.match(css, /body\.admin-app\{position:fixed;inset:0/);
  assert.match(css, /overflow:hidden/);
  assert.match(js, /event\.preventDefault\(\)/);
  assert.match(js, /activateAdminView\("stats"\)/);
});

test("feedback and SecureDrop use view tabs rather than a vertically scrolling page", async () => {
  const [feedback, feedbackJs, drop, dropJs, feedbackCss, dropCss] = await Promise.all([
    read("../public/bug-report.html"), read("../public/bug-report.js"),
    read("../public/secure-drop.html"), read("../public/secure-drop-app.js"),
    read("../public/admin.css"), read("../public/secure-drop-service.css")
  ]);
  for (const id of ["report-panel", "my-reports-panel", "report-steps", "report-expected", "report-actual"]) {
    assert.ok(feedback.includes('id="' + id + '"'), "missing feedback control " + id);
  }
  assert.match(feedbackJs, /activateReportView/);
  assert.match(feedbackCss, /body:not\(\.admin-app\)\{position:fixed;inset:0/);
  for (const id of ["service-upload-card", "service-usage-card", "service-files-card", "service-pending-card"]) {
    assert.ok(drop.includes('id="' + id + '"'), "missing SecureDrop view " + id);
  }
  assert.match(dropJs, /activateServiceView/);
  assert.match(dropJs, /MutationObserver/);
  assert.match(dropCss, /body\.service-body\{position:fixed;inset:0/);
});

test("main chat keeps its timeline as the designated scrollable conversation area", async () => {
  const css = await read("../public/ui-refresh.css");
  assert.match(css, /\.timeline\s*\{[^}]*overflow:\s*auto/s);
  assert.match(css, /\.auth-card\{overflow:hidden/);
});
