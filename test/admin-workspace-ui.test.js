import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = path => readFile(new URL(path, import.meta.url), "utf8");

test("admin console uses the IDE workspace shell without dropping admin controls", async () => {
  const html = await read("../public/admin.html");
  const js = await read("../public/admin.js");
  for (const token of ["activity-bar", "explorer", "editor-tabs", "status-bar", "id=\"console\""]) {
    assert.ok(html.includes(token), "missing workspace element: " + token);
  }
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
  const selectors = [...js.matchAll(/\$\("#([^"]+)"\)/g)].map(match => match[1]);
  const missing = [...new Set(selectors)].filter(id => !ids.has(id));
  assert.deepEqual(missing, [], "admin.js selectors must remain present in the rebuilt HTML");
  for (const id of ["announcement-form", "user-search", "users", "bug-reports", "security-checks", "logs", "logout"]) {
    assert.ok(ids.has(id), "missing existing admin control: " + id);
  }
});

test("admin IDE layout supports narrow screens, keyboard focus, and reduced motion", async () => {
  const css = await read("../public/admin.css");
  assert.match(css, /@media\s*\(max-width:\s*720px\)/);
  assert.match(css, /:focus-visible|:focus\{/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /grid-template-columns:\s*38px minmax\(0,1fr\)/);
});
