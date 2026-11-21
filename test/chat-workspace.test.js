import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("announcements are collapsed by default and remain expandable", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const match = html.match(/<details class="public-announcements"[\s\S]*?<\/details>/);

  assert.ok(match, "Announcements should use a native disclosure panel");
  assert.match(match[0], /<summary class="public-announcements-toggle">/);
  assert.match(match[0], /id="public-announcements-list"/);
  assert.doesNotMatch(match[0].split(">")[0], /\sopen(?:\s|>)/);
});

test("chat timeline receives remaining height while composer remains fixed", async () => {
  const css = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  const priorityRules = css.slice(css.indexOf("/* Give the conversation timeline priority"));

  assert.match(priorityRules, /\.chat-panel > \.timeline\s*\{[^}]*flex:\s*1 1 0%/);
  assert.match(priorityRules, /\.chat-panel > \.timeline\s*\{[^}]*min-height:\s*0/);
  assert.match(priorityRules, /\.chat-panel > \.composer-area\s*\{[^}]*flex:\s*0 0 auto/);
  assert.match(priorityRules, /\.public-announcements\[open\]\s*\{[^}]*max-height:/);
});

test("expanded announcements have a bounded scroll area on desktop and mobile", async () => {
  const css = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  const priorityRules = css.slice(css.indexOf("/* Give the conversation timeline priority"));

  assert.match(priorityRules, /\.public-announcements-content\s*\{[^}]*overflow-y:\s*auto/);
  assert.match(priorityRules, /\.public-announcements\[open\][\s\S]*?max-height:\s*22dvh/);
});
