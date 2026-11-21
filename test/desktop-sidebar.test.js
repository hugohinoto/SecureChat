import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("desktop sidebar sections do not shrink out of view", async () => {
  const css = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  const desktopRules = css.match(/@media \(min-width: 681px\) \{[\s\S]*?\/\* Desktop: prevent sidebar sections[\s\S]*?\n\}/)?.[0];

  assert.ok(desktopRules, "Missing desktop sidebar layout safeguards");
  assert.match(desktopRules, /\.sidebar > \.sidebar-heading[\s\S]*?flex:\s*0 0 auto/);
  assert.match(desktopRules, /\.sidebar > \.invitation-list[\s\S]*?flex:\s*0 0 auto/);
  assert.match(desktopRules, /\.sidebar > \.contact-list[\s\S]*?flex:\s*0 0 auto/);
  assert.match(desktopRules, /\.sidebar > \.conversation-list[\s\S]*?flex:\s*0 0 auto/);
  assert.match(desktopRules, /overflow-y:\s*auto/);
  assert.match(desktopRules, /max-height:\s*180px/);
});

test("desktop sidebar fix is isolated from the mobile breakpoint", async () => {
  const css = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  assert.match(css, /@media \(min-width: 681px\)[\s\S]*?Desktop: prevent sidebar sections from collapsing/);
});
