import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("ZAP allowlist contains only reviewed informational baseline notices", async () => {
  const rules = await readFile(new URL("../.zap/rules.tsv", import.meta.url), "utf8");
  const entries = rules.split(/\r?\n/).filter(line => line.trim() && !line.trim().startsWith("#"));
  const ids = entries.map(line => line.split("\t")[0]).sort();
  assert.deepEqual(ids, ["10015", "10024", "10049", "10111", "90004"]);
  assert.ok(entries.every(line => line.split("\t")[1] === "IGNORE"));
  for (const id of ids) assert.match(rules, new RegExp("^# "+id+":", "m"));
});

test("registration invite codes are not read from URL query parameters", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.doesNotMatch(app, /location\.search|new URLSearchParams/);
  assert.match(app, /body:registering\?\{userId,password,inviteCode:el\.inviteCode\.value\.trim\(\)\}/);
});
