import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

function sourceFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : entry.name.endsWith(".js") ? [path] : [];
  });
}

test("Worker console output contains only fixed literal labels", () => {
  const files = sourceFiles(fileURLToPath(new URL("../worker", import.meta.url)));
  const findings = [];
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    const calls = source.matchAll(/\bconsole\.(?:log|info|warn|error|debug)\s*\(([^)]*)\)/gs);
    for (const call of calls) {
      const argument = call[1].trim();
      if (!/^(?:"[^"]*"|'[^']*')$/.test(argument)) {
        findings.push(file + ": " + argument.slice(0, 120));
      }
    }
  }
  assert.deepEqual(findings, [], "Do not write request data, credentials, key material, message content, or exception objects to Worker logs.");
});
