import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const inputFiles = ["worker/index.js", "worker/admin-features.js"];

function readStringLiteral(source, start) {
  const quote = source[start];
  if (quote !== "'" && quote !== '"' && quote !== "`") return null;
  let value = "";
  for (let i = start + 1; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === quote) return { value, end: i + 1, dynamic: false };
    if (ch === "\\") {
      const next = source[i + 1];
      if (next === undefined) return null;
      const escapes = { n: "\n", r: "\r", t: "\t", "\\": "\\", "'": "'", '"': '"', "`": "`" };
      value += Object.hasOwn(escapes, next) ? escapes[next] : next;
      i += 1;
      continue;
    }
    if (quote === "`" && ch === "$" && source[i + 1] === "{") {
      return { value, end: i + 2, dynamic: true };
    }
    value += ch;
  }
  return null;
}

function extractQueries(source, file) {
  const queries = [];
  let skippedDynamic = 0;
  const callPattern = /\.prepare\s*\(/g;
  let match;
  while ((match = callPattern.exec(source))) {
    let cursor = match.index + match[0].length;
    while (/\s/.test(source[cursor] || "")) cursor += 1;
    const literal = readStringLiteral(source, cursor);
    if (!literal) {
      skippedDynamic += 1;
      continue;
    }
    let after = literal.end;
    while (/\s/.test(source[after] || "")) after += 1;
    // Only complete, single literal arguments are parsed here. Expressions are
    // checked independently by Semgrep's taint rule rather than guessed at.
    if (literal.dynamic || source[after] !== ")") {
      skippedDynamic += 1;
      continue;
    }
    const line = source.slice(0, match.index).split("\n").length;
    queries.push({ file, line, sql: literal.value.trim() });
  }
  return { queries, skippedDynamic };
}

const all = [];
let skippedDynamic = 0;
for (const file of inputFiles) {
  const source = await readFile(resolve(file), "utf8");
  const result = extractQueries(source, file);
  all.push(...result.queries);
  skippedDynamic += result.skippedDynamic;
}
if (!all.length) {
  throw new Error("No static D1 SQL statements were extracted; refusing to silently pass.");
}
const output = process.argv[2] || "/tmp/securechat-worker-queries.sql";
const sql = all.map(({ file, line, sql }) => `-- ${file}:${line}\n${sql.endsWith(";") ? sql : sql + ";"}`).join("\n\n") + "\n";
await writeFile(output, sql);
console.log(`Extracted ${all.length} static D1 statements to ${output}. ${skippedDynamic} dynamic query expressions were excluded and are separately scanned by Semgrep.`);
