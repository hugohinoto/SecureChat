import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("Cloudflare automatic invocation logs are disabled while application logs remain enabled", () => {
  const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.equal(config.observability.enabled, true);
  assert.equal(config.observability.logs.enabled, true);
  assert.equal(config.observability.logs.invocation_logs, false);
});


test("production data encryption writes use configured key generation v2", () => {
  const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.equal(config.vars.APP_DATA_ENCRYPTION_ACTIVE_VERSION, "2");
});
