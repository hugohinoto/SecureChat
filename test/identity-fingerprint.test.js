import test from "node:test";
import assert from "node:assert/strict";
import { normalizeFingerprintInput, fingerprintsMatch } from "../public/identity-fingerprint.js";

const fingerprint = "1A2B3C4D".repeat(8);

test("accepts the displayed fingerprint with spaces and common separators", () => {
  assert.equal(fingerprintsMatch(fingerprint.match(/.{1,4}/g).join(" "), fingerprint), true);
  assert.equal(fingerprintsMatch(fingerprint.match(/.{1,4}/g).join(":"), fingerprint), true);
  assert.equal(fingerprintsMatch("SHA-256: " + fingerprint, fingerprint), true);
  assert.equal(fingerprintsMatch("SHA-256 指紋： " + fingerprint, fingerprint), true);
  assert.equal(fingerprintsMatch("0x" + fingerprint.toLowerCase(), fingerprint), true);
});

test("rejects labels, invalid characters, truncated and altered fingerprints", () => {
  assert.equal(normalizeFingerprintInput("指紋は " + fingerprint), "");
  assert.equal(fingerprintsMatch(fingerprint.slice(0, 60), fingerprint), false);
  assert.equal(fingerprintsMatch("Z" + fingerprint.slice(1), fingerprint), false);
  assert.equal(fingerprintsMatch("A" + fingerprint.slice(1), fingerprint), false);
});
