import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const crypto = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");

test("automatic V2 approval requires explicit peer fingerprint verification", () => {
  assert.match(
    app,
    /if\(!cryptoV2Ready \|\| !cryptoV2Module \|\| !conversation \|\|\s*!cryptoV2Required \|\| !activePeerFingerprintVerified \|\| activeProtocolVersion===2\) return;/
  );
  assert.match(app, /await maybeAutoApproveCryptoV2ForActiveConversation\(\);/);
  assert.match(app, /activePeerFingerprintVerified=true;[\s\S]{0,180}maybeAutoApproveCryptoV2ForActiveConversation/);
  assert.match(app, /refreshCryptoConversationMode\(\)\s*\.then\(\(\)=>maybeAutoApproveCryptoV2ForActiveConversation\(\)\)/);
  assert.match(app, /activeProtocolVersion!==2 && \+\+cryptoModeRefreshTick % 5 === 0/);
});

test("manual V2 approval control is hidden; the verified path performs approval automatically", () => {
  assert.match(app, /el\.cryptoV2Approve\.hidden=true;/);
  assert.match(app, /cryptoV2Module\.approveAndPrepareConversation\(/);
  assert.match(app, /相手の本人確認後、v2と鍵交換が自動で有効になります/);
});

test("automatic V2 exchange continues to use the Olm/Megolm SDK and one-message session rotation", () => {
  assert.match(crypto, /context\.machine\.getMissingSessions/);
  assert.match(crypto, /context\.machine\.shareRoomKey/);
  assert.match(crypto, /sessionRotationPeriodMessages = 1/);
  assert.match(crypto, /rotationPeriodMessages = 1n/);
});
