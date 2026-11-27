import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const crypto = readFileSync(new URL("../public/crypto-v2.js", import.meta.url), "utf8");

test("automatic V2 approval requires a trusted peer account identity", () => {
  assert.match(
    app,
    /if\(!cryptoV2Ready \|\| !cryptoV2Module \|\| !conversation \|\|\s*!cryptoV2Required \|\| !activePeerIdentityTrusted \|\| activeProtocolVersion===2\) return;/
  );
  assert.match(app, /await maybeAutoApproveCryptoV2ForActiveConversation\(\);/);
  assert.match(app, /refreshCryptoConversationMode\(\)\s*\.then\(\(\)=>maybeAutoApproveCryptoV2ForActiveConversation\(\)\)/);
  assert.match(app, /activeProtocolVersion!==2 && \+\+cryptoModeRefreshTick % 5 === 0/);
});

test("first-use trust is limited to authenticated contacts and is pinned locally", () => {
  assert.match(app, /async function isVerifiedContact\(peerUserId\)[\s\S]*?api\("\/api\/contacts"\)/);
  assert.match(app, /if\(!await isVerifiedContact\(peerUserId\)\)/);
  const keyHandlingStart = app.indexOf("const keyChanged=");
  const keyHandlingEnd = app.indexOf("activePeerSigningKey=peer.identitySigningPublicKey;", keyHandlingStart);
  const keyHandling = app.slice(keyHandlingStart, keyHandlingEnd);
  assert.match(keyHandling, /if\(keyChanged\)[\s\S]*await showPeerKeyChangeVerification[\s\S]*throw appError/);
  assert.match(keyHandling, /if\(verifiedPeerPins\[peerUserId\]!==peer\.identitySigningPublicKey\)/);
});

test("obsolete manual V2 approval control is removed; the verified path performs approval automatically", () => {
  assert.doesNotMatch(app, /cryptoV2Approve/);
  assert.match(app, /cryptoV2Module\.approveAndPrepareConversation\(/);
  assert.match(app, /async function isVerifiedContact\(peerUserId\)/);
  assert.match(app, /verifiedPeerPins\[peerUserId\]!==peer\.identitySigningPublicKey/);
});

test("automatic V2 exchange continues to use the Olm/Megolm SDK and one-message session rotation", () => {
  assert.match(crypto, /context\.machine\.getMissingSessions/);
  assert.match(crypto, /context\.machine\.shareRoomKey/);
  assert.match(crypto, /sessionRotationPeriodMessages = 1/);
  assert.match(crypto, /rotationPeriodMessages = 1n/);
});
