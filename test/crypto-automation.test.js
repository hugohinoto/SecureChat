import assert from "node:assert/strict";
import test from "node:test";
import { runAutomaticCryptoKeyExchange } from "../public/crypto-automation.js";

function makeCrypto(initialModes = {}) {
  const calls = [];
  const modes = new Map(Object.entries(initialModes));
  return {
    calls,
    async syncCryptoV2(userId) { calls.push(["sync", userId]); },
    async getConversationCryptoMode(userId, id) {
      calls.push(["mode", id]);
      return modes.get(id) || { protocolVersion: 1, approvedByMe: false, approvedByPeer: false };
    },
    async approveAndPrepareConversation(userId, id, peer) {
      calls.push(["approve", id, peer]);
      const current = modes.get(id) || {};
      const next = { protocolVersion: 1, approvedByMe: true, approvedByPeer: !!current.approvedByPeer };
      modes.set(id, next);
      return next;
    },
    async maintainPeerSessions(userId, peer) { calls.push(["maintain", peer]); }
  };
}

test("background automation syncs device keys and approves only trusted mutual contacts", async () => {
  const crypto = makeCrypto();
  const results = await runAutomaticCryptoKeyExchange({
    userId: "alice",
    contacts: [{ userId: "bob" }, { userId: "carol" }],
    conversations: [
      { id: "conversation-bob", peer_user_id: "bob" },
      { id: "conversation-carol", peer_user_id: "carol" },
      { id: "conversation-outsider", peer_user_id: "mallory" }
    ],
    crypto,
    isPeerTrusted: async peer => peer === "bob"
  });

  assert.deepEqual(crypto.calls[0], ["sync", "alice"]);
  assert.ok(crypto.calls.some(call => call[0] === "approve" && call[1] === "conversation-bob"));
  assert.ok(crypto.calls.some(call => call[0] === "maintain" && call[1] === "bob"));
  assert.equal(crypto.calls.some(call => call.includes("carol")), false);
  assert.equal(crypto.calls.some(call => call.includes("mallory")), false);
  assert.deepEqual(results.map(result => result.status), ["waiting-for-peer", "identity-unverified"]);
});

test("background automation does not ask for a second approval and still prepares missing peer sessions", async () => {
  const crypto = makeCrypto({
    "conversation-bob": { protocolVersion: 1, approvedByMe: true, approvedByPeer: false }
  });
  const results = await runAutomaticCryptoKeyExchange({
    userId: "alice",
    contacts: [{ userId: "bob" }],
    conversations: [{ id: "conversation-bob", peer_user_id: "bob" }],
    crypto,
    isPeerTrusted: async () => true
  });

  assert.equal(crypto.calls.some(call => call[0] === "approve"), false);
  assert.ok(crypto.calls.some(call => call[0] === "maintain" && call[1] === "bob"));
  assert.equal(results[0].status, "waiting-for-peer");
});

test("a failed peer does not block automatic key exchange with other contacts", async () => {
  const crypto = makeCrypto();
  const failures = [];
  const results = await runAutomaticCryptoKeyExchange({
    userId: "alice",
    contacts: [{ userId: "bad" }, { userId: "good" }],
    conversations: [
      { id: "conversation-bad", peer_user_id: "bad" },
      { id: "conversation-good", peer_user_id: "good" }
    ],
    crypto: {
      ...crypto,
      async getConversationCryptoMode(userId, id) {
        if (id === "conversation-bad") throw Object.assign(new Error("offline"), { code: "NETWORK_ERROR" });
        return crypto.getConversationCryptoMode(userId, id);
      }
    },
    isPeerTrusted: async () => true,
    onError: (error, conversation) => failures.push([error.code, conversation.id])
  });

  assert.deepEqual(failures, [["NETWORK_ERROR", "conversation-bad"]]);
  assert.deepEqual(results.map(result => result.status), ["error", "waiting-for-peer"]);
});
