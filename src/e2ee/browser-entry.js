/**
 * SecureChat E2EE v2 browser bootstrap.
 *
 * Deliberately local-only: no hosted relay URL and no network transport are
 * configured here. Cloudflare relay integration is a separate phase.
 *
 * This module is not imported by the production app yet.
 */
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { indexedDbStore } from "@open-e2ee/signal-protocol-sdk/local/store/web";

let initialization = null;
let activeUserId = null;

export async function openSecureChatE2EE(userId) {
  if (typeof userId !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(userId)) {
    throw new TypeError("A valid SecureChat user ID is required.");
  }

  if (initialization) {
    if (activeUserId !== userId) {
      throw new Error(
        "The E2EE test client is already initialized for another account. Reload this test page before switching accounts."
      );
    }
    return initialization;
  }

  activeUserId = userId;
  initialization = (async () => {
    const storage = await indexedDbStore();
    return createSignalProtocolClient({
      identity: { userId },
      adapters: { storage },
      protocol: {
        postQuantum: "required",
        braid: "required"
      }
    });
  })();

  try {
    return await initialization;
  } catch (error) {
    initialization = null;
    activeUserId = null;
    throw error;
  }
}

export function getSecureChatE2EEStatus() {
  return Object.freeze({
    sdk: "@open-e2ee/signal-protocol-sdk",
    version: "14.7.0",
    mode: "local-only",
    relayConfigured: false,
    productionIntegrated: false
  });
}
