import {
  createHostedSignalProtocolClient,
  hostedSignalProtocolRelaySandboxIdentity,
} from "@open-e2ee/signal-protocol-sdk";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";

const relayUrl = process.env.OPEN_E2EE_SIGNAL_RELAY_URL;
if (!relayUrl) {
  throw new Error("Set OPEN_E2EE_SIGNAL_RELAY_URL in security-lab/.env.local using the Sandbox URL.");
}

const aliceStorage = inMemoryStore();
const bobStorage = inMemoryStore();

const alice = await createHostedSignalProtocolClient({
  adapters: { storage: aliceStorage },
  hosted: {
    relayUrl,
    getIdentityAssertion: hostedSignalProtocolRelaySandboxIdentity(aliceStorage),
  },
});

const bob = await createHostedSignalProtocolClient({
  adapters: { storage: bobStorage },
  hosted: {
    relayUrl,
    getIdentityAssertion: hostedSignalProtocolRelaySandboxIdentity(bobStorage),
  },
});

let timeout: ReturnType<typeof setTimeout> | undefined;
try {
  const received = new Promise<string>((resolve, reject) => {
    bob.registerHook("onMessageDecrypted", async (message) => {
      resolve(message.content);
    });
    timeout = setTimeout(() => reject(new Error("No decrypted message arrived within 30 seconds.")), 30_000);
  });

  bob.startRelaySubscription();
  const probe = "SecureChat forward-secrecy lab: encrypted round trip";
  await alice.send(bob.userId, probe);
  const plaintext = await received;

  if (plaintext !== probe) {
    throw new Error("Decrypted plaintext did not match the test message.");
  }

  console.log("PASS: Sandbox encrypted message was decrypted by the second test identity.");
  console.log("Alice:", alice.userId);
  console.log("Bob:", bob.userId);
} finally {
  if (timeout) clearTimeout(timeout);
  await Promise.all([bob.stop(), alice.stop()]);
}
