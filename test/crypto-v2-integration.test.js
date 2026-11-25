import assert from "node:assert/strict";
import test from "node:test";
import {
  initAsync,
  OlmMachine,
  UserId,
  DeviceId,
  RoomId,
  RequestType,
  DeviceLists,
  EncryptionSettings,
  EncryptionAlgorithm,
  CollectStrategy,
  RoomSettings,
  DecryptionSettings,
  TrustRequirement,
  LocalTrust
} from "@matrix-org/matrix-sdk-crypto-wasm";

// In-memory Matrix-style transport: it stores only public device/OTK records
// and opaque to-device ciphertext, then feeds those events into the peer OlmMachine.
class CryptoTransport {
  constructor() {
    this.devices = new Map();
    this.inbox = new Map();
    this.nextEvent = 0;
  }
  key(userId, deviceId) { return userId + "|" + deviceId; }
  async handle(machine, request) {
    const body = typeof request.body === "string" ? JSON.parse(request.body) : (request.body || {});
    let response = {};
    if (request.type === RequestType.KeysUpload) {
      const userId = machine.userId.toString();
      const deviceId = machine.deviceId.toString();
      const key = this.key(userId, deviceId);
      const current = this.devices.get(key) || { deviceKeys: null, oneTimeKeys: new Map(), fallbackKeys: new Map() };
      if (body.device_keys) current.deviceKeys = body.device_keys;
      for (const [id, value] of Object.entries(body.one_time_keys || {})) current.oneTimeKeys.set(id, value);
      for (const [id, value] of Object.entries(body.fallback_keys || {})) current.fallbackKeys.set(id, value);
      this.devices.set(key, current);
      response = {
        one_time_key_counts: {
          signed_curve25519: current.oneTimeKeys.size
        },
        unused_fallback_key_types: current.fallbackKeys.size ? ["signed_curve25519"] : []
      };
    } else if (request.type === RequestType.KeysQuery) {
      const result = {};
      for (const [userId, requested] of Object.entries(body.device_keys || {})) {
        result[userId] = {};
        for (const device of this.devices.values()) {
          if (device.deviceKeys?.user_id !== userId) continue;
          const deviceId = device.deviceKeys.device_id;
          if (Array.isArray(requested) && requested.length && !requested.includes(deviceId)) continue;
          result[userId][deviceId] = device.deviceKeys;
        }
      }
      response = {
        device_keys: result,
        master_keys: {},
        self_signing_keys: {},
        user_signing_keys: {},
        failures: {}
      };
    } else if (request.type === RequestType.KeysClaim) {
      const claimed = {};
      for (const [userId, deviceRequests] of Object.entries(body.one_time_keys || {})) {
        claimed[userId] = {};
        for (const [deviceId, algorithm] of Object.entries(deviceRequests || {})) {
          if (algorithm !== "signed_curve25519") continue;
          const device = this.devices.get(this.key(userId, deviceId));
          if (!device) continue;
          const next = device.oneTimeKeys.entries().next();
          if (!next.done) {
            const [id, value] = next.value;
            device.oneTimeKeys.delete(id);
            claimed[userId][deviceId] = { [id]: value };
          } else {
            const fallback = device.fallbackKeys.entries().next();
            if (!fallback.done) claimed[userId][deviceId] = { [fallback.value[0]]: fallback.value[1] };
          }
        }
      }
      response = { one_time_keys: claimed, failures: {} };
    } else if (request.type === RequestType.ToDevice) {
      const messages = body.messages || {};
      for (const [userId, deviceMap] of Object.entries(messages)) {
        for (const [deviceId, content] of Object.entries(deviceMap || {})) {
          const key = this.key(userId, deviceId);
          const list = this.inbox.get(key) || [];
          list.push({
            id: "event-" + (++this.nextEvent),
            sender: machine.userId.toString(),
            type: request.event_type,
            content,
            origin_server_ts: Date.now()
          });
          this.inbox.set(key, list);
        }
      }
      response = {};
    } else {
      throw new Error("Unsupported outgoing crypto request: " + request.type);
    }
    await machine.markRequestAsSent(request.id, request.type, JSON.stringify(response));
    request.free?.();
  }
  async flush(machine) {
    for (let round = 0; round < 20; round++) {
      const requests = await machine.outgoingRequests();
      if (!requests.length) return;
      for (const request of requests) await this.handle(machine, request);
    }
    throw new Error("Crypto request queue did not settle");
  }
  async sync(machine) {
    const key = this.key(machine.userId.toString(), machine.deviceId.toString());
    const queued = this.inbox.get(key) || [];
    this.inbox.set(key, []);
    const events = queued.map(item => ({
      event_id: "$" + item.id,
      type: item.type,
      sender: item.sender,
      origin_server_ts: item.origin_server_ts,
      content: item.content
    }));
    const lists = new DeviceLists([], []);
    try {
      await machine.receiveSyncChanges(
        JSON.stringify(events),
        lists,
        new Map([["signed_curve25519", 50]]),
        new Set()
      );
    } finally {
      lists.free();
    }
    await this.flush(machine);
    return queued;
  }
}

async function preparePair(transport, alice, bob) {
  const aliceUser = new UserId(alice.userId);
  const bobUser = new UserId(bob.userId);
  for (const machine of [alice.machine, bob.machine]) {
    const query = machine.queryKeysForUsers([aliceUser, bobUser]);
    await transport.handle(machine, query);
    await transport.flush(machine);
    for (const [userId, deviceId] of [
      [alice.userId, alice.deviceId],
      [bob.userId, bob.deviceId]
    ]) {
      const device = await machine.getDevice(new UserId(userId), new DeviceId(deviceId));
      if (device) {
        try { await device.setLocalTrust(LocalTrust.Verified); }
        finally { device.free(); }
      }
    }
    const missing = await machine.getMissingSessions([aliceUser, bobUser]);
    if (missing) await transport.handle(machine, missing);
    await transport.flush(machine);
  }
}

async function shareOneMessageSession(machine, transport, room, alice, bob) {
  const settings = new EncryptionSettings();
  const sharing = CollectStrategy.onlyTrustedDevices();
  const users = [new UserId(alice.userId), new UserId(bob.userId)];
  try {
    settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
    settings.rotationPeriod = 60n * 60n * 1_000_000n;
    settings.rotationPeriodMessages = 1n;
    settings.sharingStrategy = sharing;
    const requests = await machine.shareRoomKey(room, users, settings);
    for (const request of requests) await transport.handle(machine, request);
  } finally {
    for (const user of users) user.free();
    sharing.free();
    settings.free();
  }
  await transport.flush(machine);
}

test("real OlmMachine delivers each one-message Megolm session over Olm and decrypts both messages", async () => {
  await initAsync();
  const transport = new CryptoTransport();
  const alice = { userId: "@alice:securechat.invalid", deviceId: "ALICE_DEVICE_0001" };
  const bob = { userId: "@bob:securechat.invalid", deviceId: "BOB_DEVICE_0001" };
  const aliceMachine = await OlmMachine.initialize(new UserId(alice.userId), new DeviceId(alice.deviceId));
  const bobMachine = await OlmMachine.initialize(new UserId(bob.userId), new DeviceId(bob.deviceId));
  const room = new RoomId("!11111111111141118111111111111111:securechat.invalid");
  const roomSettings = new RoomSettings();
  try {
    await transport.flush(aliceMachine);
    await transport.flush(bobMachine);
    await preparePair(transport, alice, bob);
    roomSettings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
    roomSettings.onlyAllowTrustedDevices = true;
    roomSettings.sessionRotationPeriodMessages = 1;
    roomSettings.sessionRotationPeriodMs = 60 * 60 * 1000;
    await aliceMachine.setRoomSettings(room, roomSettings);

    const results = [];
    for (const body of ["first forward-secret message", "second forward-secret message"]) {
      await shareOneMessageSession(aliceMachine, transport, room, alice, bob);
      const encrypted = JSON.parse(await aliceMachine.encryptRoomEvent(
        room,
        "m.room.message",
        JSON.stringify({ msgtype: "m.text", body })
      ));
      results.push({ body, encrypted });
      const queued = await transport.sync(bobMachine);
      assert.ok(queued.length > 0, "recipient must receive an encrypted Olm to-device key event");
      assert.ok(queued.every(event => event.type === "m.room.encrypted"));
      assert.ok(queued.every(event => event.content.algorithm === "m.olm.v1.curve25519-aes-sha2"));
      const timelineEvent = {
        type: "m.room.encrypted",
        event_id: "$" + results.length,
        sender: alice.userId,
        origin_server_ts: Date.now(),
        room_id: room.toString(),
        content: encrypted
      };
      const decryptSettings = new DecryptionSettings(TrustRequirement.Untrusted);
      try {
        const decrypted = await bobMachine.decryptRoomEvent(JSON.stringify(timelineEvent), room, decryptSettings);
        try {
          const payload = JSON.parse(decrypted.event);
          assert.equal(payload.content.body, body);
        } finally {
          decrypted.free();
        }
      } finally {
        decryptSettings.free();
      }
    }

    assert.notEqual(
      results[0].encrypted.session_id,
      results[1].encrypted.session_id,
      "a Megolm session ID must never cover more than one message"
    );
  } finally {
    roomSettings.free();
    room.free();
    aliceMachine.close();
    bobMachine.close();
  }
});
