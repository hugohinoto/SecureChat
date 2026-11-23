-- Device-scoped Matrix Olm / Megolm key distribution and opaque to-device inbox.
-- Existing ciphertext remains protocol v1 unless a new conversation is explicitly migrated.
ALTER TABLE encrypted_messages ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1 CHECK (protocol_version IN (1, 2));
ALTER TABLE encrypted_messages ADD COLUMN sender_device_id TEXT;
-- Private ratchet state stays in the browser's encrypted IndexedDB store.
CREATE TABLE IF NOT EXISTS crypto_devices (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  device_keys_json TEXT NOT NULL,
  account_authorization_signature TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY (user_id, device_id),
  CHECK (length(device_id) BETWEEN 8 AND 64),
  CHECK (length(device_keys_json) BETWEEN 2 AND 16000),
  CHECK (length(account_authorization_signature) BETWEEN 80 AND 128)
);

CREATE INDEX IF NOT EXISTS crypto_devices_user_active_idx
  ON crypto_devices(user_id, revoked_at, updated_at);

CREATE TABLE IF NOT EXISTS crypto_one_time_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  key_json TEXT NOT NULL,
  is_fallback INTEGER NOT NULL DEFAULT 0 CHECK (is_fallback IN (0, 1)),
  created_at INTEGER NOT NULL,
  claimed_at INTEGER,
  claimed_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  claimed_by_device_id TEXT,
  FOREIGN KEY (user_id, device_id)
    REFERENCES crypto_devices(user_id, device_id) ON DELETE CASCADE,
  UNIQUE (user_id, device_id, key_id),
  CHECK (length(key_json) BETWEEN 2 AND 4096)
);

CREATE INDEX IF NOT EXISTS crypto_one_time_keys_claim_idx
  ON crypto_one_time_keys(user_id, device_id, algorithm, is_fallback, claimed_at);

CREATE TABLE IF NOT EXISTS crypto_to_device_inbox (
  id TEXT PRIMARY KEY,
  recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_device_id TEXT NOT NULL,
  sender_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_device_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  content_json TEXT NOT NULL,
  transaction_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE (sender_user_id, sender_device_id, transaction_id, recipient_user_id, recipient_device_id),
  CHECK (length(content_json) BETWEEN 2 AND 32768),
  CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS crypto_to_device_inbox_poll_idx
  ON crypto_to_device_inbox(recipient_user_id, recipient_device_id, created_at);

CREATE TABLE IF NOT EXISTS conversation_crypto_modes (
  conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
  protocol_version INTEGER NOT NULL CHECK (protocol_version = 2),
  enabled_by_user_id TEXT NOT NULL REFERENCES users(id),
  enabled_at INTEGER NOT NULL
);

-- Require each account to explicitly approve the irreversible v2 cutover.
CREATE TABLE IF NOT EXISTS conversation_crypto_approvals (
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  approved_at INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX IF NOT EXISTS conversation_crypto_approvals_user_idx
  ON conversation_crypto_approvals(user_id, conversation_id);
