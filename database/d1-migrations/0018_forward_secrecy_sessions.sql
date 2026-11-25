-- Prevent a Megolm session key from being reused for more than one message.
-- Session identifiers are public metadata; keeping this ledger after message
-- expiry prevents a stale client from reusing an old session key later.
CREATE TABLE IF NOT EXISTS crypto_used_megolm_sessions (
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_device_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  message_id TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, sender_user_id, sender_device_id, session_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS crypto_used_megolm_sessions_created_idx
  ON crypto_used_megolm_sessions(created_at);
