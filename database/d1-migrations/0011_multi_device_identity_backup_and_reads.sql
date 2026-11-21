-- Encrypted account identity backup enables the same E2EE identity on multiple devices.
-- The server stores only the password-encrypted backup, never plaintext private keys.
ALTER TABLE user_keys ADD COLUMN identity_transition_from TEXT;
ALTER TABLE user_keys ADD COLUMN identity_transition_signature TEXT;
ALTER TABLE user_keys ADD COLUMN identity_backup_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_keys ADD COLUMN identity_backup_salt TEXT;
ALTER TABLE user_keys ADD COLUMN identity_backup_iv TEXT;
ALTER TABLE user_keys ADD COLUMN identity_backup_ciphertext TEXT;

-- Per-user read cursor for each private conversation.
CREATE TABLE IF NOT EXISTS conversation_reads (
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_read_at INTEGER NOT NULL DEFAULT 0,
  last_read_message_id TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX IF NOT EXISTS conversation_reads_user_idx
  ON conversation_reads(user_id, conversation_id);
