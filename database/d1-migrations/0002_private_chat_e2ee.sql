-- SecureChat private messaging, E2EE metadata, and one-hour message expiry.
-- Message bodies are ciphertext only. Decryption keys must remain on clients.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS user_keys (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  identity_public_key TEXT NOT NULL,
  signed_prekey TEXT NOT NULL,
  signed_prekey_signature TEXT NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner_user_id, contact_user_id),
  CHECK (owner_user_id <> contact_user_id)
);

CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_in_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (expires_in_seconds = 3600)
);

CREATE TABLE IF NOT EXISTS conversation_members (
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE IF NOT EXISTS encrypted_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'AES-GCM-256',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  CHECK (expires_at = created_at + 3600000)
);

CREATE INDEX IF NOT EXISTS conversations_member_lookup_idx
  ON conversation_members(user_id, conversation_id);
CREATE INDEX IF NOT EXISTS encrypted_messages_expiry_idx
  ON encrypted_messages(expires_at);
CREATE INDEX IF NOT EXISTS encrypted_messages_conversation_idx
  ON encrypted_messages(conversation_id, created_at);
CREATE INDEX IF NOT EXISTS contacts_lookup_idx
  ON contacts(owner_user_id, contact_user_id);
