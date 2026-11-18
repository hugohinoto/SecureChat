PRAGMA foreign_keys = ON;

-- One-time registration invitations. Only a hash is stored; the plaintext code is shown once.
CREATE TABLE IF NOT EXISTS registration_invites (
  id TEXT PRIMARY KEY,
  created_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);

CREATE INDEX IF NOT EXISTS registration_invites_creator_idx
  ON registration_invites(created_by_user_id, expires_at, used_at);
CREATE INDEX IF NOT EXISTS registration_invites_expiry_idx
  ON registration_invites(expires_at);
