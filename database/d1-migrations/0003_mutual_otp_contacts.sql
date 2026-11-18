-- Mutual one-time-code verification for private contacts.
-- Legacy contacts are intentionally not treated as verified; only pairs in verified_contact_pairs can chat.
CREATE TABLE IF NOT EXISTS verified_contact_pairs (
  user_a_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (user_a_id, user_b_id),
  CHECK (user_a_id < user_b_id)
);

CREATE TABLE IF NOT EXISTS contact_invitations (
  id TEXT PRIMARY KEY,
  inviter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invitee_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  inviter_code_hash TEXT,
  inviter_code_expires_at INTEGER,
  inviter_attempts INTEGER NOT NULL DEFAULT 0,
  invitee_code_hash TEXT,
  invitee_code_expires_at INTEGER,
  invitee_attempts INTEGER NOT NULL DEFAULT 0,
  invitee_verified_at INTEGER,
  inviter_verified_at INTEGER,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (inviter_user_id <> invitee_user_id),
  CHECK (inviter_attempts BETWEEN 0 AND 5),
  CHECK (invitee_attempts BETWEEN 0 AND 5)
);

CREATE INDEX IF NOT EXISTS contact_invitations_inviter_idx
  ON contact_invitations(inviter_user_id, expires_at);
CREATE INDEX IF NOT EXISTS contact_invitations_invitee_idx
  ON contact_invitations(invitee_user_id, expires_at);
