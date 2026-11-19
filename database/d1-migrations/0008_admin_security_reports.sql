-- Encrypted admin announcements, encrypted bug reports, and searchable admin indexes.
ALTER TABLE announcements ADD COLUMN title_ciphertext TEXT;
ALTER TABLE announcements ADD COLUMN body_ciphertext TEXT;
ALTER TABLE announcements ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE announcements ADD COLUMN expires_at INTEGER;
CREATE INDEX IF NOT EXISTS announcements_expiry_idx
  ON announcements(published, expires_at);

CREATE TABLE IF NOT EXISTS bug_reports (
  id TEXT PRIMARY KEY,
  reporter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  encrypted_payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','triaged','resolved')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS bug_reports_status_created_idx
  ON bug_reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS bug_reports_reporter_idx
  ON bug_reports(reporter_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS users_created_at_admin_idx
  ON users(is_admin, created_at DESC);
CREATE INDEX IF NOT EXISTS users_last_login_idx
  ON users(last_login_at DESC);
