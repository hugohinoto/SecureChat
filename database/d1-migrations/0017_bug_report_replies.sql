-- Encrypted administrator replies to user-submitted bug reports.
CREATE TABLE IF NOT EXISTS bug_report_replies (
  id TEXT PRIMARY KEY,
  bug_report_id TEXT NOT NULL REFERENCES bug_reports(id) ON DELETE CASCADE,
  admin_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  encrypted_payload TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bug_report_replies_report_created_idx
  ON bug_report_replies(bug_report_id, created_at ASC);
