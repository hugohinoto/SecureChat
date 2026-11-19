-- Admin console data. The live production users.is_admin column was added
-- manually before this migration; fresh installs receive it from 0001_initial.sql.
CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
  body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 3000),
  published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0,1)),
  created_by_user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  published_at INTEGER
);
CREATE INDEX IF NOT EXISTS announcements_published_idx
  ON announcements(published, published_at);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id TEXT PRIMARY KEY,
  admin_user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_user_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_audit_logs_created_at_idx
  ON admin_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS admin_audit_logs_admin_user_idx
  ON admin_audit_logs(admin_user_id, created_at);
