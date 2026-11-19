CREATE TABLE IF NOT EXISTS bug_reports (
  id TEXT PRIMARY KEY,
  reporter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL CHECK (category IN ('display','login','chat','contact','performance','other')),
  title TEXT NOT NULL CHECK (length(title) BETWEEN 3 AND 120),
  description TEXT NOT NULL CHECK (length(description) BETWEEN 10 AND 4000),
  page_path TEXT NOT NULL DEFAULT '/',
  app_version TEXT NOT NULL DEFAULT 'unknown',
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','wont_fix')),
  admin_note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bug_reports_created_at_idx ON bug_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS bug_reports_status_idx ON bug_reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS bug_reports_reporter_idx ON bug_reports(reporter_user_id, created_at DESC);
