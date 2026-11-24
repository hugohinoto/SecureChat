-- Durable retry queue for SecureDrop object deletion verification.
-- A transfer is not removed from metadata until R2 confirms the object is absent.
CREATE TABLE IF NOT EXISTS secure_drop_deletion_jobs (
  transfer_id TEXT PRIMARY KEY,
  object_key TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL CHECK (reason IN ('user_delete', 'upload_rollback', 'stale_transfer')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS secure_drop_deletion_jobs_due_idx
  ON secure_drop_deletion_jobs(next_attempt_at);
