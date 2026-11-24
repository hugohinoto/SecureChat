-- D1-backed SecureDrop storage. R2 records remain readable during the transition.
ALTER TABLE secure_drop_transfers
  ADD COLUMN storage_backend TEXT NOT NULL DEFAULT 'r2'
  CHECK (storage_backend IN ('r2', 'd1'));

ALTER TABLE secure_drop_transfers
  ADD COLUMN priority INTEGER NOT NULL DEFAULT 0
  CHECK (priority IN (0, 1));

CREATE INDEX IF NOT EXISTS secure_drop_transfers_storage_capacity_idx
  ON secure_drop_transfers(storage_backend, status, priority, created_at);

CREATE TABLE IF NOT EXISTS secure_drop_file_chunks (
  transfer_id TEXT NOT NULL REFERENCES secure_drop_transfers(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
  chunk_data BLOB NOT NULL,
  chunk_size_bytes INTEGER NOT NULL CHECK (chunk_size_bytes BETWEEN 1 AND 524288),
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (transfer_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS secure_drop_preempted_uploads (
  transfer_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month_key TEXT NOT NULL,
  original_size_bytes INTEGER NOT NULL,
  stored_size_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  acknowledged_at INTEGER
);

CREATE INDEX IF NOT EXISTS secure_drop_preempted_uploads_user_idx
  ON secure_drop_preempted_uploads(user_id, acknowledged_at, created_at);
