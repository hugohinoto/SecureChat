-- SecureDrop monthly credits and encrypted file-transfer metadata.
-- File payloads are stored in R2; this database stores only opaque object keys and limits.
CREATE TABLE IF NOT EXISTS secure_drop_credit_accounts (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month_key TEXT NOT NULL,
  granted_credits INTEGER NOT NULL DEFAULT 100 CHECK (granted_credits = 100),
  balance INTEGER NOT NULL DEFAULT 100 CHECK (balance BETWEEN 0 AND 100),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, month_key),
  CHECK (length(month_key) = 7)
);

CREATE TABLE IF NOT EXISTS secure_drop_credit_ledger (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month_key TEXT NOT NULL,
  delta INTEGER NOT NULL CHECK (delta <> 0),
  reason TEXT NOT NULL CHECK (reason IN ('monthly_grant', 'upload_debit', 'upload_refund')),
  reference_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (user_id, month_key, reason, reference_id)
);

CREATE INDEX IF NOT EXISTS secure_drop_credit_ledger_month_idx
  ON secure_drop_credit_ledger(month_key, created_at);

CREATE TABLE IF NOT EXISTS secure_drop_transfers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month_key TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL,
  original_size_bytes INTEGER NOT NULL CHECK (original_size_bytes BETWEEN 1 AND 100000000),
  stored_size_bytes INTEGER NOT NULL CHECK (stored_size_bytes BETWEEN 1 AND 101000000),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count BETWEEN 0 AND 3),
  download_limit INTEGER NOT NULL DEFAULT 3 CHECK (download_limit = 3),
  CHECK (expires_at > created_at),
  CHECK (length(month_key) = 7)
);

CREATE INDEX IF NOT EXISTS secure_drop_transfers_owner_month_idx
  ON secure_drop_transfers(user_id, month_key, created_at);

CREATE INDEX IF NOT EXISTS secure_drop_transfers_expiry_idx
  ON secure_drop_transfers(month_key, expires_at);

CREATE TABLE IF NOT EXISTS secure_drop_maintenance (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  current_month TEXT NOT NULL,
  cursor TEXT,
  completed_at INTEGER
);

INSERT OR IGNORE INTO secure_drop_maintenance (id, current_month, cursor, completed_at)
VALUES (1, '1970-01', NULL, NULL);
