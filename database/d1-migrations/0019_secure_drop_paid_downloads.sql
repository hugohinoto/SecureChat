-- Allow metered downloads after the three free downloads without weakening
-- the legacy download_count constraint or losing the existing credit ledger.
ALTER TABLE secure_drop_transfers
  ADD COLUMN paid_download_count INTEGER NOT NULL DEFAULT 0
  CHECK (paid_download_count >= 0);

ALTER TABLE secure_drop_credit_ledger RENAME TO secure_drop_credit_ledger_v1;

CREATE TABLE secure_drop_credit_ledger (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month_key TEXT NOT NULL,
  delta INTEGER NOT NULL CHECK (delta <> 0),
  reason TEXT NOT NULL CHECK (reason IN ('monthly_grant', 'upload_debit', 'upload_refund', 'download_debit')),
  reference_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (user_id, month_key, reason, reference_id)
);

INSERT INTO secure_drop_credit_ledger (id, user_id, month_key, delta, reason, reference_id, created_at)
SELECT id, user_id, month_key, delta, reason, reference_id, created_at
FROM secure_drop_credit_ledger_v1;

DROP TABLE secure_drop_credit_ledger_v1;

CREATE INDEX IF NOT EXISTS secure_drop_credit_ledger_month_idx
  ON secure_drop_credit_ledger(month_key, created_at);
