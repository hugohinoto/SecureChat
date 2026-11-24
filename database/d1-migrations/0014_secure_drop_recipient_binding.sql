-- Bind SecureDrop delivery to a verified recipient and a recipient-key envelope.
-- Existing bearer-token transfers are made unavailable and queued for object cleanup.
ALTER TABLE secure_drop_transfers
  ADD COLUMN recipient_user_id TEXT REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE secure_drop_transfers
  ADD COLUMN key_envelope_json TEXT;

ALTER TABLE secure_drop_transfers
  ADD COLUMN status TEXT NOT NULL DEFAULT 'ready'
  CHECK (status IN ('pending', 'ready', 'deleting'));

ALTER TABLE secure_drop_transfers
  ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;

UPDATE secure_drop_transfers
   SET status='deleting', updated_at=created_at
 WHERE recipient_user_id IS NULL OR key_envelope_json IS NULL;

CREATE INDEX IF NOT EXISTS secure_drop_transfers_recipient_month_idx
  ON secure_drop_transfers(recipient_user_id, month_key, created_at);

CREATE INDEX IF NOT EXISTS secure_drop_transfers_status_updated_idx
  ON secure_drop_transfers(status, updated_at);
