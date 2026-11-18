-- Persistent, atomic rate-limit counters shared by all Worker isolates.
-- The bucket key is a SHA-256 digest; raw client IP addresses are never stored.
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key TEXT PRIMARY KEY,
  window_started_at INTEGER NOT NULL,
  request_count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_limit_buckets_expiry_idx
  ON rate_limit_buckets(expires_at);
