-- Admin password rotation: force administrators to change credentials every 90 days.
-- Existing admin accounts have NULL here and must change password at next login.
ALTER TABLE users ADD COLUMN password_changed_at INTEGER;
