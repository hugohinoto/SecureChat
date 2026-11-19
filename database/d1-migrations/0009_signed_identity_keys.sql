-- Add an account-bound ECDSA proof for each ECDH identity key.
-- Existing keys remain readable but are legacy until the user signs in again.
ALTER TABLE user_keys ADD COLUMN identity_signing_public_key TEXT;
ALTER TABLE user_keys ADD COLUMN identity_key_signature TEXT;
