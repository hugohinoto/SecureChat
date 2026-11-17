CREATE TABLE users (
  id UUID PRIMARY KEY,
  user_id VARCHAR(32) NOT NULL UNIQUE,
  password_salt CHAR(32) NOT NULL,
  password_hash CHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ,
  CONSTRAINT users_user_id_format
    CHECK (user_id ~ '^[a-z0-9_]{3,32}$'),
  CONSTRAINT users_password_salt_format
    CHECK (password_salt ~ '^[a-f0-9]{32}$'),
  CONSTRAINT users_password_hash_format
    CHECK (password_hash ~ '^[a-f0-9]{128}$')
);

CREATE TABLE sessions (
  token_hash CHAR(64) PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT sessions_token_hash_format
    CHECK (token_hash ~ '^[a-f0-9]{64}$')
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);
