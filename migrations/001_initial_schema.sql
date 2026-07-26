CREATE TABLE human_identities (
  id text PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE credentials (
  id text PRIMARY KEY,
  human_identity_id text NOT NULL REFERENCES human_identities(id),
  normalized_email text NOT NULL,
  password_hash text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'disabled', 'retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX credentials_non_retired_email_unique
  ON credentials (normalized_email)
  WHERE status <> 'retired';

CREATE INDEX credentials_human_identity_id_index
  ON credentials (human_identity_id);

CREATE TABLE sessions (
  id text PRIMARY KEY,
  human_identity_id text NOT NULL REFERENCES human_identities(id),
  created_at timestamptz NOT NULL,
  last_accessed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX sessions_human_identity_id_index
  ON sessions (human_identity_id);

CREATE INDEX sessions_active_expiry_index
  ON sessions (expires_at)
  WHERE status = 'active';
