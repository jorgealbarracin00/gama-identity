CREATE TABLE federated_identities (
  id text PRIMARY KEY,
  human_identity_id text NOT NULL REFERENCES human_identities(id),
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{0,31}$'),
  provider_subject text NOT NULL CHECK (
    char_length(provider_subject) BETWEEN 1 AND 1024
  ),
  provider_email text CHECK (
    provider_email IS NULL OR char_length(provider_email) BETWEEN 1 AND 320
  ),
  provider_email_verified boolean,
  provider_email_private boolean,
  status text NOT NULL CHECK (status IN ('active', 'disabled', 'retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (provider, provider_subject)
);

CREATE INDEX federated_identities_human_identity_id_index
  ON federated_identities (human_identity_id);

CREATE TABLE federated_authentication_nonces (
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{0,31}$'),
  nonce_hash text NOT NULL CHECK (char_length(nonce_hash) = 43),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL,
  PRIMARY KEY (provider, nonce_hash)
);

CREATE INDEX federated_authentication_nonces_expiry_index
  ON federated_authentication_nonces (expires_at);
