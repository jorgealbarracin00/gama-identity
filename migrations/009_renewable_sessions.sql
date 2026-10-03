ALTER TABLE sessions
  ADD COLUMN renewal_token_hash text,
  ADD COLUMN renewal_expires_at timestamptz,
  ADD CONSTRAINT sessions_renewal_fields_together CHECK (
    (renewal_token_hash IS NULL AND renewal_expires_at IS NULL)
    OR
    (renewal_token_hash IS NOT NULL AND renewal_expires_at IS NOT NULL)
  );

CREATE UNIQUE INDEX sessions_renewal_token_hash_unique
  ON sessions (renewal_token_hash)
  WHERE renewal_token_hash IS NOT NULL;

CREATE INDEX sessions_renewal_expiry_index
  ON sessions (renewal_expires_at)
  WHERE renewal_token_hash IS NOT NULL AND status <> 'revoked';
