-- Preserve authentication age through rotations so product deletion can revoke
-- that product's old sessions without deleting the shared Human Identity.
ALTER TABLE sessions ADD COLUMN authenticated_at timestamptz;
UPDATE sessions SET authenticated_at = created_at;
ALTER TABLE sessions ALTER COLUMN authenticated_at SET NOT NULL;
CREATE TABLE product_apple_revocations (
  operation_id uuid PRIMARY KEY,
  human_identity_id text NOT NULL REFERENCES human_identities(id),
  client_id text NOT NULL,
  encrypted_token text,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (encrypted_token IS NOT NULL OR completed_at IS NOT NULL)
);
