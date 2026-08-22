CREATE TABLE platform_administration_memberships (
  human_identity_id text PRIMARY KEY REFERENCES human_identities(id),
  platform_role text NOT NULL CHECK (platform_role IN ('administrator')),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX platform_administration_memberships_active_role_index
  ON platform_administration_memberships (platform_role)
  WHERE status = 'active';
