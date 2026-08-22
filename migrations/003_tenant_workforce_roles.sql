ALTER TABLE tenant_memberships
  ADD COLUMN tenant_role text NOT NULL DEFAULT 'staff'
    CHECK (tenant_role IN ('owner', 'admin', 'staff')),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX tenant_memberships_active_owner_index
  ON tenant_memberships (tenant_id)
  WHERE status = 'active' AND tenant_role = 'owner';

ALTER TABLE platform_audit_events
  ADD COLUMN event_data jsonb NOT NULL DEFAULT '{}'::jsonb;
