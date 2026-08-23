CREATE TABLE tenant_provisioning_requests (
  idempotency_key uuid PRIMARY KEY,
  tenant_id text NOT NULL UNIQUE REFERENCES tenants(id)
    DEFERRABLE INITIALLY DEFERRED,
  display_name text NOT NULL,
  initial_owner_human_identity_id text NOT NULL REFERENCES human_identities(id),
  created_at timestamptz NOT NULL
);

