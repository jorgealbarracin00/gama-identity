CREATE TABLE registered_products (
  id text PRIMARY KEY,
  display_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenants (
  id text PRIMARY KEY,
  display_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE product_workloads (
  id text PRIMARY KEY,
  product_id text NOT NULL REFERENCES registered_products(id),
  secret_hash text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_memberships (
  tenant_id text NOT NULL REFERENCES tenants(id),
  human_identity_id text NOT NULL REFERENCES human_identities(id),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  PRIMARY KEY (tenant_id, human_identity_id)
);

CREATE TABLE product_participations (
  tenant_id text NOT NULL REFERENCES tenants(id),
  product_id text NOT NULL REFERENCES registered_products(id),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  PRIMARY KEY (tenant_id, product_id)
);

CREATE TABLE product_entitlements (
  tenant_id text NOT NULL,
  product_id text NOT NULL,
  human_identity_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
  PRIMARY KEY (tenant_id, product_id, human_identity_id),
  FOREIGN KEY (tenant_id, product_id) REFERENCES product_participations(tenant_id, product_id),
  FOREIGN KEY (tenant_id, human_identity_id) REFERENCES tenant_memberships(tenant_id, human_identity_id)
);

CREATE TABLE platform_audit_events (
  id text PRIMARY KEY,
  event_type text NOT NULL,
  actor_reference text NOT NULL,
  subject_reference text NOT NULL,
  product_id text REFERENCES registered_products(id),
  tenant_id text REFERENCES tenants(id),
  occurred_at timestamptz NOT NULL
);

CREATE INDEX product_workloads_product_id_index ON product_workloads(product_id);
CREATE INDEX platform_audit_events_occurred_at_index ON platform_audit_events(occurred_at);
