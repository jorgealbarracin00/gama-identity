-- Additive metadata only. No authentication or existing ownership row is changed.
CREATE TABLE human_profiles (
  human_identity_id text PRIMARY KEY REFERENCES human_identities(id),
  preferred_display_name text CHECK (preferred_display_name IS NULL OR char_length(preferred_display_name) BETWEEN 1 AND 120),
  revision integer NOT NULL CHECK (revision > 0),
  updated_at timestamptz NOT NULL
);
-- Individual use is independent of business participation and access entitlements.
CREATE TABLE human_product_participations (
  human_identity_id text NOT NULL REFERENCES human_identities(id),
  product_id text NOT NULL REFERENCES registered_products(id),
  workload_id text NOT NULL REFERENCES product_workloads(id),
  status text NOT NULL CHECK (status IN ('active','suspended','retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY(human_identity_id,product_id)
);
CREATE INDEX human_product_participations_product_index ON human_product_participations(product_id,human_identity_id);
CREATE INDEX human_identities_created_index ON human_identities(created_at,id);
CREATE INDEX sessions_human_activity_index ON sessions(human_identity_id,last_accessed_at DESC);
-- Draft/preview requests only: this ledger cannot issue an execution grant.
CREATE TABLE identity_recovery_requests (
  id uuid PRIMARY KEY,
  actor_human_identity_id text NOT NULL REFERENCES human_identities(id),
  source_human_identity_id text NOT NULL REFERENCES human_identities(id),
  target_human_identity_id text NOT NULL REFERENCES human_identities(id),
  provider text NOT NULL CHECK (provider IN ('google','apple','email_password')),
  review_digest text NOT NULL CHECK(review_digest ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK (state IN ('review_required','cancelled')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK(source_human_identity_id <> target_human_identity_id)
);
CREATE INDEX identity_recovery_requests_created_index ON identity_recovery_requests(created_at DESC,id DESC);
CREATE INDEX platform_audit_events_pagination_index ON platform_audit_events(occurred_at DESC,id DESC);
