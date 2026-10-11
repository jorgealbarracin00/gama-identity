-- Additive review metadata. No purpose, lifecycle or relationship is assigned to an existing Human.
CREATE TABLE human_purposes (
 human_identity_id text PRIMARY KEY REFERENCES human_identities(id),
 purpose text NOT NULL CHECK(purpose IN ('production','test','unknown')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 500),
 actor_human_identity_id text NOT NULL REFERENCES human_identities(id),
 revision integer NOT NULL CHECK(revision>0), updated_at timestamptz NOT NULL
);
CREATE TABLE identity_management_operations (
 id uuid PRIMARY KEY, actor_human_identity_id text NOT NULL REFERENCES human_identities(id),
 kind text NOT NULL, intent_digest text NOT NULL, result jsonb NOT NULL, created_at timestamptz NOT NULL
);
CREATE TABLE identity_management_cases (
 id uuid PRIMARY KEY, actor_human_identity_id text NOT NULL REFERENCES human_identities(id),
 source_human_identity_id text NOT NULL REFERENCES human_identities(id),
 target_human_identity_id text NOT NULL REFERENCES human_identities(id),
 provider text NOT NULL CHECK(provider='google'), nonce text NOT NULL,
 relationship_id text REFERENCES federated_identities(id),
 state text NOT NULL CHECK(state IN ('awaiting_proof','verified','completed','cancelled')),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 proof_expires_at timestamptz, review_digest text,
 CHECK(source_human_identity_id<>target_human_identity_id)
);
-- Store only one-way session references, never usable bearer credentials.
CREATE TABLE identity_management_control_proofs (
 session_hash text PRIMARY KEY, case_id uuid NOT NULL REFERENCES identity_management_cases(id),
 human_identity_id text NOT NULL REFERENCES human_identities(id), expires_at timestamptz NOT NULL
);
CREATE TABLE product_dependency_inspectors (
 product_id text PRIMARY KEY REFERENCES registered_products(id),
 workload_id text NOT NULL REFERENCES product_workloads(id),
 coverage text NOT NULL CHECK(coverage='complete'), revision integer NOT NULL CHECK(revision>0)
);
CREATE TABLE product_dependency_reports (
 product_id text NOT NULL REFERENCES product_dependency_inspectors(product_id),
 human_identity_id text NOT NULL REFERENCES human_identities(id),
 inspector_revision integer NOT NULL, counts jsonb NOT NULL,
 evidence_reference text NOT NULL, observed_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(product_id,human_identity_id)
);
-- Optimistic write versions reject stale domain objects after lifecycle/recovery commits.
ALTER TABLE human_identities ADD COLUMN write_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE federated_identities ADD COLUMN write_revision bigint NOT NULL DEFAULT 0;
