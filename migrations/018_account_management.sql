-- Independent account-management candidate; requires reviewed schema017.
-- No existing Human/provider/session/permission record is changed.
ALTER TABLE email_action_challenges DROP CONSTRAINT email_action_challenges_purpose_check;
ALTER TABLE email_action_challenges ADD CONSTRAINT email_action_challenges_purpose_check
 CHECK (purpose IN ('verify_email','reset_password','link_email'));

-- Human tombstones preserve canonical/audit/recovery history; deletion removes
-- credentials/profile/access and never cascades into business/product storage.
CREATE TABLE IF NOT EXISTS identity_deletion_tasks (
 id uuid PRIMARY KEY,
 operation_id uuid NOT NULL REFERENCES identity_management_operations(id),
 human_identity_id text NOT NULL REFERENCES human_identities(id),
 product_id text REFERENCES registered_products(id),
 state text NOT NULL CHECK(state IN ('pending','claimed','completed','unsupported','failed')),
 revision integer NOT NULL DEFAULT 0 CHECK(revision>=0),
 claimed_workload_id text, lease_expires_at timestamptz,
 result jsonb, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 CHECK ((state='claimed') = (claimed_workload_id IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_deletion_one_task_per_product
 ON identity_deletion_tasks(operation_id,coalesce(product_id,''));
CREATE INDEX IF NOT EXISTS identity_deletion_tasks_work_queue ON identity_deletion_tasks(product_id,state,created_at);

-- Dedicated product cleanup is an explicit opt-in scope, never inherited by
-- legacy workloads. Existing capability arrays and credentials are preserved.
ALTER TABLE managed_product_workloads DROP CONSTRAINT managed_product_workloads_capabilities_check;
ALTER TABLE managed_product_workloads ADD CONSTRAINT managed_product_workloads_capabilities_check CHECK (
 cardinality(capabilities) BETWEEN 1 AND 3 AND
 capabilities <@ ARRAY['workload.context.read','human.participation.register','human.participation.backfill.preview','human.data.cleanup']::text[]
 AND array_position(capabilities,NULL) IS NULL
);

ALTER TABLE identity_management_cases ADD COLUMN IF NOT EXISTS transfer_policy text NOT NULL DEFAULT 'verified_empty_source'
 CHECK(transfer_policy IN ('verified_empty_source','retain_records'));
