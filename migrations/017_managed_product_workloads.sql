-- Separate scoped credentials are invisible to predecessor authentication.
-- Existing credentials, relationships, sessions and participation values stay unchanged.
CREATE TABLE managed_product_workloads (
  id text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{0,63}$'),
  product_id text NOT NULL REFERENCES registered_products(id),
  secret_hash text NOT NULL,
  status text NOT NULL CHECK (status IN ('active','retired')),
  revision integer NOT NULL CHECK (revision > 0),
  capabilities text[] NOT NULL CHECK (
    cardinality(capabilities) BETWEEN 1 AND 3 AND
    capabilities <@ ARRAY['workload.context.read','human.participation.register','human.participation.backfill.preview']::text[]
    AND array_position(capabilities,NULL) IS NULL
  ),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(id,product_id)
);
CREATE INDEX managed_product_workloads_product_index ON managed_product_workloads(product_id);
-- Both old and new writers serialize their namespaces, including old bootstrap code.
CREATE FUNCTION enforce_workload_namespace() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('workload-namespace:' || NEW.id,0));
  IF TG_TABLE_NAME='managed_product_workloads' THEN
    IF NEW.id='coco-backend' OR EXISTS(SELECT 1 FROM product_workloads WHERE id=NEW.id) THEN
      RAISE EXCEPTION 'Workload namespace conflict' USING ERRCODE='23505';
    END IF;
    IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.product_id<>OLD.product_id OR NEW.capabilities<>OLD.capabilities) THEN
      RAISE EXCEPTION 'Managed workload binding is immutable' USING ERRCODE='23514';
    END IF;
  ELSE
    IF EXISTS(SELECT 1 FROM managed_product_workloads WHERE id=NEW.id) THEN
      RAISE EXCEPTION 'Workload namespace conflict' USING ERRCODE='23505';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER managed_workload_namespace BEFORE INSERT OR UPDATE ON managed_product_workloads
  FOR EACH ROW EXECUTE FUNCTION enforce_workload_namespace();
CREATE TRIGGER legacy_workload_namespace BEFORE INSERT OR UPDATE ON product_workloads
  FOR EACH ROW EXECUTE FUNCTION enforce_workload_namespace();
ALTER TABLE human_product_participations
  ALTER COLUMN workload_id DROP NOT NULL,
  ADD COLUMN managed_workload_id text,
  ADD CONSTRAINT human_participation_exactly_one_workload CHECK ((workload_id IS NULL) <> (managed_workload_id IS NULL)),
  ADD CONSTRAINT human_participation_managed_product_fk FOREIGN KEY(managed_workload_id,product_id)
    REFERENCES managed_product_workloads(id,product_id);
-- Receipts contain only operation metadata. Secrets and hashes are never replayed.
CREATE TABLE managed_workload_operations (
  request_id uuid PRIMARY KEY,
  actor_human_identity_id text NOT NULL REFERENCES human_identities(id),
  operation text NOT NULL CHECK(operation IN ('create','rotate','revoke')),
  intent_digest text NOT NULL CHECK(intent_digest ~ '^[a-f0-9]{64}$'),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL
);
