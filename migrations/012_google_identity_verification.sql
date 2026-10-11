-- Observation ledger only: cannot represent an approved account-changing grant.
-- No existing identity, authentication, permission or session row is altered.
CREATE TABLE google_identity_verification_cases (
  id uuid PRIMARY KEY,
  sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  created_at timestamptz NOT NULL,
  payload jsonb NOT NULL,
  CHECK (payload->>'id' = id::text),
  CHECK (payload->>'sourceHumanIdentityId' IS NOT NULL AND payload->>'targetHumanIdentityId' IS NOT NULL),
  CHECK (payload->>'sourceHumanIdentityId' <> payload->>'targetHumanIdentityId'),
  CHECK (payload->>'appId' = 'cashcast-preview'),
  CHECK (payload->>'state' IN ('awaiting_proof','reviewed','cancelled')),
  CHECK (jsonb_typeof(payload->'matched') IN ('boolean','null')),
  CHECK ((payload - ARRAY['id','sourceHumanIdentityId','targetHumanIdentityId','appId','state','createdAt','expiresAt','observedAt','matched','relationshipId','reviewDigest']::text[]) = '{}'::jsonb),
  CHECK (NOT payload ? 'approvalReference'),
  CHECK (NOT payload ? 'providerSubject'),
  CHECK (NOT payload ? 'token')
);
