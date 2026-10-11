-- Additive short-lived OAuth state. Provider tokens, subjects and raw session credentials are never stored.
CREATE TABLE IF NOT EXISTS identity_management_google_handoffs (
 id uuid PRIMARY KEY, case_id uuid NOT NULL,
 case_kind text NOT NULL CHECK(case_kind IN ('recovery','compensation')),
 recovery_case_id uuid REFERENCES identity_management_cases(id),
 compensation_case_id uuid REFERENCES identity_recovery_compensations(id),
 CHECK((case_kind='recovery' AND recovery_case_id IS NOT NULL AND recovery_case_id=case_id AND compensation_case_id IS NULL) OR (case_kind='compensation' AND compensation_case_id IS NOT NULL AND compensation_case_id=case_id AND recovery_case_id IS NULL)),
 actor_id text NOT NULL REFERENCES human_identities(id), target_id text NOT NULL REFERENCES human_identities(id),
 admin_session_hash text NOT NULL CHECK(admin_session_hash ~ '^[a-f0-9]{64}$'),
 target_session_hash text NOT NULL CHECK(target_session_hash ~ '^[a-f0-9]{64}$'),
 state_digest text NOT NULL UNIQUE CHECK(state_digest ~ '^[a-f0-9]{64}$'),
 code_verifier text CHECK(code_verifier IS NULL OR code_verifier ~ '^[A-Za-z0-9_-]{43,128}$'),
 state text NOT NULL CHECK(state IN ('awaiting_callback','processing','verified','failed','cancelled')),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 CHECK(expires_at > created_at), CHECK(expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX IF NOT EXISTS identity_management_google_handoffs_case ON identity_management_google_handoffs(case_id,created_at);
